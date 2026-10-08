"""DNS tunneling, DGA (Domain Generation Algorithms), and exfiltration detection.

Detects:
1. High-entropy domain queries (Shannon entropy of subdomains / FQDN).
2. N-gram bigram/trigram character language model perplexity anomalies.
3. Query rate and volume burst spikes over sliding time windows.
4. TXT record tunneling heuristics (long encoded labels, base32/base64/hex payloads,
   high TXT query volume).

Mapped directly to MITRE ATT&CK:
- T1071.004: Application Layer Protocol: DNS
- T1048.003: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- T1568.002: Dynamic Resolution: Domain Generation Algorithms
"""

from __future__ import annotations

import collections
import math
import re
import threading
import time

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import (
    AttackStage,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
    new_id,
)

# Base64, base32, hex payload pattern
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_BASE32_RE = re.compile(r"^[2-7a-zA-Z]{16,}$")
_BASE64_RE = re.compile(r"^[0-9a-zA-Z_\-+/]{20,}={0,2}$")

# Common benign domain suffixes that shouldn't be penalized
_BENIGN_TLDS = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "io",
        "co",
        "uk",
        "de",
        "ca",
        "jp",
        "fr",
        "au",
        "ru",
        "ch",
        "it",
        "nl",
        "se",
        "no",
        "es",
        "ai",
        "dev",
    }
)


def shannon_entropy(s: str) -> float:
    """Shannon entropy of characters in string (in bits per char)."""
    if not s:
        return 0.0
    s_low = s.lower()
    counts = collections.Counter(s_low)
    total = len(s_low)
    return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())


# ---------------------------------------------------------------------------
# Precomputed character n-gram transition language model for domain names
# ---------------------------------------------------------------------------
class NgramLanguageModel:
    """Lightweight character bigram language model for natural domain names.

    Higher perplexity means the domain name is highly irregular or random (DGA/tunneling).
    Lower perplexity indicates natural language domain syllables.
    """

    _VOWELS = frozenset("aeiouy")
    _COMMON_CC = frozenset(
        {
            "th",
            "st",
            "nd",
            "nt",
            "ng",
            "ch",
            "sh",
            "pr",
            "tr",
            "cr",
            "br",
            "gr",
            "pl",
            "cl",
            "fl",
            "sp",
            "sc",
            "sk",
            "sm",
            "sn",
            "sw",
            "rt",
            "rd",
            "rk",
            "rm",
            "rn",
            "rp",
            "rs",
            "lt",
            "ld",
            "lk",
            "lm",
            "lp",
            "ft",
            "mp",
            "pt",
            "ct",
            "xt",
            "gh",
            "ph",
            "wh",
            "wr",
            "kn",
            "ll",
            "ss",
            "tt",
            "ff",
            "mm",
            "nn",
            "pp",
            "rr",
            "cc",
            "dd",
            "bb",
            "gg",
            "ck",
            "qu",
            "dr",
            "fr",
            "gl",
        }
    )

    def _transition_prob(self, c1: str, c2: str) -> float:
        if c1.isdigit() or c2.isdigit():
            return 0.02
        is_v1, is_v2 = c1 in self._VOWELS, c2 in self._VOWELS
        if is_v1 and not is_v2:
            return 0.25
        if not is_v1 and is_v2:
            return 0.30
        if is_v1 and is_v2:
            return 0.10
        if (c1 + c2) in self._COMMON_CC:
            return 0.12
        # Awkward or rare consonant clusters (e.g. 'qj', 'zx', 'kx', 'qz')
        return 0.005

    def perplexity(self, text: str) -> float:
        """Compute bigram cross-entropy perplexity for input text.

        Returns values in [1.0, 200.0]. Typical benign domain label: 4.0 - 16.0.
        Random / DGA / hex / encoded strings: 25.0 - 200.0+.
        """
        s = re.sub(r"[^a-zA-Z0-9]", "", text.lower())
        if len(s) < 3:
            return 1.0

        log_sum = 0.0
        n_grams = len(s) - 1
        for i in range(n_grams):
            prob = self._transition_prob(s[i], s[i + 1])
            log_sum += math.log2(prob)

        cross_entropy = -log_sum / n_grams
        return float(min(2.0**cross_entropy, 200.0))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class DnsExfilConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Entropy thresholds
    entropy_subdomain_threshold: float = Field(default=3.6, ge=1.0, le=8.0)
    entropy_domain_threshold: float = Field(default=3.8, ge=1.0, le=8.0)

    # N-gram perplexity threshold for random / DGA domain detection
    perplexity_threshold: float = Field(default=24.0, ge=5.0, le=100.0)
    min_length_for_perplexity: int = Field(default=8, ge=3)

    # Query rate and volume burst thresholds
    rate_window_sec: float = Field(default=10.0, gt=0.0)
    rate_burst_threshold: int = Field(default=15, ge=3)

    # TXT tunneling heuristics
    txt_payload_len_threshold: int = Field(default=40, ge=10)
    txt_fqdn_len_threshold: int = Field(default=75, ge=20)
    txt_rate_burst_threshold: int = Field(default=5, ge=2)


# ---------------------------------------------------------------------------
# Query Rate Tracker
# ---------------------------------------------------------------------------
class DnsRateTracker:
    """Thread-safe sliding-window query tracker."""

    def __init__(self, window_sec: float) -> None:
        self.window_sec = window_sec
        self._lock = threading.Lock()
        # Key: client_key (host/pid/process) -> deque of timestamps
        self._query_times: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)
        self._txt_times: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)

    def record_query(self, key: str, is_txt: bool = False, now: float | None = None) -> tuple[int, int]:
        """Record query and return (total_count_in_window, txt_count_in_window)."""
        t = now if now is not None else time.monotonic()
        cutoff = t - self.window_sec
        with self._lock:
            q_dq = self._query_times[key]
            q_dq.append(t)
            while q_dq and q_dq[0] < cutoff:
                q_dq.popleft()
            q_cnt = len(q_dq)

            txt_cnt = 0
            if is_txt:
                t_dq = self._txt_times[key]
                t_dq.append(t)
                while t_dq and t_dq[0] < cutoff:
                    t_dq.popleft()
                txt_cnt = len(t_dq)

            return q_cnt, txt_cnt

    def reset(self) -> None:
        with self._lock:
            self._query_times.clear()
            self._txt_times.clear()


# ---------------------------------------------------------------------------
# Detector Implementation
# ---------------------------------------------------------------------------
class DnsExfilDetector:
    """DNS Tunneling, DGA, and Data Exfiltration Detector."""

    def __init__(self, config: DnsExfilConfig | None = None) -> None:
        self.config = config or DnsExfilConfig()
        self.lm = NgramLanguageModel()
        self.tracker = DnsRateTracker(self.config.rate_window_sec)

    def evaluate(self, event: NormalizedEvent, now: float | None = None) -> list[Finding]:
        """Evaluate a NormalizedEvent for DNS tunneling, DGA, or exfiltration indicators."""
        # Only evaluate DNS queries or network events with domain information
        domain = event.domain
        if not domain:
            raw_domain = event.raw_metadata.get("domain") or event.raw_metadata.get("query_name")
            if isinstance(raw_domain, str):
                domain = raw_domain
        if not domain:
            return []

        domain = domain.strip().rstrip(".")
        if not domain or len(domain) < 3:
            return []

        findings: list[Finding] = []
        labels = domain.split(".")
        subdomain_labels = labels[:-2] if len(labels) > 2 else labels[:-1]
        longest_subdomain = max(subdomain_labels, key=len) if subdomain_labels else labels[0]

        # 1. High-entropy subdomain / domain detection
        sub_entropy = shannon_entropy(longest_subdomain)
        full_entropy = shannon_entropy(domain)
        is_high_entropy = (
            len(longest_subdomain) >= 12 and sub_entropy >= self.config.entropy_subdomain_threshold
        ) or (len(domain) >= 20 and full_entropy >= self.config.entropy_domain_threshold)
        if is_high_entropy:
            findings.append(
                Finding(
                    finding_id=new_id(),
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source=FindingSource.BEHAVIOR,
                    rule_id="BEH_DNS_DGA_ENTROPY",
                    title=f"High-Entropy Domain Query Detected: {domain} (entropy={sub_entropy:.2f})",
                    severity=Severity.HIGH,
                    score=75.0,
                    confidence=0.85,
                    mitre_techniques=["T1568.002"],
                    attack_stage=AttackStage.COMMAND_AND_CONTROL,
                    details={
                        "domain": domain,
                        "subdomain": longest_subdomain,
                        "subdomain_entropy": round(sub_entropy, 3),
                        "full_entropy": round(full_entropy, 3),
                    },
                )
            )

        # 2. N-gram language model perplexity (DGA / pseudo-random domain syllables)
        perplexity = 0.0
        if len(longest_subdomain) >= self.config.min_length_for_perplexity:
            perplexity = self.lm.perplexity(longest_subdomain)
            if perplexity >= self.config.perplexity_threshold:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_DNS_EXFIL_PERPLEXITY",
                        title=(
                            f"Anomalous Domain Language Perplexity: {domain} (perplexity={perplexity:.1f})"
                        ),
                        severity=Severity.MEDIUM,
                        score=65.0,
                        confidence=0.80,
                        mitre_techniques=["T1568.002", "T1071.004"],
                        attack_stage=AttackStage.COMMAND_AND_CONTROL,
                        details={
                            "domain": domain,
                            "subdomain": longest_subdomain,
                            "perplexity": round(perplexity, 2),
                        },
                    )
                )

        # 3. TXT record tunneling heuristics
        record_type = str(
            event.raw_metadata.get("record_type")
            or event.raw_metadata.get("qtype")
            or event.raw_metadata.get("query_type")
            or ""
        ).upper()
        is_txt = record_type in ("TXT", "16")

        is_encoded_payload = bool(
            _HEX_RE.match(longest_subdomain)
            or _BASE32_RE.match(longest_subdomain)
            or _BASE64_RE.match(longest_subdomain)
        )

        txt_tunneling_score = 0.0
        txt_reasons: list[str] = []
        if is_txt:
            txt_reasons.append("record_type=TXT")
            if len(longest_subdomain) >= self.config.txt_payload_len_threshold:
                txt_tunneling_score += 40.0
                txt_reasons.append(f"long_label_len={len(longest_subdomain)}")
            if len(domain) >= self.config.txt_fqdn_len_threshold:
                txt_tunneling_score += 25.0
                txt_reasons.append(f"fqdn_len={len(domain)}")
            if is_encoded_payload:
                txt_tunneling_score += 35.0
                txt_reasons.append("encoded_payload_signature")
        elif is_encoded_payload and len(longest_subdomain) >= 30:
            txt_tunneling_score += 45.0
            txt_reasons.append("encoded_tunneling_payload")

        # 4. Query rate / volume burst tracker
        client_key = (
            f"pid:{event.pid}"
            if event.pid
            else (event.process_name or event.executable_path or event.host_id)
        )
        q_count, txt_count = self.tracker.record_query(client_key, is_txt=is_txt, now=now)

        if txt_count >= self.config.txt_rate_burst_threshold and is_txt:
            txt_tunneling_score += 30.0
            txt_reasons.append(f"txt_burst_count={txt_count}")

        if txt_tunneling_score >= 60.0:
            findings.append(
                Finding(
                    finding_id=new_id(),
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source=FindingSource.BEHAVIOR,
                    rule_id="BEH_DNS_TUNNEL_TXT",
                    title=f"DNS Tunneling Heuristics Detected: {domain}",
                    severity=Severity.HIGH,
                    score=min(100.0, txt_tunneling_score),
                    confidence=0.90,
                    mitre_techniques=["T1071.004", "T1048.003"],
                    attack_stage=AttackStage.EXFILTRATION,
                    details={
                        "domain": domain,
                        "record_type": record_type,
                        "reasons": txt_reasons,
                        "score": round(txt_tunneling_score, 1),
                    },
                )
            )

        if q_count >= self.config.rate_burst_threshold:
            findings.append(
                Finding(
                    finding_id=new_id(),
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    source=FindingSource.BEHAVIOR,
                    rule_id="BEH_DNS_QUERY_BURST",
                    title=(
                        f"DNS Query Rate Burst: {q_count} queries in {self.config.rate_window_sec:g}s "
                        f"from {client_key}"
                    ),
                    severity=Severity.MEDIUM,
                    score=60.0,
                    confidence=0.80,
                    mitre_techniques=["T1071.004"],
                    attack_stage=AttackStage.COMMAND_AND_CONTROL,
                    details={
                        "client_key": client_key,
                        "burst_count": q_count,
                        "window_sec": self.config.rate_window_sec,
                    },
                )
            )

        return findings


__all__ = [
    "DnsExfilConfig",
    "DnsExfilDetector",
    "DnsRateTracker",
    "NgramLanguageModel",
    "shannon_entropy",
]
