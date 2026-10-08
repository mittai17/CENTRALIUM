"""Unit tests for DNS tunneling, DGA, and exfiltration detector."""

from __future__ import annotations

import time

from centralium.agent.behavior.dns_exfil import (
    DnsExfilConfig,
    DnsExfilDetector,
    NgramLanguageModel,
    shannon_entropy,
)
from centralium.agent.models import AttackStage, EventType, FindingSource, NormalizedEvent, Severity


def test_shannon_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaa") == 0.0
    # "0123456789abcdef" has maximum entropy for 16 distinct chars = log2(16) = 4.0
    hex_entropy = shannon_entropy("0123456789abcdef")
    assert hex_entropy >= 3.9


def test_ngram_language_model_perplexity() -> None:
    lm = NgramLanguageModel()
    benign_perp = lm.perplexity("google")
    benign_perp2 = lm.perplexity("microsoft")
    dga_perp = lm.perplexity("zxqkjpmtwvrf")
    assert benign_perp < 20.0
    assert benign_perp2 < 20.0
    assert dga_perp > benign_perp
    assert dga_perp >= 24.0


def test_dns_detector_benign_domain() -> None:
    detector = DnsExfilDetector()
    ev = NormalizedEvent(
        event_type=EventType.DNS_QUERY,
        domain="www.google.com",
        pid=1234,
        process_name="chrome",
    )
    findings = detector.evaluate(ev)
    assert len(findings) == 0


def test_dns_detector_high_entropy_dga() -> None:
    detector = DnsExfilDetector()
    # High entropy random hex/base32 subdomain
    ev = NormalizedEvent(
        event_type=EventType.DNS_QUERY,
        domain="f9b2d8e41a7c5039ef12.c2server.org",
        pid=5555,
        process_name="malware.exe",
    )
    findings = detector.evaluate(ev)
    assert len(findings) >= 1
    entropy_finding = next((f for f in findings if f.rule_id == "BEH_DNS_DGA_ENTROPY"), None)
    assert entropy_finding is not None
    assert entropy_finding.source == FindingSource.BEHAVIOR
    assert entropy_finding.attack_stage == AttackStage.COMMAND_AND_CONTROL
    assert "T1568.002" in entropy_finding.mitre_techniques
    assert entropy_finding.severity == Severity.HIGH


def test_dns_detector_ngram_perplexity() -> None:
    cfg = DnsExfilConfig(entropy_subdomain_threshold=5.0)  # Make entropy not trigger
    detector = DnsExfilDetector(cfg)
    # Pronounceable-entropy but consonant-heavy DGA string
    ev = NormalizedEvent(
        event_type=EventType.DNS_QUERY,
        domain="qkxjvpwzfmrt.dynu.net",
        pid=1001,
        process_name="beacon.exe",
    )
    findings = detector.evaluate(ev)
    assert any(f.rule_id == "BEH_DNS_EXFIL_PERPLEXITY" for f in findings)


def test_dns_detector_txt_tunneling() -> None:
    detector = DnsExfilDetector()
    long_payload = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
    ev = NormalizedEvent(
        event_type=EventType.DNS_QUERY,
        domain=f"{long_payload}.tunnel.exfil.attacker.com",
        pid=4000,
        process_name="iodine",
        raw_metadata={"record_type": "TXT"},
    )
    findings = detector.evaluate(ev)
    txt_finding = next((f for f in findings if f.rule_id == "BEH_DNS_TUNNEL_TXT"), None)
    assert txt_finding is not None
    assert txt_finding.attack_stage == AttackStage.EXFILTRATION
    assert "T1048.003" in txt_finding.mitre_techniques
    assert txt_finding.severity == Severity.HIGH
    assert txt_finding.score >= 60.0


def test_dns_detector_query_rate_burst() -> None:
    cfg = DnsExfilConfig(rate_window_sec=5.0, rate_burst_threshold=5)
    detector = DnsExfilDetector(cfg)
    now = time.monotonic()
    findings_list = []
    for i in range(6):
        ev = NormalizedEvent(
            event_type=EventType.DNS_QUERY,
            domain=f"query{i}.domain.com",
            pid=8888,
            process_name="exfil_tool",
        )
        findings = detector.evaluate(ev, now=now + i * 0.1)
        findings_list.extend(findings)

    burst_findings = [f for f in findings_list if f.rule_id == "BEH_DNS_QUERY_BURST"]
    assert len(burst_findings) >= 1
    assert burst_findings[0].attack_stage == AttackStage.COMMAND_AND_CONTROL
    assert "T1071.004" in burst_findings[0].mitre_techniques


def test_dns_detector_ignores_non_dns_events() -> None:
    detector = DnsExfilDetector()
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        process_name="ls",
        command_line="/bin/ls -la",
    )
    assert detector.evaluate(ev) == []
