from __future__ import annotations

from datetime import UTC, datetime, timedelta

from centralium.agent.behavior.state import BehaviorState
from centralium.agent.models import (
    AttackStage,
    DetectionResult,
    EventType,
    FindingSource,
    NormalizedEvent,
    ScoreFamily,
    Severity,
)
from centralium.agent.ransomware import RansomwareConfig, RansomwareScorer

T0 = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)


class Sim:
    """Feeds synthetic events into a state and scores after each one."""

    def __init__(
        self,
        pid: int = 900,
        ppid: int = 800,
        name: str = "locker.exe",
        exe: str = "C:\\Users\\a\\AppData\\Local\\Temp\\locker.exe",
    ) -> None:
        self.state = BehaviorState()
        self.scorer = RansomwareScorer()
        self.pid, self.ppid, self.name, self.exe = pid, ppid, name, exe
        self.t = 0.0
        self.last = None

    def feed(self, et: EventType, dt: float = 0.05, **kw) -> NormalizedEvent:
        self.t += dt
        kw.setdefault("pid", self.pid)
        kw.setdefault("ppid", self.ppid)
        kw.setdefault("process_name", self.name)
        kw.setdefault("executable_path", self.exe)
        ev = NormalizedEvent(event_type=et, timestamp=T0 + timedelta(seconds=self.t), source="test", **kw)
        self.state.observe(ev)
        self.last = self.scorer.assess(ev, self.state)
        return ev

    def parent_start(self, name: str = "WINWORD.EXE") -> None:
        ev = NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=self.ppid,
            ppid=1,
            process_name=name,
            timestamp=T0,
            source="test",
        )
        self.state.observe(ev)

    def writes(self, n: int, entropy: float | None = 7.9, before: float | None = 4.5) -> None:
        for i in range(n):
            meta = {}
            if entropy is not None:
                meta["entropy_after"] = entropy
            if before is not None:
                meta["entropy_before"] = before
            self.feed(
                EventType.FILE_MODIFY, file_path=f"C:\\Users\\a\\Documents\\f{i}.docx", raw_metadata=meta
            )

    def renames(self, n: int, new_ext: str = ".locked") -> None:
        for i in range(n):
            old = f"C:\\Users\\a\\Documents\\f{i}.docx"
            self.feed(EventType.FILE_RENAME, file_path=old + new_ext, raw_metadata={"old_path": old})


def test_single_file_operation_never_triggers():
    s = Sim()
    s.feed(
        EventType.FILE_MODIFY,
        file_path="C:\\x\\a.docx",
        raw_metadata={"entropy_after": 7.9, "entropy_before": 3.0},
    )
    assert s.last is not None and s.last.score < 20 and not s.last.active
    s.feed(
        EventType.FILE_RENAME, file_path="C:\\x\\a.docx.locked", raw_metadata={"old_path": "C:\\x\\a.docx"}
    )
    assert s.last.score < 20
    assert (
        s.scorer.findings(NormalizedEvent(event_type=EventType.FILE_MODIFY, source="t"), s.last, s.state)
        == []
    )


def test_single_component_is_capped_even_when_extreme():
    s = Sim(name="unknown.exe", exe="C:\\x\\unknown.exe")
    s.writes(400, entropy=None, before=None)  # huge write burst alone
    assert s.last.components["write_burst"] == 1.0
    assert s.last.score <= RansomwareConfig().single_component_cap
    assert s.scorer.findings(NormalizedEvent(event_type=EventType.FILE_MODIFY, source="t"), s.last) == []


def test_full_ransomware_chain_is_critical():
    s = Sim()
    s.parent_start("WINWORD.EXE")
    s.feed(
        EventType.PROCESS_START,
        command_line="vssadmin.exe delete shadows /all /quiet",
        process_name="vssadmin.exe",
        executable_path="C:\\Windows\\System32\\vssadmin.exe",
        pid=901,
        ppid=900,
    )
    s.writes(160)
    s.renames(70)
    a = s.last
    assert a.score >= 80, a
    assert len(a.active) >= 3 and {"write_burst", "extension_mutation", "entropy_increase"} <= set(a.active)
    findings = s.scorer.findings(
        s.feed(EventType.FILE_RENAME, file_path="C:\\z.locked", raw_metadata={"old_path": "C:\\z"}),
        s.last,
        s.state,
    )
    comp = [f for f in findings if f.rule_id == "RW-COMPOSITE"]
    assert comp and comp[0].severity == Severity.CRITICAL and "T1486" in comp[0].mitre_techniques
    assert comp[0].attack_stage == AttackStage.IMPACT and comp[0].source == FindingSource.RANSOMWARE
    res = s.scorer.to_result(a)
    assert (
        isinstance(res, DetectionResult)
        and res.family == ScoreFamily.DETERMINISTIC_EVIDENCE
        and res.score >= 80
    )


def test_shadow_copy_commands_detected_but_not_alone_critical():
    s = Sim(name="cmd.exe", exe="C:\\Windows\\System32\\cmd.exe")
    for cmd in (
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "wbadmin delete catalog -quiet",
        "powershell Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}".replace(
            "{$_.Delete()}", "delete"
        ),
    ):
        s2 = Sim(name="cmd.exe", exe="C:\\Windows\\System32\\cmd.exe")
        ev = s2.feed(EventType.PROCESS_START, command_line=cmd)
        assert s2.last.shadow_kind, cmd
        fs = s2.scorer.findings(ev, s2.last, s2.state)
        assert any(f.rule_id == "RW-SHADOW-COPY-DESTRUCTION" and "T1490" in f.mitre_techniques for f in fs)
        assert s2.last.score < 40  # shadow alone != ransomware composite
    ev = s.feed(EventType.PROCESS_START, command_line="vssadmin list shadows")
    assert s.last.shadow_kind is None and ev is not None


def test_benign_bulk_writer_is_dampened_and_no_alert():
    s = Sim(name="git", exe="/usr/bin/git", pid=50, ppid=49)
    s.writes(200, entropy=7.9, before=4.0)  # packfile-like churn
    s.renames(40, new_ext=".tmp")
    comps_active = len(s.last.active)
    assert comps_active >= 2
    s2 = Sim(name="x", exe="/usr/bin/x", pid=50, ppid=49)
    s2.writes(200, entropy=7.9, before=4.0)
    s2.renames(40, new_ext=".tmp")
    assert s.last.score < s2.last.score
    assert any("bulk file writer" in r for r in s.last.reasons)


def test_ransom_extensions_and_notes_increase_extension_component():
    s = Sim()
    s.renames(5, ".wncry")
    assert s.last.components["extension_mutation"] >= 0.8
    s2 = Sim()
    s2.renames(5, ".bak")
    assert s2.last.components["extension_mutation"] < 0.5
    s3 = Sim()
    for i in range(3):
        s3.feed(EventType.FILE_CREATE, file_path=f"C:\\d{i}\\README_TO_DECRYPT.txt")
    assert s3.last.components["extension_mutation"] >= 0.6


def test_entropy_fallback_without_before_values_and_window_expiry():
    s = Sim(name="y.exe", exe="C:\\y.exe")
    s.writes(40, entropy=7.95, before=None)
    assert s.last.components["entropy_increase"] >= 0.5
    # compressible data (low entropy) -> no entropy component
    s2 = Sim(name="y.exe", exe="C:\\y.exe")
    s2.writes(40, entropy=4.0, before=None)
    assert s2.last.components["entropy_increase"] == 0.0
    # after the window passes, activity ages out
    s.t += 500
    s.feed(EventType.FILE_MODIFY, file_path="C:\\late.txt")
    assert s.last.components["write_burst"] < 0.2


def test_alert_cooldown_and_state_bounds():
    s = Sim()
    s.parent_start()
    s.writes(160)
    s.renames(70)
    ev = s.feed(EventType.FILE_RENAME, file_path="C:\\q.locked", raw_metadata={"old_path": "C:\\q"})
    first = s.scorer.findings(ev, s.last, s.state)
    second = s.scorer.findings(ev, s.last, s.state)
    assert first and not [f for f in second if f.rule_id == "RW-COMPOSITE"]
    big = BehaviorState(max_pids=50, max_ops_per_pid=100)
    for i in range(5000):
        big.observe(
            NormalizedEvent(
                event_type=EventType.FILE_MODIFY, pid=i, file_path=f"/tmp/{i}", timestamp=T0, source="t"
            )
        )
    assert len(big.file_ops) <= 51
    assert all(len(d) <= 200 for d in big.file_ops.values())
