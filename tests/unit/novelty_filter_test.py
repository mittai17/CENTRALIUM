from __future__ import annotations

from datetime import UTC, datetime, timedelta

from centralium.agent.interfaces import BehaviorResult, NoveltyFilter
from centralium.agent.models import EventType, Finding, FindingSource, NormalizedEvent, Severity
from centralium.agent.novelty import BaselineNoveltyFilter, NoveltySettings

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def e(i=0, **kw) -> NormalizedEvent:
    kw.setdefault("event_type", EventType.PROCESS_START)
    kw.setdefault("process_name", "chrome")
    return NormalizedEvent(timestamp=T0 + timedelta(seconds=i), source="test", **kw)


B = BehaviorResult()


def teach(f: BaselineNoveltyFilter, n=5, **kw):
    for i in range(n):
        f.learn(e(i, **kw))


def test_protocol():
    assert isinstance(BaselineNoveltyFilter(), NoveltyFilter)


def test_empty_baseline_is_novel_conservative():
    r = BaselineNoveltyFilter().assess(e(user="a", parent_process="bash"), B)
    assert r.is_novel and r.novelty_score == 1.0
    assert "empty" in r.reasons[0]


def test_learned_pattern_not_novel_and_unseen_is_novel():
    f = BaselineNoveltyFilter()
    teach(
        f,
        user="alice",
        parent_process="explorer.exe",
        domain="update.example",
        executable_path="/opt/chrome/chrome",
    )
    known = f.assess(e(100, user="alice", parent_process="explorer.exe", domain="update.example",
                       executable_path="/opt/chrome/chrome"), B)  # fmt: skip
    assert not known.is_novel and known.novelty_score < 0.2
    assert known.baseline_hits > 0
    odd = f.assess(
        e(101, process_name="evil", user="alice", parent_process="winword.exe", domain="c2.example"), B
    )
    assert odd.is_novel and odd.novelty_score > 0.9
    assert any("parent-child" in r for r in odd.reasons) and any("destination" in r for r in odd.reasons)


def test_new_parent_child_or_destination_for_known_process_raises_novelty():
    f = BaselineNoveltyFilter()
    teach(f, parent_process="explorer.exe", domain="a.example")
    base = f.assess(e(100, parent_process="explorer.exe", domain="a.example"), B).novelty_score
    new_parent = f.assess(e(101, parent_process="winword.exe", domain="a.example"), B).novelty_score
    new_dest = f.assess(e(102, parent_process="explorer.exe", domain="zzz.example"), B).novelty_score
    assert new_parent > base and new_dest > base


def test_min_hits_gradual():
    f = BaselineNoveltyFilter(settings=NoveltySettings(min_hits=4))
    f.learn(e(0))
    one = f.assess(e(1), B).novelty_score
    for i in range(2, 6):
        f.learn(e(i))
    est = f.assess(e(10), B).novelty_score
    assert one > est == 0.0 or est < 0.1


def test_signed_trust_reduces_but_does_not_erase():
    s = NoveltySettings(trusted_signers=frozenset({"Microsoft Corporation"}))
    f = BaselineNoveltyFilter(settings=s)
    teach(f, process_name="other")
    plain = f.assess(e(50, process_name="newtool"), B).novelty_score
    signed = f.assess(e(50, process_name="newtool", signer="Microsoft Corporation"), B).novelty_score
    unknown_signer = f.assess(e(50, process_name="newtool", signer="Shady Ltd"), B).novelty_score
    assert signed < plain and signed > 0
    assert unknown_signer == plain


def test_high_severity_finding_overrides_baseline():
    f = BaselineNoveltyFilter()
    teach(f)
    fnd = Finding(
        event_id="x", source=FindingSource.BEHAVIOR, rule_id="r", title="t", severity=Severity.HIGH, score=70
    )
    r = f.assess(e(100), BehaviorResult(findings=[fnd]))
    assert r.is_novel
    assert any("overrides" in x for x in r.reasons)


def test_assess_never_writes_baseline_learning_mode_only():
    f = BaselineNoveltyFilter()
    teach(f)
    size = f.baseline_size()
    for i in range(50):
        f.assess(e(200 + i, process_name="attacker"), B)
    assert f.baseline_size() == size
    assert f.assess(e(300, process_name="attacker"), B).is_novel


def test_frequency_spike_detected():
    f = BaselineNoveltyFilter(settings=NoveltySettings(min_hits=3, freq_slack_abs=2))
    for i in range(10):  # ~1 event per 10s => small learned peak rate
        f.learn(e(i * 10))
    assert not f.assess(e(200), B).is_novel
    # burst of recent activity recorded in the rate window without teaching the peak
    for i in range(60):
        f._rate("chrome", (T0 + timedelta(seconds=1000 + i * 0.1)).timestamp(), record=True)
    r = f.assess(e(1006), B)
    assert any("exceeds baseline peak" in x for x in r.reasons)


def test_baselines_persist_across_restart(tmp_path):
    p = tmp_path / "nov.db"
    f = BaselineNoveltyFilter(p)
    teach(f, user="alice", parent_process="bash")
    f.close()
    g = BaselineNoveltyFilter(p)
    r = g.assess(e(100, user="alice", parent_process="bash"), B)
    assert not r.is_novel
    assert g.baseline_size()["process"] == 1
    g.close()


def test_false_positive_reduction_over_learning_window():
    f = BaselineNoveltyFilter()
    events = [
        e(i, process_name=n, parent_process="bash", user="u") for i, n in enumerate(["git", "ls", "vim"] * 6)
    ]
    f.learn_many(events)
    novel = [f.assess(ev, B).is_novel for ev in events]
    assert not any(novel)
