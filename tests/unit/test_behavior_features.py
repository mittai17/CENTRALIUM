from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from centralium.agent.behavior import DefaultBehaviorEngine
from centralium.agent.behavior.engine import BehaviorConfig, bytes_entropy
from centralium.agent.behavior.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, extract_features
from centralium.agent.behavior.state import BehaviorState
from centralium.agent.interfaces import BehaviorEngine, BehaviorResult
from centralium.agent.models import EventType, FindingSource, NormalizedEvent

T0 = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)


def mk(et: EventType, t: float = 0.0, **kw) -> NormalizedEvent:
    kw.setdefault("source", "test")
    return NormalizedEvent(event_type=et, timestamp=T0 + timedelta(seconds=t), **kw)


def test_schema_is_stable_and_complete():
    assert FEATURE_SCHEMA_VERSION == "1.0.0"
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)) == 45
    families = {
        "PROCESS": [
            "proc_frequency",
            "proc_rarity",
            "parent_child_frequency",
            "parent_child_rarity",
            "child_count",
            "exe_rarity",
            "unsigned",
            "path_risk",
            "privilege_context",
        ],
        "NETWORK": [
            "net_conn_count",
            "net_unique_dest",
            "net_dest_rarity",
            "net_port_rarity",
            "net_domain_rarity",
            "net_dns_entropy",
            "net_ip_reputation",
            "net_conn_burst",
        ],
        "FILE": [
            "file_create_rate",
            "file_modify_rate",
            "file_delete_rate",
            "file_rename_rate",
            "file_ext_changes",
            "file_entropy",
            "file_suspicious_dir",
            "file_exec_creation",
        ],
        "BEHAVIOR": [
            "beh_powershell",
            "beh_lolbin",
            "beh_persistence_mod",
            "beh_priv_change",
            "beh_injection",
            "beh_unusual_parent_child",
            "beh_download_execute",
            "beh_script_interpreter",
        ],
        "RANSOMWARE": [
            "rw_write_burst",
            "rw_rename_burst",
            "rw_ext_mutation",
            "rw_entropy_increase",
            "rw_shadow_copy",
        ],
    }
    for names in families.values():
        for n in names:
            assert n in FEATURE_NAMES


@pytest.mark.parametrize(
    "ev",
    [
        mk(EventType.PROCESS_START, process_name="ls", pid=1),
        mk(EventType.NETWORK_CONNECT, destination_ip="8.8.8.8", destination_port=53, domain="a.example.com"),
        mk(EventType.FILE_MODIFY, file_path="/tmp/x", pid=2),
        mk(EventType.REGISTRY_MODIFY, registry_key="HKCU\\x"),
        mk(EventType.AUTH, user="bob"),
        mk(EventType.OTHER),
    ],
)
def test_extract_returns_exact_schema_for_any_event(ev):
    st = BehaviorState()
    st.observe(ev)
    f = extract_features(ev, st)
    assert list(f.keys()) == FEATURE_NAMES
    assert all(isinstance(v, float) and math.isfinite(v) for v in f.values())


def test_process_family_rarity_and_frequency():
    st = BehaviorState()
    ev = mk(
        EventType.PROCESS_START,
        process_name="weird.exe",
        executable_path="C:\\Users\\Public\\weird.exe",
        pid=5,
        ppid=4,
        parent_process="explorer.exe",
    )
    st.observe(ev)
    f = extract_features(ev, st)
    assert f["proc_rarity"] == 1.0 and f["exe_rarity"] == 1.0 and f["parent_child_rarity"] == 1.0
    assert f["path_risk"] >= 0.8 and f["unsigned"] == 1.0
    for i in range(9):
        e2 = mk(
            EventType.PROCESS_START,
            t=i + 1,
            process_name="weird.exe",
            executable_path="C:\\Users\\Public\\weird.exe",
            pid=10 + i,
            ppid=4,
            parent_process="explorer.exe",
        )
        st.observe(e2)
    f2 = extract_features(e2, st)
    assert f2["proc_rarity"] == pytest.approx(0.1) and f2["proc_frequency"] > f["proc_frequency"]
    assert f2["child_count"] == 10  # pid 4 spawned 10 children in the window
    signed = mk(EventType.PROCESS_START, process_name="a", signer="Microsoft Windows", pid=99)
    st.observe(signed)
    assert extract_features(signed, st)["unsigned"] == 0.0
    root = mk(EventType.PROCESS_START, process_name="a", user="root", pid=98)
    st.observe(root)
    assert extract_features(root, st)["privilege_context"] == 1.0


def test_network_family():
    st = BehaviorState()
    last = None
    for i in range(30):
        last = mk(
            EventType.NETWORK_CONNECT,
            t=i * 0.1,
            destination_ip=f"198.51.100.{i}",
            destination_port=4444,
            pid=3,
        )
        st.observe(last)
    f = extract_features(last, st)
    assert f["net_conn_count"] == pytest.approx(math.log1p(30)) and f["net_unique_dest"] == pytest.approx(
        math.log1p(30)
    )
    assert (
        f["net_conn_burst"] > 3
        and f["net_dest_rarity"] == 1.0
        and f["net_port_rarity"] == pytest.approx(1 / 30)
    )
    dga = mk(EventType.DNS_QUERY, t=5, domain="xk3j9qzp7vw2mh4t.example.com", pid=3)
    st.observe(dga)
    assert extract_features(dga, st)["net_dns_entropy"] > 3.0
    rep = mk(EventType.NETWORK_CONNECT, t=6, destination_ip="1.2.3.4", raw_metadata={"ip_reputation": 0.9})
    st.observe(rep)
    assert extract_features(rep, st)["net_ip_reputation"] == 0.9


def test_file_family():
    st = BehaviorState()
    last = None
    for i in range(20):
        last = mk(EventType.FILE_CREATE, t=i * 0.1, pid=7, file_path=f"/tmp/d/f{i}.sh")
        st.observe(last)
    st.observe(
        old := mk(
            EventType.FILE_RENAME,
            t=3,
            pid=7,
            file_path="/tmp/d/a.txt.enc",
            raw_metadata={"old_path": "/tmp/d/a.txt"},
        )
    )
    f = extract_features(old, st)
    assert f["file_create_rate"] == pytest.approx(2.0) and f["file_rename_rate"] == pytest.approx(0.1)
    assert f["file_ext_changes"] == pytest.approx(math.log1p(1))
    e = extract_features(last, st)
    assert e["file_exec_creation"] == 1.0 and e["file_suspicious_dir"] == 0.8


def test_behavior_family_flags():
    st = BehaviorState()
    ps = mk(
        EventType.PROCESS_START,
        process_name="powershell.exe",
        parent_process="WINWORD.EXE",
        pid=2,
        command_line="powershell -enc " + "A" * 40,
    )
    st.observe(ps)
    f = extract_features(ps, st)
    assert f["beh_powershell"] == f["beh_lolbin"] == f["beh_script_interpreter"] == 1.0
    assert f["beh_lolbin_context_score"] > 0.5 and f["beh_unusual_parent_child"] >= 0.9
    inj = mk(EventType.PROCESS_INJECT, pid=2)
    st.observe(inj)
    assert extract_features(inj, st)["beh_injection"] == 1.0
    pr = mk(EventType.PRIVILEGE_CHANGE, pid=2)
    st.observe(pr)
    assert extract_features(pr, st)["beh_priv_change"] == 1.0
    per = mk(EventType.FILE_MODIFY, file_path="/home/u/.bashrc", pid=2)
    st.observe(per)
    assert extract_features(per, st)["beh_persistence_mod"] > 0
    # download + execute: network-connected process drops an exe that is then run
    st2 = BehaviorState()
    for e in (
        mk(EventType.NETWORK_CONNECT, t=0, pid=40, destination_ip="203.0.113.5", destination_port=80),
        mk(EventType.FILE_CREATE, t=1, pid=40, file_path="/tmp/payload.sh"),
    ):
        st2.observe(e)
    run = mk(
        EventType.PROCESS_START,
        t=5,
        pid=41,
        ppid=40,
        process_name="payload.sh",
        executable_path="/tmp/payload.sh",
    )
    st2.observe(run)
    assert extract_features(run, st2)["beh_download_execute"] == 1.0


def test_engine_protocol_and_ml_gating():
    eng = DefaultBehaviorEngine()
    assert isinstance(eng, BehaviorEngine)
    benign = [
        mk(EventType.PROCESS_EXIT, pid=1),
        mk(EventType.FILE_MODIFY, file_path="/home/u/doc.txt", pid=3),
        mk(EventType.AUTH, user="u"),
        mk(EventType.MODULE_LOAD, file_path="/usr/lib/libc.so"),
    ]
    for e in benign:
        r = eng.analyze(e, [])
        assert (
            isinstance(r, BehaviorResult)
            and r.feature_version == FEATURE_SCHEMA_VERSION
            and not r.ml_eligible
        )
        assert list(r.features) == FEATURE_NAMES
    # a repeatedly-seen, signed, common process is not ML-eligible
    for i in range(5):
        r = eng.analyze(
            mk(
                EventType.PROCESS_START,
                t=i,
                process_name="bash",
                executable_path="/usr/bin/bash",
                parent_process="sshd",
                signer="distro",
                pid=i + 10,
            ),
            [],
        )
    assert not r.ml_eligible
    # suspicious chain is eligible and carries a LOLBin finding
    bad = eng.analyze(
        mk(
            EventType.PROCESS_START,
            process_name="powershell.exe",
            parent_process="EXCEL.EXE",
            pid=77,
            command_line="powershell -nop -w hidden -enc " + "B" * 40,
        ),
        [],
    )
    assert bad.ml_eligible and any(f.source == FindingSource.LOLBIN for f in bad.findings)
    # rare process from a temp dir is eligible with no findings
    tmp = eng.analyze(
        mk(
            EventType.PROCESS_START,
            process_name="zz",
            executable_path="/dev/shm/zz",
            pid=78,
            parent_process="bash",
        ),
        [],
    )
    assert tmp.ml_eligible
    # an EPP finding forces eligibility
    from centralium.agent.models import Finding

    epp = Finding(event_id="e", source=FindingSource.RULE, rule_id="R", title="t", score=40)
    assert eng.analyze(mk(EventType.AUTH, user="u"), [epp]).ml_eligible
    c = eng.counters
    assert c["events"] > 0 and 0 < c["ml_eligible"] < c["events"]


def test_engine_does_not_mutate_event_and_baseline_sampling():
    eng = DefaultBehaviorEngine(BehaviorConfig(baseline_sample_every=3))
    e = mk(EventType.AUTH, user="u")
    before = e.model_dump()
    results = [eng.analyze(e, []).ml_eligible for _ in range(9)]
    assert e.model_dump() == before
    assert results.count(True) == 3


def test_entropy_sampling_is_opt_in_and_safe(tmp_path):
    rand = tmp_path / "rand.bin"
    rand.write_bytes(bytes(range(256)) * 64)
    txt = tmp_path / "a.txt"
    txt.write_text("a" * 5000)
    link = tmp_path / "link"
    link.symlink_to(rand)
    assert bytes_entropy(rand.read_bytes()) == pytest.approx(8.0)
    off = DefaultBehaviorEngine()
    on = DefaultBehaviorEngine(BehaviorConfig(sample_file_entropy=True))
    ev = mk(EventType.FILE_MODIFY, pid=1, file_path=str(rand))
    assert off.analyze(ev, []).features["file_entropy"] == 0.0
    assert on.analyze(ev, []).features["file_entropy"] == pytest.approx(1.0)
    assert (
        on.analyze(mk(EventType.FILE_MODIFY, pid=2, file_path=str(txt)), []).features["file_entropy"] == 0.0
    )
    # symlinks, missing files and relative paths are ignored without error
    for p in (str(link), str(tmp_path / "nope"), "relative/path"):
        assert on.analyze(mk(EventType.FILE_MODIFY, pid=3, file_path=p), []).features["file_entropy"] == 0.0


def test_event_time_driven_windows_expire():
    st = BehaviorState(window_sec=10)
    for i in range(5):
        st.observe(mk(EventType.NETWORK_CONNECT, t=i, destination_ip=f"198.51.100.{i}", pid=1))
    assert st.net_stats()["count"] == 5
    st.observe(late := mk(EventType.NETWORK_CONNECT, t=100, destination_ip="198.51.100.99", pid=1))
    assert st.net_stats()["count"] == 1 and extract_features(late, st)["net_unique_dest"] == pytest.approx(
        math.log1p(1)
    )
