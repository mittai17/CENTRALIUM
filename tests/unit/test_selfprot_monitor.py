from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from centralium.agent.interfaces import SelfProtection
from centralium.agent.models import EventType, FindingSource, NormalizedEvent, Severity
from centralium.agent.self_protection import (
    HAVE_CRYPTO,
    SelfProtectionMonitor,
    SelfProtectionSettings,
    build_manifest,
    check_dir_permissions,
    verify_manifest,
)
from centralium.agent.storage import Database


@pytest.fixture
def env(tmp_path: Path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "a.py").write_text("print('a')\n")
    (pkg / "b.py").write_text("print('b')\n")
    cfg = tmp_path / "agent.toml"
    cfg.write_text("mode='passive'\n")
    events: list[NormalizedEvent] = []
    audit: list[tuple[str, str, dict]] = []
    s = SelfProtectionSettings(
        package_root=pkg, baseline_path=tmp_path / "state" / "baseline.json", config_files=[cfg]
    )
    m = SelfProtectionMonitor(s, sink=events.append, audit=lambda a, e, d: audit.append((a, e, d)))
    m.create_baseline()
    return pkg, cfg, m, events, audit, s


def rules(fs):
    return sorted(f.rule_id for f in fs)


def test_protocol(env):
    assert isinstance(env[2], SelfProtection)


def test_clean_state_no_findings(env):
    assert env[2].check() == []


def test_modified_file_detected_and_tamper_event_emitted(env):
    pkg, _, m, events, audit, _ = env
    (pkg / "a.py").write_text("import os; os.system('x')\n")
    fs = m.check()
    assert rules(fs) == ["SP-FILE-MODIFIED"]
    f = fs[0]
    assert (
        f.source is FindingSource.SELF_PROTECTION
        and f.severity is Severity.CRITICAL
        and not f.known_malicious
    )
    assert f.details["file"] == "a.py"
    (ev,) = events
    assert ev.event_type is EventType.TAMPER and ev.event_id == f.event_id and ev.source == "self_protection"
    assert any(e == "tamper_detected" and d["rule_id"] == "SP-FILE-MODIFIED" for _, e, d in audit)


def test_events_not_reemitted_until_state_changes(env):
    pkg, _, m, events, audit, _ = env
    (pkg / "a.py").write_text("x\n")
    m.check()
    m.check()
    assert len(events) == 1
    (pkg / "a.py").write_text("print('a')\n")  # restored
    assert m.check() == []
    assert any(e == "tamper_resolved" for _, e, _ in audit)


def test_missing_and_unexpected_files(env):
    pkg, _, m, *_ = env
    (pkg / "b.py").unlink()
    (pkg / "evil.py").write_text("x")
    assert rules(m.check()) == ["SP-FILE-MISSING", "SP-FILE-UNEXPECTED"]


def test_config_modification_and_accepted_change(env):
    _, cfg, m, _, audit, _ = env
    cfg.write_text("mode='active'\n")
    assert rules(m.check()) == ["SP-CONFIG-MODIFIED"]
    m.accept_config_change("alice", "enable active mode")
    assert m.check() == []
    assert any(e == "baseline_created" and "alice" in str(d) for _, e, d in audit)


def test_missing_baseline_reported(env):
    _, _, m, _, _, s = env
    s.baseline_path.unlink()
    assert rules(m.check()) == ["SP-BASELINE-MISSING"]


def test_corrupt_baseline_reported(env):
    _, _, m, _, _, s = env
    s.baseline_path.write_text("{nope")
    assert rules(m.check()) == ["SP-BASELINE-CORRUPT"]


def test_component_health(env):
    _, _, m, *_ = env
    m.register_component("collector", lambda: (False, "no events for 300s"))
    m.register_component("sync", lambda: (True, ""))
    m.register_component("crashy", lambda: 1 / 0)  # type: ignore[arg-type,return-value]
    fs = m.check()
    assert rules(fs) == ["SP-COMPONENT-UNHEALTHY"] * 2
    assert {f.details["component"] for f in fs} == {"collector", "crashy"}


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_protected_dir_permissions(env, tmp_path):
    _, _, m, _, _, s = env
    d = tmp_path / "data"
    d.mkdir()
    d.chmod(0o700)
    s.protected_dirs = [d]
    assert m.check() == []
    d.chmod(0o777)
    assert rules(m.check()) == ["SP-DIR-PERMISSIONS"]
    assert check_dir_permissions(tmp_path / "nope")[0].endswith("missing")


def test_watchdog_thread_detects_tamper_and_stops(env):
    pkg, _, m, events, audit, s = env
    s.interval_s = 0.02
    m.start()
    try:
        assert m.watchdog_alive()
        (pkg / "a.py").write_text("tampered")
        deadline = time.time() + 3
        while not events and time.time() < deadline:
            time.sleep(0.02)
        assert events
    finally:
        m.stop()
    assert not m.watchdog_alive()
    assert {"watchdog_started", "watchdog_stopped"} <= {e for _, e, _ in audit}


def test_audit_chain_with_real_database(env, tmp_path):
    pkg, _, _, _, _, s = env
    with Database(tmp_path / "main.db") as db:
        m = SelfProtectionMonitor(s, audit=db.audit.append)
        (pkg / "a.py").write_text("tampered")
        m.check()
        assert db.audit.entries()[0]["event_type"] == "tamper_detected"
        assert db.audit.verify().ok


def test_manifest_helpers(tmp_path):
    (tmp_path / "x.py").write_text("1")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.py").write_text("skip")
    (tmp_path / "x.txt").write_text("skip")
    man = build_manifest(tmp_path)
    assert list(man) == ["x.py"]
    assert verify_manifest(tmp_path, man).ok


@pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")
def test_signed_baseline_required_when_key_configured(env):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from centralium.agent.self_protection import generate_keypair

    _, _, m, _, _, s = env
    priv, pub = generate_keypair()
    s.public_key = pub
    assert rules(m.check()) == ["SP-BASELINE-SIGNATURE"]  # unsigned
    sig_path = Path(str(s.baseline_path) + ".sig")
    sig_path.write_bytes(Ed25519PrivateKey.from_private_bytes(priv).sign(s.baseline_path.read_bytes()))
    assert m.check() == []
    s.baseline_path.write_bytes(s.baseline_path.read_bytes() + b" ")  # attacker edits baseline
    assert rules(m.check()) == ["SP-BASELINE-SIGNATURE"]
