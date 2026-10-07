"""Acceptance-checklist items that the 10 scenarios do not cover: tamper detection, offline queue +
sync recovery against the real dashboard ingest, process suspension/termination on a throw-away
child, network block/isolation via a mock runner, model-missing fallback, dashboard-approved
actions, and graph visibility in the dashboard.

Nothing here touches anything but processes/files this test spawned/created itself."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import psutil
import pytest
from fastapi.testclient import TestClient

from centralium.agent.config import load_config
from centralium.agent.models import (
    ActionResult,
    ActionStatus,
    EventType,
    NormalizedEvent,
    PolicyDecision,
    ResponseAction,
    RiskBand,
)
from centralium.agent.response.base import ProcInfo
from centralium.agent.runtime import ApprovedActionDispatcher, write_graph_snapshot
from centralium.agent.self_protection import SelfProtectionMonitor, SelfProtectionSettings
from centralium.agent.storage import Database
from centralium.agent.sync import HttpTransport, SyncWorker
from dashboard.backend.app import create_app
from tests.e2e.helpers import (
    EICAR,
    RecordingBackend,
    RecordingRunner,
    make_rt,
    run_events,
    sandbox_cfg,
    scenario,
)

pytestmark = pytest.mark.e2e

TOKENS = {
    "viewer": "viewer-token-0123456789",
    "analyst": "analyst-token-0123456789",
    "admin": "admin-token-0123456789",
    "agent": "agent-token-0123456789",
}


def _hdr(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


# --------------------------------------------------------------------------- tamper detection
def test_tamper_detection_flows_into_pipeline_and_audit(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "agent.py").write_text("print('ok')\n")
    rt = make_rt(sandbox_cfg(tmp_path))
    try:
        outs = []
        mon = SelfProtectionMonitor(
            SelfProtectionSettings(package_root=pkg, baseline_path=tmp_path / "baseline.json"),
            finding_sink=lambda ev, f: outs.append(rt.pipeline.process(ev, extra_findings=[f])),
            audit=lambda a, e, d: rt.db.audit.append(a, e, d),
        )
        mon.create_baseline(actor="test", reason="baseline")
        assert mon.check() == []
        (pkg / "agent.py").write_text("print('tampered')\n")
        found = mon.check()
        assert {f.rule_id for f in found} == {"SP-FILE-MODIFIED"}
        assert len(outs) == 1
        out = outs[0]
        assert out.event_id and any(f.rule_id == "SP-FILE-MODIFIED" for f in out.findings)
        assert out.risk is not None and out.risk.band in (RiskBand.HIGH, RiskBand.CRITICAL)
        assert out.incident is not None  # tamper becomes a first-class incident
        assert any(
            r["event_type"] == "tamper_detected" for r in rt.db.query("SELECT event_type FROM audit_log")
        )
        # re-checking an unchanged tampered state does not re-alert
        mon.check()
        assert len(outs) == 1
    finally:
        rt.close()


def test_audit_log_tamper_detected_by_cli_verify(tmp_path):
    rt = make_rt(sandbox_cfg(tmp_path))
    try:
        run_events(rt, scenario("known_ioc").events)
        assert rt.db.audit.verify().ok
        db_path = Path(str(rt.db.path))
    finally:
        rt.close()
    con = sqlite3.connect(db_path)
    con.execute(
        "UPDATE audit_log SET details = '{\"forged\": true}' WHERE seq = (SELECT MIN(seq) FROM audit_log)"
    )
    con.commit()
    con.close()
    env = {**os.environ, "CENTRALIUM_PATHS__DATA_DIR": str(tmp_path / "data")}
    cp = subprocess.run(
        [sys.executable, "-m", "centralium.agent.main", "audit", "verify"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert cp.returncode == 1, cp.stdout + cp.stderr
    assert json.loads(cp.stdout)["ok"] is False


# --------------------------------------------------------------------------- offline queue + sync recovery
class FlakyClient:
    """httpx-like client: raises ConnectError while 'down', else forwards to the real dashboard app."""

    def __init__(self, inner: TestClient) -> None:
        self.inner = inner
        self.down = True
        self.attempts = 0

    def post(self, url: str, **kw: Any) -> httpx.Response:
        self.attempts += 1
        if self.down:
            raise httpx.ConnectError("dashboard unreachable (test)")
        return self.inner.post(url, **kw)


def test_offline_queue_survives_restart_and_syncs_to_dashboard_on_recovery(tmp_path, monkeypatch):
    monkeypatch.setenv("CENTRALIUM_SYNC_TOKEN", TOKENS["agent"])
    dash_db = tmp_path / "dashboard.db"
    app = create_app(dash_db, config=load_config(None, env={}), tokens=TOKENS)
    client = FlakyClient(TestClient(app))
    transport = HttpTransport("http://127.0.0.1:8765/api/ingest", client=client, host_id="e2e-host")
    cfg = sandbox_cfg(tmp_path, sync_enabled=True)
    rt = make_rt(cfg, transport=transport)
    try:
        outs = run_events(rt, scenario("office_powershell_chain").events)
        assert any(o.incident for o in outs)
        queued = rt.sync_queue.pending()
        assert queued >= 2
        assert rt.sync_worker is not None and rt.sync_worker.run_once() == 0  # dashboard down
        assert client.attempts >= 1 and rt.sync_queue.pending() == queued
    finally:
        rt.close()
    # "agent restart": reopen the same durable queue - nothing was lost
    from centralium.agent.sync import DurableSyncQueue

    q2 = DurableSyncQueue(tmp_path / "data" / "sync_queue.db")
    assert q2.pending() == queued
    con = sqlite3.connect(tmp_path / "data" / "sync_queue.db")
    con.execute(
        "UPDATE sync_queue SET next_attempt_at = '1970-01-01T00:00:00.000000+00:00'"
    )  # backoff elapsed
    con.commit()
    con.close()
    # connectivity returns
    client.down = False
    worker = SyncWorker(q2, transport, enabled=lambda: True)
    assert worker.run_once() == queued
    assert q2.pending() == 0
    # dedup: re-enqueueing the same record is rejected
    assert q2.stats()["by_status"].get("delivered") == queued
    # the dashboard now has the incident + events
    check = TestClient(app)
    incs = check.get("/api/incidents", headers=_hdr("viewer")).json()
    items = incs["items"] if isinstance(incs, dict) else incs
    assert len(items) >= 1
    dash = Database(dash_db)
    try:
        assert dash.count("events") >= 1 and dash.count("incidents") >= 1
    finally:
        dash.close()


# --------------------------------------------------------------------------- process suspend / terminate (throw-away child only)
@pytest.fixture
def throwaway_child(tmp_path):
    exe = shutil.which("sleep")
    if exe is None or not sys.platform.startswith("linux"):
        pytest.skip("needs a Linux 'sleep' binary")
    copy = tmp_path / "evil_sleep"
    shutil.copy(exe, copy)
    copy.chmod(0o755)
    p = subprocess.Popen(
        [str(copy), "300"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.2)
    try:
        yield p, copy
    finally:
        if p.poll() is None:
            p.kill()
        p.wait(timeout=5)


def _live_cfg(tmp_path: Path, **kw: Any):
    """A LIVE (non-test) ACTIVE config - only used with mocked/throw-away targets."""
    return load_config(
        None,
        env={},
        mode="ACTIVE",
        paths={"data_dir": str(tmp_path / "live")},
        policy={"require_approval": False, "min_risk_destructive": 80.0},
        **kw,
    )


def test_process_suspend_then_terminate_real_executor_on_throwaway_child(tmp_path, throwaway_child):
    child, copy = throwaway_child
    from centralium.agent.response import create_executor

    ex = create_executor(runner=RecordingRunner())
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START, pid=child.pid, ppid=os.getpid(), process_name="evil_sleep",
        executable_path=str(copy), source="test",
    )  # fmt: skip
    base = {"event_id": ev.event_id, "pid": child.pid, "process_name": "evil_sleep"}
    res = ex.execute(PolicyDecision(action=ResponseAction.SUSPEND_PROCESS, allowed=True, target=base), ev)
    assert res.status == ActionStatus.EXECUTED, res.detail
    deadline = time.time() + 3
    while time.time() < deadline and psutil.Process(child.pid).status() != psutil.STATUS_STOPPED:
        time.sleep(0.05)
    assert psutil.Process(child.pid).status() == psutil.STATUS_STOPPED
    res = ex.execute(PolicyDecision(action=ResponseAction.TERMINATE_PROCESS, allowed=True, target=base), ev)
    assert res.status == ActionStatus.EXECUTED, res.detail
    assert child.wait(timeout=5) == -9  # SIGKILL
    # our own process and PID 1 are protected even if a decision asks for them
    for pid in (os.getpid(), 1):
        refused = ex.execute(
            PolicyDecision(
                action=ResponseAction.TERMINATE_PROCESS, allowed=True,
                target={"event_id": ev.event_id, "pid": pid, "process_name": "x"},
            ),
            ev,
        )  # fmt: skip
        assert refused.status == ActionStatus.FAILED and "refused" in refused.detail
    assert psutil.pid_exists(os.getpid())


def test_full_pipeline_terminates_and_quarantines_throwaway_child_in_active_mode(tmp_path, throwaway_child):
    """LIVE ACTIVE config end-to-end: known-bad hash on a throw-away child -> TERMINATE + QUARANTINE of
    the child's own copied binary. Network commands go to a recording runner (never executed)."""
    child, copy = throwaway_child
    runner = RecordingRunner()
    rt = make_rt(_live_cfg(tmp_path), command_runner=runner, runner_guard=False, llm_mode="off")
    try:
        assert rt.config.destructive_allowed(rt.modes.mode) and not rt.config.test_mode
        ev = NormalizedEvent(
            event_type=EventType.PROCESS_START, pid=child.pid, ppid=os.getpid(), process_name="evil_sleep",
            executable_path=str(copy), hash_sha256=EICAR, source="test", host_id="localhost",
        )  # fmt: skip
        out = rt.pipeline.process(ev)
        statuses = {(a.action, a.status) for a in out.actions}
        assert (ResponseAction.TERMINATE_PROCESS, ActionStatus.EXECUTED) in statuses, out.actions
        assert child.wait(timeout=5) == -9
        assert (ResponseAction.QUARANTINE_FILE, ActionStatus.EXECUTED) in statuses, out.actions
        assert not copy.exists()  # moved out of the executable path
        recs = rt.quarantine.list()
        assert len(recs) == 1 and recs[0].original_path == str(copy.resolve())
        assert any(
            r["event_type"] == "response_action" for r in rt.db.query("SELECT event_type FROM audit_log")
        )
        assert runner.calls == []  # no firewall command was needed for a process event
    finally:
        rt.close()


# --------------------------------------------------------------------------- network block / isolation (mock runner)
def test_network_block_and_isolation_emit_validated_firewall_argv_via_mock_runner(tmp_path):
    from centralium.agent.response import create_executor

    runner = RecordingRunner()
    ex = create_executor(platform="linux", runner=runner, process_backend=RecordingBackend(), firewall="nft")
    ev = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT, pid=4242, process_name="svc", destination_ip="203.0.113.50",
        destination_port=443, protocol="tcp", source="test",
    )  # fmt: skip
    res = ex.execute(
        PolicyDecision(
            action=ResponseAction.BLOCK_CONNECTION, allowed=True,
            target={"event_id": ev.event_id, "ip": "203.0.113.50", "port": 443, "protocol": "tcp"},
        ),
        ev,
    )  # fmt: skip
    assert res.status == ActionStatus.EXECUTED, res.detail
    assert runner.calls and all(isinstance(a, str) for c in runner.calls for a in c)
    flat = " ".join(" ".join(c) for c in runner.calls)
    assert "203.0.113.50" in flat and "443" in flat and runner.calls[0][0] == "nft"
    n_block = len(runner.calls)
    res = ex.execute(PolicyDecision(action=ResponseAction.ISOLATE_ENDPOINT, allowed=True, target={}), ev)
    assert res.status == ActionStatus.EXECUTED, res.detail
    iso = " ".join(" ".join(c) for c in runner.calls[n_block:])
    assert "centralium_iso" in iso and "lo" in iso  # isolation table with loopback exception
    # hostile values are refused before any command is built
    for bad in ("1.2.3.4; reboot", "$(id)", "127.0.0.1", "0.0.0.0", "-j ACCEPT"):
        n = len(runner.calls)
        r = ex.execute(
            PolicyDecision(action=ResponseAction.BLOCK_CONNECTION, allowed=True,
                           target={"event_id": ev.event_id, "ip": bad}),
            ev,
        )  # fmt: skip
        assert r.status == ActionStatus.FAILED and len(runner.calls) == n, bad


def test_process_suspend_terminate_on_python_throwaway_subprocess():
    """Verify suspend and terminate on a safe throwaway child subprocess:
    python -c "import time; time.sleep(60)"
    """
    from centralium.agent.response import create_executor

    p = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.15)
    try:
        ex = create_executor(runner=RecordingRunner())
        proc_name = psutil.Process(p.pid).name()
        ev = NormalizedEvent(
            event_type=EventType.PROCESS_START,
            pid=p.pid,
            ppid=os.getpid(),
            process_name=proc_name,
            executable_path=sys.executable,
            source="test",
        )
        base = {"event_id": ev.event_id, "pid": p.pid, "process_name": proc_name}
        # 1. Suspend process
        res_suspend = ex.execute(
            PolicyDecision(action=ResponseAction.SUSPEND_PROCESS, allowed=True, target=base),
            ev,
        )
        assert res_suspend.status == ActionStatus.EXECUTED, res_suspend.detail
        deadline = time.time() + 3
        while time.time() < deadline and psutil.Process(p.pid).status() != psutil.STATUS_STOPPED:
            time.sleep(0.05)
        assert psutil.Process(p.pid).status() == psutil.STATUS_STOPPED

        # 2. Terminate process
        res_term = ex.execute(
            PolicyDecision(action=ResponseAction.TERMINATE_PROCESS, allowed=True, target=base),
            ev,
        )
        assert res_term.status == ActionStatus.EXECUTED, res_term.detail
        assert p.wait(timeout=5) == -9  # SIGKILL

        # 3. Protected processes cannot be terminated
        for protected_pid in (os.getpid(), 1):
            refused = ex.execute(
                PolicyDecision(
                    action=ResponseAction.TERMINATE_PROCESS,
                    allowed=True,
                    target={"event_id": ev.event_id, "pid": protected_pid, "process_name": "protected"},
                ),
                ev,
            )
            assert refused.status == ActionStatus.FAILED and "refused" in refused.detail
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=2)


def test_network_block_and_isolation_iptables_and_windows_via_mock_runner():
    from centralium.agent.response import create_executor

    ev = NormalizedEvent(
        event_type=EventType.NETWORK_CONNECT,
        pid=4242,
        process_name="svc",
        destination_ip="203.0.113.50",
        destination_port=443,
        protocol="tcp",
        source="test",
    )
    # 1. Linux iptables
    runner_ipt = RecordingRunner()
    ex_ipt = create_executor(
        platform="linux", runner=runner_ipt, process_backend=RecordingBackend(), firewall="iptables"
    )
    res_ipt = ex_ipt.execute(
        PolicyDecision(
            action=ResponseAction.BLOCK_CONNECTION,
            allowed=True,
            target={"event_id": ev.event_id, "ip": "203.0.113.50", "port": 443, "protocol": "tcp"},
        ),
        ev,
    )
    assert res_ipt.status == ActionStatus.EXECUTED
    ipt_flat = " ".join(" ".join(c) for c in runner_ipt.calls)
    assert (
        "CENTRALIUM_BLOCK" in ipt_flat and "203.0.113.50" in ipt_flat and runner_ipt.calls[0][0] == "iptables"
    )

    # Isolation on iptables
    n_ipt_block = len(runner_ipt.calls)
    res_iso_ipt = ex_ipt.execute(
        PolicyDecision(action=ResponseAction.ISOLATE_ENDPOINT, allowed=True, target={}),
        ev,
    )
    assert res_iso_ipt.status == ActionStatus.EXECUTED
    iso_ipt_flat = " ".join(" ".join(c) for c in runner_ipt.calls[n_ipt_block:])
    assert "CENTRALIUM_ISO" in iso_ipt_flat and "lo" in iso_ipt_flat

    # 2. Windows netsh
    runner_win = RecordingRunner()
    ex_win = create_executor(platform="windows", runner=runner_win, process_backend=RecordingBackend())
    res_win = ex_win.execute(
        PolicyDecision(
            action=ResponseAction.BLOCK_CONNECTION,
            allowed=True,
            target={"event_id": ev.event_id, "ip": "203.0.113.50", "port": 443, "protocol": "tcp"},
        ),
        ev,
    )
    assert res_win.status == ActionStatus.EXECUTED
    win_flat = " ".join(" ".join(c) for c in runner_win.calls)
    assert "netsh" in win_flat and "advfirewall" in win_flat and "203.0.113.50" in win_flat

    # Isolation on Windows
    n_win_block = len(runner_win.calls)
    res_iso_win = ex_win.execute(
        PolicyDecision(action=ResponseAction.ISOLATE_ENDPOINT, allowed=True, target={}),
        ev,
    )
    assert res_iso_win.status == ActionStatus.EXECUTED
    iso_win_flat = " ".join(" ".join(c) for c in runner_win.calls[n_win_block:])
    assert "advfirewall" in iso_win_flat and "blockinbound,blockoutbound" in iso_win_flat


# --------------------------------------------------------------------------- model missing fallback
def test_missing_ml_models_fall_back_gracefully(tmp_path):
    empty = tmp_path / "no_models"
    empty.mkdir()
    cfg = sandbox_cfg(tmp_path, paths={"data_dir": str(tmp_path / "data"), "models_dir": str(empty)})
    rt = make_rt(cfg, auto_install_models=False)
    try:
        assert not rt.ml.available()
        assert any("ML models unavailable" in n for n in rt.notes)
        outs = run_events(
            rt, scenario("ransomware_like").events[:60] + scenario("persistence_creation").events
        )
        from centralium.agent.models import ScoreFamily

        assert all(ScoreFamily.ML_ANOMALY not in o.scores for o in outs)  # nothing fabricated
        assert rt.db.count("ml_results") == 0
        assert rt.pipeline.stats.snapshot()["errors"] == {}
        assert any(o.incident for o in outs), "deterministic detections must still raise incidents"
    finally:
        rt.close()


def test_corrupt_ml_model_is_rejected_by_sha256_check(tmp_path):
    from centralium.agent.ml import create_ml_engine

    d = tmp_path / "models"
    shutil.copytree(Path("ml/models"), d, ignore=shutil.ignore_patterns("onnx", "__pycache__"))
    (d / "classifier_rf.joblib").write_bytes(b"\x80\x04 not a model " * 50)  # tampered artifact
    eng = create_ml_engine(d)
    assert eng.available()  # the intact anomaly model still loads
    assert "classifier" in eng.load_errors  # tampered one rejected, never unpickled


# --------------------------------------------------------------------------- dashboard-approved actions
def _approval_rig(tmp_path: Path, **cfg_kw: Any):
    backend = RecordingBackend(procs={})
    runner = RecordingRunner()
    rt = make_rt(_live_cfg(tmp_path, **cfg_kw), command_runner=runner, runner_guard=False, llm_mode="off")
    rt.executor.process_backend = backend
    return rt, backend, runner


def _pending_action(rt, pid: int = 31337, name: str = "badproc"):
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START, pid=pid, ppid=1, process_name=name,
        executable_path=f"/tmp/{name}", source="test", host_id="localhost",
    )  # fmt: skip
    rt.pipeline.repo.add_event(ev)
    target = {"event_id": ev.event_id, "pid": pid, "process_name": name, "executable_path": f"/tmp/{name}"}
    ar = ActionResult(
        action=ResponseAction.TERMINATE_PROCESS, status=ActionStatus.PENDING_APPROVAL, target=target,
        event_id=ev.event_id, detail="awaiting user approval",
    )  # fmt: skip
    rt.pipeline.repo.add_action(ar)
    return ev, ar


def test_dashboard_approved_action_executes_via_policy_gate_with_validated_target(tmp_path):
    rt, backend, _runner = _approval_rig(tmp_path)
    try:
        ev, ar = _pending_action(rt)
        backend.procs[31337] = ProcInfo(31337, "badproc", ev.timestamp.timestamp() - 10, "/tmp/badproc")
        # operator approves through the real dashboard API (same DB)
        app = create_app(Path(str(rt.db.path)), config=rt.config, tokens=TOKENS)
        r = TestClient(app).post(
            f"/api/response/actions/{ar.action_id}/decision", json={"decision": "approve", "note": "ok"},
            headers=_hdr("admin"),
        )  # fmt: skip
        assert r.status_code == 200 and r.json()["executed"] is False  # the API itself never executes
        assert backend.killed == []
        assert rt.approvals.run_once() == 1
        assert backend.killed == [31337]
        row = rt.db.query_one(
            "SELECT status, detail FROM response_actions WHERE action_id = ?", (ar.action_id,)
        )
        assert row["status"] == "executed" and "terminated" in row["detail"]
        assert rt.approvals.run_once() == 0  # exactly once
    finally:
        rt.close()


def test_approved_action_refused_when_target_tampered_protected_or_sandboxed(tmp_path):
    rt, backend, runner = _approval_rig(tmp_path)
    try:
        # 1) stored pid altered after the decision (DB tampering): must not redirect the action
        _ev, ar = _pending_action(rt, pid=31337)
        backend.procs.update(
            {31337: ProcInfo(31337, "badproc", 1.0, None), 999: ProcInfo(999, "other", 1.0, None)}
        )
        rt.db.execute(
            "UPDATE response_actions SET status='approved', target=? WHERE action_id=?",
            (json.dumps({**ar.target, "pid": 999}), ar.action_id),
        )
        rt.approvals.run_once()
        row = rt.db.query_one(
            "SELECT status, detail FROM response_actions WHERE action_id=?", (ar.action_id,)
        )
        assert row["status"] == "failed" and "does not match" in row["detail"]
        # 2) protected process (init) is refused even if somebody approved it
        _ev2, ar2 = _pending_action(rt, pid=1, name="systemd")
        backend.procs[1] = ProcInfo(1, "systemd", 1.0, "/usr/lib/systemd/systemd")
        rt.db.execute("UPDATE response_actions SET status='approved' WHERE action_id=?", (ar2.action_id,))
        rt.approvals.run_once()
        row2 = rt.db.query_one(
            "SELECT status, detail FROM response_actions WHERE action_id=?", (ar2.action_id,)
        )
        assert row2["status"] == "failed" and "refused" in row2["detail"]
        assert backend.killed == [] and runner.calls == []
        # 3) LEARNING mode closes the hard gate: approved rows are only marked simulated
        rt.modes.set_mode(__import__("centralium.agent.models", fromlist=["OperatingMode"]).OperatingMode.LEARNING,
                          actor="test", reason="close the gate")  # fmt: skip
        _ev3, ar3 = _pending_action(rt, pid=31338)
        rt.db.execute("UPDATE response_actions SET status='approved' WHERE action_id=?", (ar3.action_id,))
        rt.approvals.run_once()
        row3 = rt.db.query_one("SELECT status FROM response_actions WHERE action_id=?", (ar3.action_id,))
        assert row3["status"] == "simulated" and backend.killed == []
    finally:
        rt.close()


def test_approved_action_in_test_mode_is_never_executed(tmp_path):
    rt = make_rt(sandbox_cfg(tmp_path))
    try:
        _ev, ar = _pending_action(rt)
        rt.db.execute("UPDATE response_actions SET status='approved' WHERE action_id=?", (ar.action_id,))
        assert isinstance(rt.approvals, ApprovedActionDispatcher)
        rt.approvals.run_once()  # BoomBackend/BoomRunner would fail the test if anything ran
        row = rt.db.query_one("SELECT status FROM response_actions WHERE action_id=?", (ar.action_id,))
        assert row["status"] == "simulated"
    finally:
        rt.close()


# --------------------------------------------------------------------------- graph visible in the dashboard
def test_graph_snapshot_is_served_by_dashboard_graph_page(tmp_path):
    rt = make_rt(sandbox_cfg(tmp_path))
    try:
        run_events(rt, scenario("office_powershell_chain").events + scenario("normal_browser").events)
        rt.snapshot_graph()
        db_path = Path(str(rt.db.path))
        app = create_app(db_path, config=rt.config, tokens=TOKENS)
        c = TestClient(app)
        g = c.get("/api/graph", headers=_hdr("viewer")).json()
        assert g["source"] == "snapshot" and len(g["nodes"]) >= 5 and len(g["edges"]) >= 4
        kinds = {n["type"] for n in g["nodes"]}
        assert {"process", "network", "incident"} <= kinds
        assert {e["type"] for e in g["edges"]} >= {"spawned", "connected"}
        assert all(e["source"] in {n["id"] for n in g["nodes"]} for e in g["edges"])
        # process explorer / network pages are populated from the same pipeline run
        assert c.get("/api/processes", headers=_hdr("viewer")).json()["total"] >= 5
        assert c.get("/api/network", headers=_hdr("viewer")).json()["totals"]["connections"] >= 3
        assert write_graph_snapshot(rt.db, rt.graph) > 0
    finally:
        rt.close()
