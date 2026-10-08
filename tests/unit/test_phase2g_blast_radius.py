"""Unit tests for Phase 2G: Blast-radius estimator and structured dry-run diff."""

from __future__ import annotations

import pytest

from centralium.agent.models import ResponseAction
from centralium.agent.response.blast_radius import (
    BlastRadiusEstimate,
    BlastRadiusEstimator,
    MockSystemInspector,
    ProcessBlast,
    SocketBlast,
)


@pytest.fixture
def mock_inspector() -> MockSystemInspector:
    proc_root = ProcessBlast(pid=1000, name="worker_proc", cmdline=["worker", "--job", "1"], is_root=True)
    child1 = ProcessBlast(pid=1001, name="child_worker", cmdline=["child", "1"], parent_pid=1000)
    child2 = ProcessBlast(pid=1002, name="child_worker", cmdline=["child", "2"], parent_pid=1000)

    sockets = {
        1000: [
            SocketBlast(
                local="127.0.0.1:8080", remote="10.0.0.5:5432", protocol="tcp", state="ESTABLISHED", pid=1000
            ),
            SocketBlast(local="0.0.0.0:8080", remote="", protocol="tcp", state="LISTEN", pid=1000),
        ],
        1001: [
            SocketBlast(
                local="127.0.0.1:42100", remote="10.0.0.6:6379", protocol="tcp", state="ESTABLISHED", pid=1001
            ),
        ],
    }

    files = {
        1000: ["/var/log/app.log", "/var/data/state.db"],
    }

    services = {
        1000: ["worker.service"],
    }

    connections = [
        SocketBlast(
            local="192.168.1.10:44120",
            remote="198.51.100.22:4444",
            protocol="tcp",
            state="ESTABLISHED",
            pid=500,
        ),
        SocketBlast(
            local="192.168.1.10:44122",
            remote="198.51.100.22:4444",
            protocol="tcp",
            state="ESTABLISHED",
            pid=501,
        ),
    ]

    return MockSystemInspector(
        processes={1000: (proc_root, [child1, child2])},
        sockets=sockets,
        files=files,
        services=services,
        connections=connections,
        system_socket_count=42,
        open_file_pids={"/etc/shadow": [200, 201]},
    )


def test_blast_radius_process_termination(mock_inspector: MockSystemInspector):
    estimator = BlastRadiusEstimator(inspector=mock_inspector, default_threshold=50.0)

    target = {"pid": 1000, "process_name": "worker_proc"}
    est = estimator.estimate(ResponseAction.TERMINATE_PROCESS, target)

    assert isinstance(est, BlastRadiusEstimate)
    assert est.action == ResponseAction.TERMINATE_PROCESS
    assert len(est.processes_affected) == 3  # root + 2 children
    assert est.process_tree_children == [1001, 1002]
    assert est.open_socket_count == 3
    assert est.dependent_system_services == ["worker.service"]
    assert "/var/log/app.log" in est.affected_files

    # Impact score includes: base (35) + children (20) + sockets (15) + files (4) + service (25) = 99
    assert est.impact_score >= 80.0
    assert est.risk_level == "CRITICAL"
    assert est.requires_approval is True
    assert "exceeds threshold" in est.approval_reason or ">=" in est.approval_reason
    assert "worker.service" in est.approval_reason

    # Verify structured dry-run diff
    diff = est.to_diff()
    assert "--- DRY-RUN DIFF: TERMINATE_PROCESS ---" in diff
    assert "PID 1000" in diff
    assert "Process Tree Children (2): PIDs [1001, 1002]" in diff
    assert "Disrupted Sockets (3)" in diff
    assert "worker.service" in diff


def test_blast_radius_process_suspend_below_threshold(mock_inspector: MockSystemInspector):
    # Process with no children, no sockets, no services
    inspector = MockSystemInspector(
        processes={2000: (ProcessBlast(pid=2000, name="benign", is_root=True), [])},
    )
    estimator = BlastRadiusEstimator(inspector=inspector, default_threshold=50.0)

    est = estimator.estimate(ResponseAction.SUSPEND_PROCESS, {"pid": 2000})
    assert est.action == ResponseAction.SUSPEND_PROCESS
    assert est.impact_score == 25.0
    assert est.requires_approval is False
    assert est.risk_level == "LOW"


def test_blast_radius_block_connection(mock_inspector: MockSystemInspector):
    estimator = BlastRadiusEstimator(inspector=mock_inspector, default_threshold=40.0)

    target = {"ip": "198.51.100.22", "port": 4444, "protocol": "tcp"}
    est = estimator.estimate(ResponseAction.BLOCK_CONNECTION, target)

    assert est.action == ResponseAction.BLOCK_CONNECTION
    assert est.open_socket_count == 2
    # 20 base + 2*15 (connections) = 50.0 >= 40.0 threshold
    assert est.impact_score == 50.0
    assert est.requires_approval is True
    assert "blocks 198.51.100.22:4444" in est.approval_reason


def test_blast_radius_quarantine_file_system_file(mock_inspector: MockSystemInspector):
    estimator = BlastRadiusEstimator(inspector=mock_inspector, default_threshold=50.0)

    target = {"path": "/etc/shadow"}
    est = estimator.estimate(ResponseAction.QUARANTINE_FILE, target)

    assert est.action == ResponseAction.QUARANTINE_FILE
    assert est.requires_approval is True
    assert est.impact_score >= 80.0
    assert "/etc/shadow" in est.affected_files
    assert "system executable/library location" in est.approval_reason


def test_blast_radius_isolate_endpoint(mock_inspector: MockSystemInspector):
    estimator = BlastRadiusEstimator(inspector=mock_inspector, default_threshold=50.0)

    target = {"endpoint": True}
    est = estimator.estimate(ResponseAction.ISOLATE_ENDPOINT, target)

    assert est.action == ResponseAction.ISOLATE_ENDPOINT
    assert est.impact_score >= 85.0
    assert est.risk_level == "CRITICAL"
    assert est.requires_approval is True
    assert "endpoint isolation severs network connectivity" in est.approval_reason


def test_blast_radius_alert_zero_impact():
    estimator = BlastRadiusEstimator(default_threshold=50.0)
    est = estimator.estimate(ResponseAction.ALERT, {"event_id": "test"})

    assert est.impact_score == 0.0
    assert est.requires_approval is False
    assert est.risk_level == "LOW"
    assert "zero host blast radius" in est.diff_summary
