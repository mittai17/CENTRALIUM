from __future__ import annotations

from pathlib import Path

from centralium.agent.config import CentraliumConfig, load_config
from centralium.agent.models import OperatingMode
from centralium.agent.runtime import (
    ApprovedActionDispatcher,
    Runtime,
    build_runtime,
    load_persisted_mode,
    set_mode_audited,
)


def test_build_runtime_wires_all_real_modules_in_test_mode(tmp_path: Path):
    cfg = load_config(
        None,
        env={},
        mode="ACTIVE",
        test_mode=True,
        demo_mode=False,
        paths={
            "data_dir": str(tmp_path / "data"),
            "db_path": str(tmp_path / "data" / "agent.db"),
            "graph_dir": str(tmp_path / "data" / "graph"),
            "quarantine_dir": str(tmp_path / "data" / "quarantine"),
        },
    )

    rt = build_runtime(cfg, llm_mode="off", auto_install_models=False, enable_self_protection=False)
    try:
        assert isinstance(rt, Runtime)
        # Executor must get simulate=True in test mode
        assert getattr(rt.executor, "simulate", False) is True

        p = rt.pipeline
        assert p.db is not None and p.db is rt.db
        assert p.normalizer is not None
        assert p.epp is not None
        assert p.yara is not None
        assert p.static is not None
        assert p.threat_intel is not None
        assert p.behavior is not None
        assert p.ml is not None and p.ml is rt.ml
        assert p.graph is not None and p.graph is rt.graph
        assert p.novelty is not None and p.novelty is rt.novelty
        assert p.policy is not None and p.policy is rt.policy
        assert p.risk is not None
        assert p.executor is not None and p.executor is rt.executor
        assert p.modes is not None and p.modes is rt.modes
        assert p.approvals is not None
        assert isinstance(rt.approvals, ApprovedActionDispatcher)

        # Audit log is functional
        assert rt.db.audit.verify().ok
    finally:
        rt.close()


def test_build_runtime_wires_executor_simulate_false_in_live_mode(tmp_path: Path):
    cfg = load_config(
        None,
        env={},
        mode="ACTIVE",
        test_mode=False,
        demo_mode=False,
        paths={
            "data_dir": str(tmp_path / "data"),
            "db_path": str(tmp_path / "data" / "agent.db"),
            "graph_dir": str(tmp_path / "data" / "graph"),
            "quarantine_dir": str(tmp_path / "data" / "quarantine"),
        },
    )

    rt = build_runtime(cfg, llm_mode="off", auto_install_models=False, enable_self_protection=False)
    try:
        # In non-test, non-demo mode: simulate must be False
        assert getattr(rt.executor, "simulate", False) is False
        assert rt.config.demo_mode is False
        assert rt.config.test_mode is False
    finally:
        rt.close()


def test_runtime_persisted_mode_and_audited_set(tmp_path: Path):
    cfg = CentraliumConfig(
        paths={
            "data_dir": str(tmp_path / "data"),
            "db_path": str(tmp_path / "data" / "agent.db"),
            "graph_dir": str(tmp_path / "data" / "graph"),
            "quarantine_dir": str(tmp_path / "data" / "quarantine"),
        }
    )
    rt = build_runtime(cfg, llm_mode="off", auto_install_models=False, enable_self_protection=False)
    try:
        assert load_persisted_mode(rt.db) is None
        new_mode = set_mode_audited(rt, OperatingMode.PASSIVE, actor="admin", reason="operator switch")
        assert new_mode == OperatingMode.PASSIVE
        assert load_persisted_mode(rt.db) == OperatingMode.PASSIVE
    finally:
        rt.close()
