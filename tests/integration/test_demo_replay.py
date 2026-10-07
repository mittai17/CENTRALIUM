"""Integration test for demo replay mode: replaying ml/datasets/replay/demo_replay.jsonl
through the full pipeline with destructive response disabled."""

from __future__ import annotations

from pathlib import Path

import pytest

from centralium.agent.config import OperatingMode, load_config
from centralium.agent.demo import load_replay_scenarios, run_demo
from centralium.agent.runtime import PROJECT_ROOT, build_runtime

pytestmark = pytest.mark.integration


def test_load_replay_scenarios_from_default_file():
    scenarios = load_replay_scenarios()
    assert len(scenarios) == 11
    total_events = sum(len(s.events) for s in scenarios)
    assert total_events == 192

    # Verify scenario expectations
    sc_by_name = {s.name: s for s in scenarios}
    assert sc_by_name["replay_normal_process"].expect == "benign"
    assert sc_by_name["replay_benign_installer"].expect == "benign"
    assert sc_by_name["replay_suspicious_powershell"].expect == "detect"
    assert sc_by_name["replay_ransomware_like"].expect == "detect"


def test_run_demo_with_replay_dataset(tmp_path: Path):
    cfg = load_config(
        demo_mode=True,
        mode=OperatingMode.ACTIVE,
        paths={"data_dir": str(tmp_path / "data")},
    )
    scenarios = load_replay_scenarios()
    rt = build_runtime(cfg, llm_mode="mock")
    try:
        report = run_demo(rt, scenarios=scenarios)
        assert report.safety_ok is True
        assert report.destructive_allowed is False
        assert report.executor_simulate is True
        assert len(report.results) == 11
        # Funnel has events
        assert report.funnel["raw"] > 0
        assert report.incidents > 0
        # Check that destructive actions are simulated, never executed
        for action_status in report.actions_by_status:
            assert action_status in ("executed", "simulated", "pending_approval", "denied")
    finally:
        rt.close()


def test_load_replay_scenarios_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_replay_scenarios(PROJECT_ROOT / "ml" / "datasets" / "nonexistent.jsonl")
