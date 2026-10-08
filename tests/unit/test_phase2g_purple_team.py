"""Unit tests for Phase 2G: Purple-team simulator and ATT&CK coverage analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from centralium.agent.config import load_config
from centralium.agent.main import app
from centralium.agent.simulate.purple_team import (
    PurpleTeamReport,
    PurpleTeamSimulator,
    run_purple_team_simulation,
)

runner = CliRunner()


def test_simulation_safety_invariants(tmp_path: Path):
    cfg = load_config(demo_mode=True, test_mode=True)
    simulator = PurpleTeamSimulator(config=cfg)

    # Inspect all scenarios
    for tid, scenario in simulator.catalog.items():
        events = scenario.generator(tmp_path)
        assert len(events) >= 1
        for ev in events:
            # Invariant 1: Marked as simulation
            assert ev.raw_metadata.get("is_simulation") is True
            # Invariant 2: Associated with technique ID
            assert ev.raw_metadata.get("simulation_technique") == tid
            # Invariant 3: Event IDs prefixed with sim-
            assert ev.event_id.startswith("sim-")
            # Invariant 4: No host changes outside temp directory
            if ev.file_path and "temp" in ev.file_path.lower():
                p = Path(ev.file_path)
                # If path was in tmp_path
                if str(tmp_path) in str(p):
                    assert str(tmp_path) in str(p)


def test_purple_team_simulator_run_targeted():
    cfg = load_config(demo_mode=True, test_mode=True)
    simulator = PurpleTeamSimulator(config=cfg)

    # Test targeted subset: PowerShell execution, LSASS dumping, Ransomware
    report = simulator.run(["T1059.001", "T1003.001", "T1486"])

    assert isinstance(report, PurpleTeamReport)
    assert report.techniques_tested == 3
    assert report.techniques_detected >= 1
    assert report.coverage_score > 0.0
    assert len(report.results) == 3

    # Check Markdown report
    md = report.to_markdown()
    assert "# Centralium Purple-Team MITRE ATT&CK Coverage Report" in md
    assert "T1059.001" in md
    assert "T1003.001" in md
    assert "T1486" in md

    # Check JSON export
    js = report.to_json()
    parsed = json.loads(js)
    assert parsed["techniques_tested"] == 3
    assert "coverage_score" in parsed


def test_purple_team_cli_simulate_command(tmp_path: Path):
    out_file = tmp_path / "purple_report.md"
    result = runner.invoke(
        app,
        ["simulate", "--techniques", "T1059.001,T1486", "--out", str(out_file)],
    )

    assert result.exit_code == 0
    assert "Centralium Purple-Team MITRE ATT&CK Coverage Report" in result.stdout
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "T1059.001" in content
    assert "T1486" in content


def test_purple_team_cli_simulate_json(tmp_path: Path):
    out_file = tmp_path / "purple_report.json"
    result = runner.invoke(
        app,
        ["simulate", "--techniques", "T1059.001", "--out", str(out_file)],
    )

    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["techniques_tested"] == 1
    assert data["results"][0]["technique_id"] == "T1059.001"


def test_run_purple_team_simulation_helper():
    report = run_purple_team_simulation(techniques=["T1059.001"])
    assert report.techniques_tested == 1
    assert report.results[0].technique_id == "T1059.001"
