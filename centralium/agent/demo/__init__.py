"""Safe synthetic demo/test-mode scenarios and runner (destructive response always disabled)."""

from centralium.agent.demo.runner import (
    DemoReport,
    DemoSafetyError,
    ScenarioResult,
    assert_no_destructive,
    clone_events,
    run_demo,
)
from centralium.agent.demo.scenarios import DemoScenario, build_scenarios, load_replay_scenarios

__all__ = [
    "DemoReport",
    "DemoSafetyError",
    "DemoScenario",
    "ScenarioResult",
    "assert_no_destructive",
    "build_scenarios",
    "clone_events",
    "load_replay_scenarios",
    "run_demo",
]
