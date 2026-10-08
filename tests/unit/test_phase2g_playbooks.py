"""Unit tests for Phase 2G: Declarative, schema-validated response playbooks."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from centralium.agent.models import (
    EventType,
    NormalizedEvent,
    ResponseAction,
    RiskBand,
)
from centralium.agent.response.base import BaseResponseExecutor, ProcInfo
from centralium.agent.response.blast_radius import BlastRadiusEstimator, MockSystemInspector
from centralium.agent.response.playbooks import (
    Playbook,
    PlaybookRegistry,
    PlaybookStep,
)
from centralium.agent.response.reversibility import ReversibilityJournal


class MockProcBackend:
    def info(self, pid: int) -> ProcInfo | None:
        import time

        return ProcInfo(pid=pid, name="beacon.exe", create_time=time.time())

    def suspend(self, pid: int) -> None:
        pass

    def kill(self, pid: int) -> None:
        pass


class DummyExecutor(BaseResponseExecutor):
    def __init__(self):
        super().__init__(simulate=True, process_backend=MockProcBackend())
        self.executed_actions = []

    def execute(self, decision, event):
        self.executed_actions.append(decision.action)
        return super().execute(decision, event)

    def block_connection(self, ip: str, port: int | None, proto: str | None, simulate: bool) -> str:
        return f"blocked outbound {ip}"

    def isolate_endpoint(self, simulate: bool) -> str:
        return "endpoint isolated"


@pytest.fixture
def playbook_dir() -> Path:
    p = Path("rules/playbooks")
    assert p.is_dir()
    return p


def test_load_all_built_in_playbooks(playbook_dir: Path):
    registry = PlaybookRegistry(directory=playbook_dir)
    assert len(registry._playbooks) >= 5

    # Verify ransomware playbook
    pb = registry.get("pb-ransomware-containment")
    assert pb is not None
    assert pb.name == "Ransomware Rapid Containment and File Protection"
    assert "ransomware" in pb.categories
    assert pb.min_severity == RiskBand.HIGH
    assert len(pb.steps) == 5

    # Verify C2 beacon playbook
    c2_pb = registry.get("pb-c2-beacon-containment")
    assert c2_pb is not None
    assert "c2" in c2_pb.categories
    assert c2_pb.min_severity == RiskBand.MEDIUM


def test_playbook_schema_validation_rejections():
    # 1. Empty steps
    with pytest.raises(ValidationError):
        Playbook(
            id="bad-pb",
            name="Bad",
            categories=["ransomware"],
            steps=[],
        )

    # 2. Invalid target field
    with pytest.raises(ValidationError):
        PlaybookStep(
            id="step-1",
            action=ResponseAction.TERMINATE_PROCESS,
            target_field="arbitrary_unvalidated_field",
        )

    # 3. Invalid action
    with pytest.raises(ValidationError):
        PlaybookStep.model_validate(
            {
                "id": "step-1",
                "action": "RUN_ARBITRARY_BASH_SCRIPT",
                "target_field": "pid",
            }
        )


def test_playbook_selection_by_category_and_severity(playbook_dir: Path):
    registry = PlaybookRegistry(directory=playbook_dir)

    # High severity ransomware match
    matches = registry.select(category="ransomware", severity=RiskBand.HIGH)
    assert len(matches) >= 1
    assert matches[0].id == "pb-ransomware-containment"

    # Low severity query should NOT match HIGH min_severity playbook
    low_matches = registry.select(category="ransomware", severity=RiskBand.LOW)
    assert len(low_matches) == 0

    # C2 matches at MEDIUM
    c2_matches = registry.select(category="c2", severity=RiskBand.MEDIUM)
    assert len(c2_matches) >= 1
    assert c2_matches[0].id == "pb-c2-beacon-containment"


def test_llm_ranking_invariant_preserves_safety(playbook_dir: Path):
    registry = PlaybookRegistry(directory=playbook_dir)
    candidates = registry.select(category="c2", severity=RiskBand.HIGH)
    assert len(candidates) >= 1

    # Scenario 1: LLM proposes reordering of known candidates
    ranked = registry.rank_candidates_with_llm(
        candidates,
        [candidates[0].id],
    )
    assert len(ranked) == len(candidates)
    assert ranked[0].id == candidates[0].id

    # Scenario 2: LLM tries to inject an unauthorized / unknown playbook ID or command
    adversarial_ranks = ["rm -rf /", "malicious-pb", candidates[0].id, "DROP TABLE"]
    safe_ranked = registry.rank_candidates_with_llm(candidates, adversarial_ranks)

    # Unknown/malicious IDs are completely filtered out
    assert len(safe_ranked) == len(candidates)
    assert safe_ranked[0].id == candidates[0].id
    assert not any(p.id in adversarial_ranks[:2] for p in safe_ranked)


def test_playbook_execution_with_blast_radius_and_reversibility(playbook_dir: Path):
    registry = PlaybookRegistry(directory=playbook_dir)
    pb = registry.get("pb-c2-beacon-containment")
    assert pb is not None

    event = NormalizedEvent(
        event_id="test-event-c2",
        event_type=EventType.NETWORK_CONNECT,
        pid=4567,
        process_name="beacon.exe",
        destination_ip="203.0.113.99",
        destination_port=4444,
        protocol="tcp",
    )

    executor = DummyExecutor()
    estimator = BlastRadiusEstimator(inspector=MockSystemInspector(), default_threshold=60.0)
    journal = ReversibilityJournal()

    result = registry.execute_playbook(
        pb,
        event,
        executor,
        estimator=estimator,
        reversibility=journal,
        simulate=True,
    )

    assert result.success is True
    assert len(result.step_results) == 3
    # Step 1: BLOCK_CONNECTION, Step 2: SUSPEND_PROCESS, Step 3: TERMINATE_PROCESS
    assert result.step_results[0].action == ResponseAction.BLOCK_CONNECTION
    assert result.step_results[1].action == ResponseAction.SUSPEND_PROCESS
    assert result.step_results[2].action == ResponseAction.TERMINATE_PROCESS

    # Reversibility recorded undos
    actions = journal.list_actions()
    assert len(actions) >= 2


def test_playbook_execution_halts_on_unapproved_step():
    # Playbook where step requires approval
    pb = Playbook(
        id="pb-require-approval-test",
        name="Approval Test Playbook",
        categories=["test"],
        steps=[
            PlaybookStep(
                id="step-1",
                action=ResponseAction.ISOLATE_ENDPOINT,
                target_field="endpoint",
                require_approval=True,
            )
        ],
    )

    event = NormalizedEvent(
        event_id="test-event-approval",
        event_type=EventType.PROCESS_START,
        pid=123,
    )

    executor = DummyExecutor()
    registry = PlaybookRegistry()

    result = registry.execute_playbook(
        pb,
        event,
        executor,
        simulate=False,  # live execution
    )

    assert result.success is False
    assert result.requires_approval_stopped is True
    assert "requires explicit approval" in result.step_results[0].detail
