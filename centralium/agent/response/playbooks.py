"""Declarative, schema-validated response playbooks stored as data.

Key guarantees:
1. Playbooks are declared as data (YAML or JSON) in ``rules/playbooks/`` and validated against
   a strict Pydantic schema (``Playbook`` and ``PlaybookStep``).
2. Every step uses a schema-validated ``ResponseAction`` (e.g. SUSPEND_PROCESS, TERMINATE_PROCESS,
   BLOCK_CONNECTION, QUARANTINE_FILE, ISOLATE_ENDPOINT, SNAPSHOT_PROTECT, ALERT).
3. Arbitrary shell commands or unsanitized script execution are strictly prohibited.
4. The policy engine selects candidate playbooks deterministically by incident category and severity.
5. The LLM may ONLY rank candidate playbooks; it can NEVER author, modify, or inject playbooks.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from centralium.agent.models import (
    ActionStatus,
    NormalizedEvent,
    OperatingMode,
    PolicyDecision,
    ResponseAction,
    RiskBand,
)
from centralium.agent.response.base import BaseResponseExecutor
from centralium.agent.response.blast_radius import BlastRadiusEstimate, BlastRadiusEstimator
from centralium.agent.response.reversibility import ReversibilityJournal

log = logging.getLogger("centralium.response.playbooks")

_BAND_RANKS = {
    RiskBand.SAFE: 0,
    RiskBand.LOW: 1,
    RiskBand.MEDIUM: 2,
    RiskBand.HIGH: 3,
    RiskBand.CRITICAL: 4,
}


# --------------------------------------------------------------------------- models
class PlaybookStep(BaseModel):
    """A single atomic, schema-validated response step within a playbook."""

    model_config = ConfigDict(extra="forbid")

    id: str
    action: ResponseAction
    target_field: str = Field(
        description="Target field: 'pid', 'destination_ip', 'file_path', 'executable_path', 'endpoint'"
    )
    description: str = ""
    require_approval: bool = False
    continue_on_failure: bool = False

    @field_validator("id")
    @classmethod
    def validate_step_id(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("step id cannot be empty")
        return s

    @field_validator("target_field")
    @classmethod
    def validate_target_field(cls, v: str) -> str:
        valid = {"pid", "destination_ip", "file_path", "executable_path", "endpoint"}
        if v not in valid:
            raise ValueError(f"Invalid target_field {v!r}. Must be one of {valid}")
        return v


class Playbook(BaseModel):
    """Declarative, schema-validated response playbook."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    categories: list[str] = Field(description="Incident categories, e.g. ['ransomware', 'c2', 'persistence']")
    min_severity: RiskBand = Field(default=RiskBand.MEDIUM)
    author: str = "Centralium SecOps"
    version: str = "1.0"
    steps: list[PlaybookStep] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def validate_playbook_id(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("playbook id cannot be empty")
        return s

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, v: list[str]) -> list[str]:
        cleaned = [c.strip().lower() for c in v if c.strip()]
        if not cleaned:
            raise ValueError("playbook must define at least one incident category")
        return cleaned


class StepExecutionResult(BaseModel):
    """Result of executing an individual playbook step."""

    model_config = ConfigDict(extra="forbid")

    step_id: str
    action: ResponseAction
    status: ActionStatus
    detail: str
    blast_radius: BlastRadiusEstimate | None = None
    undo_action_id: str | None = None


class PlaybookExecutionResult(BaseModel):
    """Result of running a response playbook."""

    model_config = ConfigDict(extra="forbid")

    playbook_id: str
    playbook_name: str
    event_id: str
    success: bool
    step_results: list[StepExecutionResult] = Field(default_factory=list)
    requires_approval_stopped: bool = False
    stopped_reason: str = ""


# --------------------------------------------------------------------------- parser
def _parse_scalar(val: str) -> Any:
    v = val.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


def _parse_yaml_or_json(text: str) -> dict[str, Any]:
    """Parse YAML or JSON dictionary."""
    try:
        import yaml  # type: ignore

        res = yaml.safe_load(text)
        if isinstance(res, dict):
            return res
        raise ValueError("Document must be a mapping")
    except ImportError:
        pass

    s = text.strip()
    if s.startswith("{"):
        try:
            res = json.loads(s)
            if isinstance(res, dict):
                return res
        except json.JSONDecodeError:
            pass

    lines: list[tuple[int, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        lines.append((indent, stripped))

    if not lines:
        return {}

    def _parse_block(idx: int) -> tuple[Any, int]:
        if idx >= len(lines):
            return {}, idx
        indent, line = lines[idx]
        if line.startswith("- "):
            lst: list[Any] = []
            while idx < len(lines):
                cur_indent, cur_line = lines[idx]
                if cur_indent < indent:
                    break
                if cur_indent == indent and cur_line.startswith("- "):
                    item = cur_line[2:].strip()
                    if not item:
                        sub, idx = _parse_block(idx + 1)
                        lst.append(sub)
                    elif ":" in item and not item.startswith(('"', "'")):
                        k, v = item.split(":", 1)
                        k, v = k.strip(), v.strip()
                        obj: dict[str, Any] = {}
                        if v:
                            obj[k] = _parse_scalar(v)
                            idx += 1
                        else:
                            sub, idx = _parse_block(idx + 1)
                            obj[k] = sub
                        while idx < len(lines):
                            next_indent, next_line = lines[idx]
                            if next_indent <= cur_indent or next_line.startswith("- "):
                                break
                            if ":" in next_line:
                                nk, nv = next_line.split(":", 1)
                                nk, nv = nk.strip(), nv.strip()
                                if nv:
                                    obj[nk] = _parse_scalar(nv)
                                    idx += 1
                                else:
                                    nsub, idx = _parse_block(idx + 1)
                                    obj[nk] = nsub
                            else:
                                idx += 1
                        lst.append(obj)
                    else:
                        lst.append(_parse_scalar(item))
                        idx += 1
                else:
                    break
            return lst, idx
        else:
            dct: dict[str, Any] = {}
            while idx < len(lines):
                cur_indent, cur_line = lines[idx]
                if cur_indent < indent:
                    break
                if cur_indent == indent:
                    if ":" not in cur_line:
                        idx += 1
                        continue
                    k, v = cur_line.split(":", 1)
                    k, v = k.strip(), v.strip()
                    if not v:
                        sub, idx = _parse_block(idx + 1)
                        dct[k] = sub
                    else:
                        dct[k] = _parse_scalar(v)
                        idx += 1
                elif cur_indent > indent:
                    idx += 1
                else:
                    break
            return dct, idx

    res, _ = _parse_block(0)
    if isinstance(res, dict):
        return res
    raise ValueError("Document is not a valid YAML/JSON mapping")


# --------------------------------------------------------------------------- registry & engine
class PlaybookRegistry:
    """Loads, validates, selects, and ranks response playbooks."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self._playbooks: dict[str, Playbook] = {}
        if directory and directory.is_dir():
            self.load_directory(directory)

    def load_directory(self, dir_path: Path) -> int:
        """Load and validate all .yaml, .yml, or .json playbooks in a directory."""
        count = 0
        for p in dir_path.glob("**/*"):
            if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".json"):
                try:
                    pb = self.load_file(p)
                    self._playbooks[pb.id] = pb
                    count += 1
                except Exception as exc:
                    log.error("Failed to load playbook %s: %s", p, exc)
        log.info("Loaded %d playbooks from %s", count, dir_path)
        return count

    def load_file(self, file_path: Path) -> Playbook:
        """Load and validate a single playbook file."""
        content = file_path.read_text(encoding="utf-8")
        data = _parse_yaml_or_json(content)
        return self.register_dict(data)

    def register_dict(self, data: dict[str, Any]) -> Playbook:
        """Validate and register a playbook from a dictionary."""
        if "min_severity" in data and isinstance(data["min_severity"], str):
            sev_str = data["min_severity"].upper()
            data["min_severity"] = RiskBand(sev_str)

        if "steps" in data and isinstance(data["steps"], list):
            for step in data["steps"]:
                if isinstance(step, dict) and "action" in step and isinstance(step["action"], str):
                    step["action"] = ResponseAction(step["action"].upper())

        pb = Playbook.model_validate(data)
        self._playbooks[pb.id] = pb
        return pb

    def get(self, playbook_id: str) -> Playbook | None:
        return self._playbooks.get(playbook_id)

    def select(
        self,
        category: str | None = None,
        severity: RiskBand | None = None,
        tags: Sequence[str] | None = None,
    ) -> list[Playbook]:
        """Select applicable playbooks deterministically based on category and severity."""
        matches: list[Playbook] = []
        target_cat = category.strip().lower() if category else None
        target_sev_rank = _BAND_RANKS[severity] if severity else 0

        for pb in self._playbooks.values():
            if target_cat and target_cat not in pb.categories:
                continue
            if _BAND_RANKS[pb.min_severity] > target_sev_rank:
                continue
            if tags and not all(t in pb.tags for t in tags):
                continue
            matches.append(pb)

        matches.sort(key=lambda p: (_BAND_RANKS[p.min_severity], p.id), reverse=True)
        return matches

    @staticmethod
    def rank_candidates_with_llm(
        candidates: Sequence[Playbook],
        llm_ranked_ids: Sequence[str],
    ) -> list[Playbook]:
        """Rank candidate playbooks using LLM recommendations.

        Safety invariant:
        - The LLM can only reorder the candidate playbooks supplied.
        - The LLM CANNOT inject new playbooks or arbitrary commands.
        - Any unknown or unauthorized playbook IDs suggested by the LLM are ignored.
        """
        candidate_map = {pb.id: pb for pb in candidates}
        ordered: list[Playbook] = []
        seen = set()

        for rank_id in llm_ranked_ids:
            clean_id = rank_id.strip()
            if clean_id in candidate_map and clean_id not in seen:
                ordered.append(candidate_map[clean_id])
                seen.add(clean_id)

        for pb in candidates:
            if pb.id not in seen:
                ordered.append(pb)

        return ordered

    def execute_playbook(
        self,
        playbook: Playbook,
        event: NormalizedEvent,
        executor: BaseResponseExecutor,
        *,
        estimator: BlastRadiusEstimator | None = None,
        reversibility: ReversibilityJournal | None = None,
        approval_threshold: float = 50.0,
        simulate: bool = False,
    ) -> PlaybookExecutionResult:
        """Execute all steps of a response playbook sequentially."""
        results: list[StepExecutionResult] = []
        est = estimator or BlastRadiusEstimator()

        for step in playbook.steps:
            target = self._build_target(step, event)
            if simulate:
                target["simulate"] = True

            # 1. Estimate blast radius
            blast = est.estimate(step.action, target, threshold=approval_threshold)

            # 2. Check approval requirement
            needs_appr = blast.requires_approval or step.require_approval
            if needs_appr and not simulate and not target.get("approved"):
                appr_reason = blast.approval_reason or "playbook step requires approval"
                results.append(
                    StepExecutionResult(
                        step_id=step.id,
                        action=step.action,
                        status=ActionStatus.FAILED,
                        detail=f"Stopped: requires explicit approval ({appr_reason})",
                        blast_radius=blast,
                    )
                )
                return PlaybookExecutionResult(
                    playbook_id=playbook.id,
                    playbook_name=playbook.name,
                    event_id=event.event_id,
                    success=False,
                    step_results=results,
                    requires_approval_stopped=True,
                    stopped_reason=blast.approval_reason or "Approval required",
                )

            # 3. Execute action
            mode = getattr(executor.settings, "mode", None) or OperatingMode.ACTIVE
            decision = PolicyDecision(
                action=step.action,
                allowed=True,
                requires_approval=False,
                mode=mode,
                reason=f"Playbook {playbook.id} step {step.id}: {step.description}",
                target=target,
            )
            act_res = executor.execute(decision, event)

            # 4. Record undo action if successful
            undo_id = None
            if reversibility is not None and act_res.status in (
                ActionStatus.EXECUTED,
                ActionStatus.SIMULATED,
            ):
                undo = reversibility.record(
                    step.action,
                    target,
                    executor=executor,
                    result_detail=act_res.detail,
                )
                undo_id = undo.undo_id

            results.append(
                StepExecutionResult(
                    step_id=step.id,
                    action=step.action,
                    status=act_res.status,
                    detail=act_res.detail,
                    blast_radius=blast,
                    undo_action_id=undo_id,
                )
            )

            # 5. Handle failure
            if act_res.status == ActionStatus.FAILED and not step.continue_on_failure:
                return PlaybookExecutionResult(
                    playbook_id=playbook.id,
                    playbook_name=playbook.name,
                    event_id=event.event_id,
                    success=False,
                    step_results=results,
                    stopped_reason=f"Step {step.id} failed: {act_res.detail}",
                )

        return PlaybookExecutionResult(
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            event_id=event.event_id,
            success=all(r.status in (ActionStatus.EXECUTED, ActionStatus.SIMULATED) for r in results),
            step_results=results,
        )

    @staticmethod
    def _build_target(step: PlaybookStep, event: NormalizedEvent) -> dict[str, Any]:
        target: dict[str, Any] = {"event_id": event.event_id}
        if step.target_field == "pid":
            target["pid"] = event.pid
            if event.process_name:
                target["process_name"] = event.process_name
            if event.executable_path:
                target["executable_path"] = event.executable_path
        elif step.target_field == "destination_ip":
            target["ip"] = event.destination_ip
            if event.destination_port:
                target["port"] = event.destination_port
            if event.protocol:
                target["protocol"] = event.protocol
        elif step.target_field == "file_path":
            target["path"] = event.file_path or event.executable_path
        elif step.target_field == "executable_path":
            target["path"] = event.executable_path or event.file_path
        elif step.target_field == "endpoint":
            target["endpoint"] = True
        return target


__all__ = [
    "Playbook",
    "PlaybookExecutionResult",
    "PlaybookRegistry",
    "PlaybookStep",
    "StepExecutionResult",
]
