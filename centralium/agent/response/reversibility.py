"""Rollback and reversibility engine for Centralium response actions.

Guarantees:
- Every response action records a structured undo entry:
  * SUSPEND_PROCESS -> Resumes process via SIGCONT (or psutil resume);
  * BLOCK_CONNECTION -> Removes firewall block rules;
  * QUARANTINE_FILE -> Restores quarantined file back to original location;
  * ISOLATE_ENDPOINT -> Releases firewall isolation rules;
  * SNAPSHOT_PROTECT -> Restores snapshot contents;
  * TERMINATE_PROCESS -> Explicitly documented as non-reversible once killed.
- Timed auto-release dead-man switch for isolation (default 300 seconds):
  Prevents an isolated endpoint from being permanently stranded if the agent crashes,
  restarts, or loses network connectivity.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.interfaces import QuarantineManager
from centralium.agent.models import ActionResult, ActionStatus, ResponseAction
from centralium.agent.response.base import BaseResponseExecutor

log = logging.getLogger("centralium.response.reversibility")

DEFAULT_DEAD_MAN_TIMEOUT_SEC = 300.0


class UndoStatus(StrEnum):
    PENDING = "PENDING"
    REVERSED = "REVERSED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    NON_REVERSIBLE = "NON_REVERSIBLE"


class UndoAction(BaseModel):
    """Reversible undo record corresponding to an executed response action."""

    model_config = ConfigDict(extra="forbid")

    undo_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ResponseAction
    target: dict[str, Any]
    undo_operation: str
    is_reversible: bool = True
    status: UndoStatus = UndoStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    executed_at: datetime | None = None
    details: str = ""
    undo_metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- dead-man switch
class IsolationDeadManSwitch:
    """Timed auto-release dead-man switch for host network isolation.

    Ensures that if the agent loses connectivity, crashes, or is terminated while the host
    is isolated, the endpoint is automatically released after `timeout_seconds` (default 300s).
    """

    def __init__(
        self,
        default_timeout: float = DEFAULT_DEAD_MAN_TIMEOUT_SEC,
        state_file: Path | None = None,
        release_callback: Callable[[], Any] | None = None,
    ) -> None:
        self.default_timeout = default_timeout
        self.state_file = state_file or (Path.home() / ".centralium" / "isolation_deadman.json")
        self.release_callback = release_callback
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._armed: bool = False
        self._expires_at: float = 0.0

    @property
    def is_armed(self) -> bool:
        with self._lock:
            return self._armed and (time.time() < self._expires_at)

    def time_remaining(self) -> float:
        with self._lock:
            if not self._armed:
                return 0.0
            return max(0.0, self._expires_at - time.time())

    def arm(
        self,
        timeout: float | None = None,
        release_callback: Callable[[], Any] | None = None,
    ) -> float:
        """Arm the dead-man switch with a countdown in seconds."""
        t_sec = timeout if timeout is not None else self.default_timeout
        if release_callback is not None:
            self.release_callback = release_callback

        with self._lock:
            if self._timer is not None:
                self._timer.cancel()

            self._armed = True
            self._expires_at = time.time() + t_sec
            self._persist_state()

            # Schedule timer callback
            self._timer = threading.Timer(t_sec, self._on_timeout)
            self._timer.daemon = True
            self._timer.start()

            log.warning(
                "Isolation dead-man switch ARMED for %.1f seconds (expires at %.1f)",
                t_sec,
                self._expires_at,
            )
            return self._expires_at

    def heartbeat(self, extend_seconds: float | None = None) -> float:
        """Extend the dead-man switch timeout while agent remains healthy."""
        with self._lock:
            if not self._armed:
                log.warning("Heartbeat received for disarmed dead-man switch; ignoring.")
                return 0.0

            extend = extend_seconds if extend_seconds is not None else self.default_timeout
            if self._timer is not None:
                self._timer.cancel()

            self._expires_at = time.time() + extend
            self._persist_state()

            self._timer = threading.Timer(extend, self._on_timeout)
            self._timer.daemon = True
            self._timer.start()

            log.info("Isolation dead-man switch extended by %.1f seconds", extend)
            return self._expires_at

    def disarm(self) -> None:
        """Disarm the dead-man switch upon explicit isolation release."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self._armed = False
            self._expires_at = 0.0
            self._clear_state()
            log.info("Isolation dead-man switch DISARMED.")

    def check_and_recover(self) -> bool:
        """Check persistent state on startup or recovery; release if stale."""
        with self._lock:
            if not self.state_file.exists():
                return False
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                armed = data.get("armed", False)
                expires_at = float(data.get("expires_at", 0.0))
                now = time.time()
                if armed:
                    if now >= expires_at:
                        log.warning(
                            "Found expired isolation dead-man state on disk; executing recovery release"
                        )
                        self._clear_state()
                        if self.release_callback:
                            self.release_callback()
                        return True
                    else:
                        remaining = expires_at - now
                        log.warning(
                            "Found active isolation dead-man state with %.1fs remaining; resuming timer",
                            remaining,
                        )
                        self._armed = True
                        self._expires_at = expires_at
                        self._timer = threading.Timer(remaining, self._on_timeout)
                        self._timer.daemon = True
                        self._timer.start()
                        return True
            except Exception:
                log.exception("Error checking persistent dead-man switch state")
        return False

    def _on_timeout(self) -> None:
        """Triggered automatically when the timeout expires."""
        log.warning("ISOLATION DEAD-MAN SWITCH FIRED! Automatically releasing host isolation.")
        with self._lock:
            self._armed = False
            self._timer = None
            self._clear_state()

        if self.release_callback:
            try:
                self.release_callback()
            except Exception:
                log.exception("Failed to trigger release callback in dead-man switch")

    def _persist_state(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "armed": self._armed,
                "expires_at": self._expires_at,
                "timestamp": time.time(),
            }
            self.state_file.write_text(json.dumps(payload), encoding="utf-8")
        except Exception:
            log.exception("Failed to write dead-man state file")

    def _clear_state(self) -> None:
        try:
            if self.state_file.exists():
                self.state_file.unlink(missing_ok=True)
        except Exception as exc:
            log.debug("Error clearing state file %s: %s", self.state_file, exc)


# --------------------------------------------------------------------------- reversibility journal
class ReversibilityJournal:
    """Manages undo actions, rollbacks, and isolation safety."""

    def __init__(
        self,
        dead_man_switch: IsolationDeadManSwitch | None = None,
        dead_man_timeout: float = DEFAULT_DEAD_MAN_TIMEOUT_SEC,
    ) -> None:
        self.dead_man_switch = dead_man_switch or IsolationDeadManSwitch(default_timeout=dead_man_timeout)
        self._journal: dict[str, UndoAction] = {}
        self._lock = threading.Lock()

    def record(
        self,
        action: ResponseAction,
        target: dict[str, Any],
        *,
        executor: BaseResponseExecutor | None = None,
        result_detail: str = "",
        quarantine_id: str | None = None,
        snapshot_id: str | None = None,
    ) -> UndoAction:
        """Create and store an undo record for an executed response action."""
        with self._lock:
            undo_id = str(uuid.uuid4())
            undo_op = "NONE"
            is_rev = True
            details = result_detail
            meta: dict[str, Any] = {}

            if action == ResponseAction.SUSPEND_PROCESS:
                undo_op = "RESUME_PROCESS"
                pid = target.get("pid")
                meta["pid"] = pid
                details = f"Resume suspended process PID {pid} via SIGCONT / resume"

            elif action == ResponseAction.TERMINATE_PROCESS:
                undo_op = "TERMINATE_IRREVERSIBLE"
                is_rev = False
                details = "Process killed; cannot resurrect terminated process memory state"

            elif action == ResponseAction.BLOCK_CONNECTION:
                undo_op = "RELEASE_BLOCKS"
                meta["ip"] = target.get("ip")
                meta["port"] = target.get("port")
                meta["protocol"] = target.get("protocol")
                details = f"Remove firewall block rules for {meta['ip']}"

            elif action == ResponseAction.ISOLATE_ENDPOINT:
                undo_op = "RELEASE_ISOLATION"
                details = "Release host isolation firewall rule set"
                if executor is not None:
                    self.dead_man_switch.arm(
                        release_callback=lambda: executor.release_isolation(simulate=False)
                    )
                else:
                    self.dead_man_switch.arm()
                meta["dead_man_timeout"] = self.dead_man_switch.default_timeout

            elif action == ResponseAction.QUARANTINE_FILE:
                undo_op = "RESTORE_QUARANTINED_FILE"
                qid = quarantine_id
                if not qid and "quarantined as " in result_detail:
                    parts = result_detail.split("quarantined as ")[1].split()
                    if parts:
                        qid = parts[0]
                meta["quarantine_id"] = qid
                meta["original_path"] = target.get("path")
                details = f"Restore quarantined file {target.get('path')} (id={qid})"

            elif action == ResponseAction.SNAPSHOT_PROTECT:
                undo_op = "ROLLBACK_SNAPSHOT"
                meta["snapshot_id"] = snapshot_id
                details = f"Rollback protective snapshot {snapshot_id}"

            elif action == ResponseAction.ALERT:
                undo_op = "NONE"
                is_rev = True
                details = "Alert notification (non-destructive)"

            status = UndoStatus.PENDING if is_rev else UndoStatus.NON_REVERSIBLE

            undo = UndoAction(
                undo_id=undo_id,
                action_type=action,
                target=dict(target),
                undo_operation=undo_op,
                is_reversible=is_rev,
                status=status,
                details=details,
                undo_metadata=meta,
            )
            self._journal[undo_id] = undo
            log.info("Recorded undo action %s for %s (%s)", undo_id, action.value, undo_op)
            return undo

    def rollback(
        self,
        undo_id: str,
        *,
        executor: BaseResponseExecutor | None = None,
        quarantine_mgr: QuarantineManager | None = None,
    ) -> ActionResult:
        """Execute rollback for a recorded undo action."""
        with self._lock:
            undo = self._journal.get(undo_id)
            if undo is None:
                raise KeyError(f"Undo action {undo_id} not found in journal")

            if not undo.is_reversible:
                undo.status = UndoStatus.NON_REVERSIBLE
                return ActionResult(
                    action=undo.action_type,
                    status=ActionStatus.FAILED,
                    target=undo.target,
                    detail=f"Action {undo.action_type.value} is marked non-reversible",
                )

            if undo.status == UndoStatus.REVERSED:
                return ActionResult(
                    action=undo.action_type,
                    status=ActionStatus.EXECUTED,
                    target=undo.target,
                    detail=f"Undo action {undo_id} already executed previously",
                )

        try:
            detail = self._execute_rollback(undo, executor=executor, quarantine_mgr=quarantine_mgr)
            with self._lock:
                undo.status = UndoStatus.REVERSED
                undo.executed_at = datetime.now(UTC)
                undo.details = detail
            return ActionResult(
                action=undo.action_type,
                status=ActionStatus.EXECUTED,
                target=undo.target,
                detail=detail,
            )
        except Exception as exc:
            with self._lock:
                undo.status = UndoStatus.FAILED
                undo.details = f"Rollback failed: {exc}"
            log.exception("Rollback failed for %s", undo_id)
            return ActionResult(
                action=undo.action_type,
                status=ActionStatus.FAILED,
                target=undo.target,
                detail=str(exc),
            )

    def _execute_rollback(
        self,
        undo: UndoAction,
        executor: BaseResponseExecutor | None,
        quarantine_mgr: QuarantineManager | None,
    ) -> str:
        op = undo.undo_operation

        if op == "RESUME_PROCESS":
            pid = undo.undo_metadata.get("pid") or undo.target.get("pid")
            if not pid or not isinstance(pid, int):
                raise ValueError("Missing PID for RESUME_PROCESS")
            return self._resume_process(pid)

        elif op == "RELEASE_BLOCKS":
            if executor is None:
                raise ValueError("ResponseExecutor required to release firewall blocks")
            res = executor.release_blocks(simulate=False)
            return f"Rollback firewall blocks: {res}"

        elif op == "RELEASE_ISOLATION":
            self.dead_man_switch.disarm()
            if executor is None:
                raise ValueError("ResponseExecutor required to release host isolation")
            res = executor.release_isolation(simulate=False)
            return f"Rollback isolation: {res}"

        elif op == "RESTORE_QUARANTINED_FILE":
            qid = undo.undo_metadata.get("quarantine_id")
            if not qid:
                raise ValueError("Missing quarantine_id for RESTORE_QUARANTINED_FILE")
            if quarantine_mgr is None:
                raise ValueError("QuarantineManager required to restore quarantined file")
            restored_path = quarantine_mgr.restore(
                qid,
                authorized_by="reversibility_engine",
                reason="Operator rollback of quarantine action",
            )
            return f"Restored quarantined file to {restored_path}"

        elif op == "ROLLBACK_SNAPSHOT":
            from centralium.agent.response.snapshot import SnapshotManager

            sid = undo.undo_metadata.get("snapshot_id")
            if not sid:
                raise ValueError("Missing snapshot_id for ROLLBACK_SNAPSHOT")
            mgr = SnapshotManager()
            cnt = mgr.rollback_snapshot(sid)
            return f"Restored {cnt} file(s) from snapshot {sid}"

        elif op == "NONE":
            return "No operation required for alert rollback"

        raise ValueError(f"Unknown undo operation: {op}")

    def _resume_process(self, pid: int) -> str:
        """Resume process execution via SIGCONT (POSIX) or psutil (Windows)."""
        if os.name == "posix":
            try:
                os.kill(pid, signal.SIGCONT)
                return f"Sent SIGCONT to process {pid}"
            except ProcessLookupError:
                return f"Process {pid} no longer exists"
        else:
            import psutil

            try:
                p = psutil.Process(pid)
                p.resume()
                return f"Resumed process {pid} via psutil"
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                return f"Process {pid} no longer exists"

    def rollback_all(
        self,
        *,
        executor: BaseResponseExecutor | None = None,
        quarantine_mgr: QuarantineManager | None = None,
    ) -> list[ActionResult]:
        """Rollback all pending reversible actions in reverse order of creation."""
        with self._lock:
            pending = [
                u for u in self._journal.values() if u.is_reversible and u.status == UndoStatus.PENDING
            ]
        pending.sort(key=lambda u: u.created_at, reverse=True)

        results = []
        for u in pending:
            res = self.rollback(u.undo_id, executor=executor, quarantine_mgr=quarantine_mgr)
            results.append(res)
        return results

    def list_actions(self, status: UndoStatus | None = None) -> list[UndoAction]:
        with self._lock:
            actions = list(self._journal.values())
        if status is not None:
            actions = [a for a in actions if a.status == status]
        return sorted(actions, key=lambda a: a.created_at, reverse=True)

    def get_action(self, undo_id: str) -> UndoAction | None:
        with self._lock:
            return self._journal.get(undo_id)


__all__ = [
    "DEFAULT_DEAD_MAN_TIMEOUT_SEC",
    "IsolationDeadManSwitch",
    "ReversibilityJournal",
    "UndoAction",
    "UndoStatus",
]
