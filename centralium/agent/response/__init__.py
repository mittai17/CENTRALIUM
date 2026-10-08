"""Response executors (Linux real, Windows guarded) with runner injection."""

from __future__ import annotations

import sys

from centralium.agent.response.base import (
    BaseResponseExecutor,
    CommandResult,
    CommandRunner,
    IsolationConfig,
    ProcessBackend,
    ProcInfo,
    PsutilProcessBackend,
    SubprocessRunner,
)
from centralium.agent.response.blast_radius import (
    DEFAULT_IMPACT_THRESHOLD,
    BlastRadiusEstimate,
    BlastRadiusEstimator,
    MockSystemInspector,
    PsutilSystemInspector,
    SystemInspector,
)
from centralium.agent.response.linux import LinuxResponseExecutor
from centralium.agent.response.playbooks import (
    Playbook,
    PlaybookExecutionResult,
    PlaybookRegistry,
    PlaybookStep,
    StepExecutionResult,
)
from centralium.agent.response.reversibility import (
    DEFAULT_DEAD_MAN_TIMEOUT_SEC,
    IsolationDeadManSwitch,
    ReversibilityJournal,
    UndoAction,
    UndoStatus,
)
from centralium.agent.response.snapshot import (
    SnapshotConfig,
    SnapshotManager,
    SnapshotRecord,
    execute_snapshot_protect,
)
from centralium.agent.response.windows import WindowsResponseExecutor


def create_executor(platform: str | None = None, **kwargs: object) -> BaseResponseExecutor:
    """Platform executor. In demo/test pass ``simulate=True`` (validates, plans, performs nothing)."""
    plat = (platform or sys.platform).lower()
    if plat.startswith("win"):
        return WindowsResponseExecutor(**kwargs)  # type: ignore[arg-type]
    if plat.startswith("linux"):
        return LinuxResponseExecutor(**kwargs)  # type: ignore[arg-type]
    raise ValueError(f"unsupported platform: {plat} (Linux and Windows only)")


__all__ = [
    "DEFAULT_DEAD_MAN_TIMEOUT_SEC",
    "DEFAULT_IMPACT_THRESHOLD",
    "BaseResponseExecutor",
    "BlastRadiusEstimate",
    "BlastRadiusEstimator",
    "CommandResult",
    "CommandRunner",
    "IsolationConfig",
    "IsolationDeadManSwitch",
    "LinuxResponseExecutor",
    "MockSystemInspector",
    "Playbook",
    "PlaybookExecutionResult",
    "PlaybookRegistry",
    "PlaybookStep",
    "ProcInfo",
    "ProcessBackend",
    "PsutilProcessBackend",
    "PsutilSystemInspector",
    "ReversibilityJournal",
    "SnapshotConfig",
    "SnapshotManager",
    "SnapshotRecord",
    "StepExecutionResult",
    "SubprocessRunner",
    "SystemInspector",
    "UndoAction",
    "UndoStatus",
    "WindowsResponseExecutor",
    "create_executor",
    "execute_snapshot_protect",
]
