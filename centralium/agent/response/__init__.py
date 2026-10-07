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
from centralium.agent.response.linux import LinuxResponseExecutor
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
    "BaseResponseExecutor",
    "CommandResult",
    "CommandRunner",
    "IsolationConfig",
    "LinuxResponseExecutor",
    "ProcInfo",
    "ProcessBackend",
    "PsutilProcessBackend",
    "SubprocessRunner",
    "WindowsResponseExecutor",
    "create_executor",
]
