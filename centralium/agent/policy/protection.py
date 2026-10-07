"""Protected-process / protected-path rules (shared by policy and executor)."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from centralium.agent.policy.validation import validate_pid

log = logging.getLogger("centralium.policy")


def _norm_name(name: str | None) -> str:
    n = (name or "").strip().lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return n


def _norm_path(p: str) -> str:
    return os.path.normpath(p.replace("\\", "/")).lower().rstrip("/")


def own_lineage_pids() -> frozenset[int]:
    """This process + all ancestors (so we never kill our supervisor/launcher)."""
    pids = {os.getpid()}
    try:
        import psutil  # type: ignore[import-untyped,unused-ignore]

        p = psutil.Process(os.getpid())
        for parent in p.parents():
            pids.add(parent.pid)
    except Exception:
        log.debug("could not enumerate parent processes", exc_info=True)
        pids.add(os.getppid())
    return frozenset(pids)


@dataclass
class ProtectionRules:
    protected_names: frozenset[str]
    protected_paths: tuple[str, ...]
    protected_pids: frozenset[int] = field(default_factory=frozenset)
    pid_resolver: Callable[[], Iterable[int]] | None = own_lineage_pids

    @classmethod
    def from_lists(
        cls,
        names: Iterable[str],
        paths: Iterable[str],
        *,
        extra_pids: Iterable[int] = (),
        pid_resolver: Callable[[], Iterable[int]] | None = own_lineage_pids,
    ) -> ProtectionRules:
        nm: set[str] = set()
        for n in names:
            low = _norm_name(n)
            nm.add(low)
            nm.add(low[:-4] if low.endswith(".exe") else low + ".exe")
        return cls(
            frozenset(nm),
            tuple(_norm_path(p) for p in paths),
            frozenset(extra_pids),
            pid_resolver,
        )

    def pids(self) -> frozenset[int]:
        resolved = frozenset(self.pid_resolver()) if self.pid_resolver else frozenset()
        return self.protected_pids | resolved

    def process_refusal(self, pid: int | None, name: str | None, exe_path: str | None = None) -> str | None:
        """Return a human reason if the process must not be suspended/terminated, else None."""
        if pid is not None:
            try:
                validate_pid(pid)
            except ValueError:
                return f"invalid pid {pid!r}"
            if pid in (1, 2, 4):  # init, kthreadd, Windows System
                return f"pid {pid} is a core system process"
            if pid in self.pids():
                return f"pid {pid} is Centralium itself or one of its parents"
        n = _norm_name(name)
        if n and n in self.protected_names:
            return f"process '{name}' is on the protected list"
        if exe_path:
            en = _norm_name(exe_path)
            if en in self.protected_names:
                return f"executable '{en}' is on the protected list"
        return None

    def path_refusal(self, path: str) -> str | None:
        p = _norm_path(path)
        for prot in self.protected_paths:
            if prot and (p == prot or p.startswith(prot + "/")):
                return f"path is under protected location {prot}"
        return None
