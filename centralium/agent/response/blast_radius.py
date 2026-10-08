"""Blast-radius estimator and structured dry-run diff for response actions.

Evaluates the potential impact of any destructive or containment action before execution:
- Processes affected and their full process tree children;
- Open socket count and active network connections disrupted;
- Dependent system services (systemd units / Windows services);
- Files locked, quarantined, or modified.

Generates a structured dry-run diff (``BlastRadiusEstimate``) and flags whether the action
requires explicit operator approval based on a configurable impact threshold.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import ResponseAction

log = logging.getLogger("centralium.response.blast_radius")

DEFAULT_IMPACT_THRESHOLD = 50.0


# --------------------------------------------------------------------------- models
class ProcessBlast(BaseModel):
    """Information on an affected process in the blast radius."""

    model_config = ConfigDict(extra="forbid")

    pid: int
    name: str = ""
    cmdline: list[str] = Field(default_factory=list)
    parent_pid: int | None = None
    is_root: bool = False


class SocketBlast(BaseModel):
    """Network connection or listening socket affected by an action."""

    model_config = ConfigDict(extra="forbid")

    local: str = ""
    remote: str = ""
    protocol: str = "tcp"
    state: str = ""
    pid: int | None = None


class BlastRadiusEstimate(BaseModel):
    """Structured dry-run diff and blast radius calculation for a proposed action."""

    model_config = ConfigDict(extra="forbid")

    action: ResponseAction
    target: dict[str, Any]
    impact_score: float = Field(ge=0.0, le=100.0)
    threshold: float = Field(default=DEFAULT_IMPACT_THRESHOLD, ge=0.0, le=100.0)
    requires_approval: bool
    approval_reason: str = ""
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL

    processes_affected: list[ProcessBlast] = Field(default_factory=list)
    process_tree_children: list[int] = Field(default_factory=list)
    open_socket_count: int = 0
    open_sockets: list[SocketBlast] = Field(default_factory=list)
    dependent_system_services: list[str] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    diff_summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_diff(self) -> str:
        """Render a human-readable structured dry-run diff."""
        appr_str = f"YES ({self.approval_reason})" if self.requires_approval else "NO"
        lines = [
            f"--- DRY-RUN DIFF: {self.action.value} ---",
            (
                f"[!] Impact Score: {self.impact_score:.1f} / 100.0 "
                f"(Threshold: {self.threshold:.1f}) | Risk Level: {self.risk_level}"
            ),
            f"[!] Approval Required: {appr_str}",
        ]

        if self.processes_affected:
            root_proc = next((p for p in self.processes_affected if p.is_root), self.processes_affected[0])
            lines.append(f"[-] Target Process: PID {root_proc.pid} ({root_proc.name or 'unknown'})")
            if self.process_tree_children:
                child_pids_str = ", ".join(str(p) for p in self.process_tree_children)
                cnt = len(self.process_tree_children)
                lines.append(f"[-] Process Tree Children ({cnt}): PIDs [{child_pids_str}]")

        if self.open_sockets:
            lines.append(f"[-] Disrupted Sockets ({len(self.open_sockets)}):")
            for sock in self.open_sockets[:10]:
                rem = f" -> {sock.remote}" if sock.remote else ""
                lines.append(f"    * {sock.local}{rem} ({sock.protocol.upper()} {sock.state})")
            if len(self.open_sockets) > 10:
                lines.append(f"    * ... and {len(self.open_sockets) - 10} more socket(s)")

        if self.dependent_system_services:
            svc_str = ", ".join(self.dependent_system_services)
            cnt = len(self.dependent_system_services)
            lines.append(f"[!] Dependent System Services Affected ({cnt}): {svc_str}")

        if self.affected_files:
            lines.append(f"[-] Affected Files ({len(self.affected_files)}):")
            for fpath in self.affected_files[:8]:
                lines.append(f"    * {fpath}")
            if len(self.affected_files) > 8:
                lines.append(f"    * ... and {len(self.affected_files) - 8} more file(s)")

        lines.append("=" * 50)
        return "\n".join(lines)


# --------------------------------------------------------------------------- inspector
class SystemInspector(Protocol):
    """Protocol for inspecting host process trees, sockets, services, and files."""

    def get_process_tree(self, pid: int) -> tuple[ProcessBlast | None, list[ProcessBlast]]: ...
    def get_open_sockets(self, pids: Sequence[int]) -> list[SocketBlast]: ...
    def get_open_files(self, pids: Sequence[int]) -> list[str]: ...
    def get_dependent_services(self, pid: int, name: str | None = None) -> list[str]: ...
    def get_connections_to_target(self, ip: str, port: int | None = None) -> list[SocketBlast]: ...
    def get_system_socket_count(self) -> int: ...
    def is_file_open_by_processes(self, file_path: str) -> list[int]: ...


class PsutilSystemInspector:
    """Live system inspection using psutil and OS filesystem / cgroup checks."""

    def get_process_tree(self, pid: int) -> tuple[ProcessBlast | None, list[ProcessBlast]]:
        import psutil

        try:
            p = psutil.Process(pid)
            cmd: list[str] = []
            with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
                cmd = p.cmdline()
            root = ProcessBlast(
                pid=p.pid,
                name=p.name(),
                cmdline=cmd,
                parent_pid=p.ppid(),
                is_root=True,
            )
            children: list[ProcessBlast] = []
            for child in p.children(recursive=True):
                try:
                    c_cmd: list[str] = []
                    with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
                        c_cmd = child.cmdline()
                    children.append(
                        ProcessBlast(
                            pid=child.pid,
                            name=child.name(),
                            cmdline=c_cmd,
                            parent_pid=child.ppid(),
                            is_root=False,
                        )
                    )
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
            return root, children
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None, []

    def get_open_sockets(self, pids: Sequence[int]) -> list[SocketBlast]:
        import psutil

        results: list[SocketBlast] = []
        for pid in pids:
            try:
                p = psutil.Process(pid)
                for conn in p.net_connections():
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    results.append(
                        SocketBlast(
                            local=laddr,
                            remote=raddr,
                            protocol="tcp" if conn.type == 1 else "udp",
                            state=conn.status,
                            pid=pid,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return results

    def get_open_files(self, pids: Sequence[int]) -> list[str]:
        import psutil

        files: set[str] = set()
        for pid in pids:
            try:
                p = psutil.Process(pid)
                for of in p.open_files():
                    files.add(of.path)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return sorted(files)

    def get_dependent_services(self, pid: int, name: str | None = None) -> list[str]:
        services: list[str] = []
        if sys.platform.startswith("linux"):
            cgroup_path = Path(f"/proc/{pid}/cgroup")
            if cgroup_path.is_file():
                try:
                    content = cgroup_path.read_text(encoding="utf-8")
                    for line in content.splitlines():
                        if ".service" in line:
                            parts = line.split("/")
                            for part in parts:
                                if part.endswith(".service"):
                                    services.append(part)
                except Exception as exc:
                    log.debug("Could not read cgroup for pid %d: %s", pid, exc)
        return sorted(set(services))

    def get_connections_to_target(self, ip: str, port: int | None = None) -> list[SocketBlast]:
        import psutil

        matches: list[SocketBlast] = []
        try:
            for conn in psutil.net_connections():
                if conn.raddr and conn.raddr.ip == ip and (port is None or conn.raddr.port == port):
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
                    matches.append(
                        SocketBlast(
                            local=laddr,
                            remote=raddr,
                            protocol="tcp" if conn.type == 1 else "udp",
                            state=conn.status,
                            pid=conn.pid,
                        )
                    )
        except (psutil.AccessDenied, Exception) as exc:
            log.debug("psutil.net_connections error: %s", exc)
        return matches

    def get_system_socket_count(self) -> int:
        import psutil

        try:
            return len(psutil.net_connections())
        except Exception:
            return 0

    def is_file_open_by_processes(self, file_path: str) -> list[int]:
        import psutil

        pids: list[int] = []
        canon = os.path.realpath(file_path)
        for proc in psutil.process_iter(attrs=["pid"]):
            try:
                for of in proc.open_files():
                    if os.path.realpath(of.path) == canon:
                        pids.append(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return pids


class MockSystemInspector:
    """Mock inspector for deterministic unit tests and simulated blast radius checks."""

    def __init__(
        self,
        *,
        processes: dict[int, tuple[ProcessBlast, list[ProcessBlast]]] | None = None,
        sockets: dict[int, list[SocketBlast]] | None = None,
        files: dict[int, list[str]] | None = None,
        services: dict[int, list[str]] | None = None,
        connections: list[SocketBlast] | None = None,
        system_socket_count: int = 15,
        open_file_pids: dict[str, list[int]] | None = None,
    ) -> None:
        self._processes = processes or {}
        self._sockets = sockets or {}
        self._files = files or {}
        self._services = services or {}
        self._connections = connections or []
        self._system_socket_count = system_socket_count
        self._open_file_pids = open_file_pids or {}

    def get_process_tree(self, pid: int) -> tuple[ProcessBlast | None, list[ProcessBlast]]:
        return self._processes.get(pid, (None, []))

    def get_open_sockets(self, pids: Sequence[int]) -> list[SocketBlast]:
        res: list[SocketBlast] = []
        for p in pids:
            res.extend(self._sockets.get(p, []))
        return res

    def get_open_files(self, pids: Sequence[int]) -> list[str]:
        res: set[str] = set()
        for p in pids:
            res.update(self._files.get(p, []))
        return sorted(res)

    def get_dependent_services(self, pid: int, name: str | None = None) -> list[str]:
        return self._services.get(pid, [])

    def get_connections_to_target(self, ip: str, port: int | None = None) -> list[SocketBlast]:
        matches = []
        for c in self._connections:
            if c.remote.startswith(ip) and (port is None or c.remote.endswith(f":{port}")):
                matches.append(c)
        return matches

    def get_system_socket_count(self) -> int:
        return self._system_socket_count

    def is_file_open_by_processes(self, file_path: str) -> list[int]:
        return self._open_file_pids.get(file_path, [])


# --------------------------------------------------------------------------- estimator
class BlastRadiusEstimator:
    """Calculates blast radius impact and builds structured dry-run diffs."""

    def __init__(
        self,
        inspector: SystemInspector | None = None,
        default_threshold: float = DEFAULT_IMPACT_THRESHOLD,
    ) -> None:
        self.inspector: SystemInspector = inspector or PsutilSystemInspector()
        self.default_threshold = default_threshold

    def estimate(
        self,
        action: ResponseAction,
        target: dict[str, Any],
        *,
        threshold: float | None = None,
    ) -> BlastRadiusEstimate:
        """Estimate blast radius for a given action and target."""
        limit = self.default_threshold if threshold is None else threshold

        if action in (ResponseAction.SUSPEND_PROCESS, ResponseAction.TERMINATE_PROCESS):
            return self._estimate_process_action(action, target, limit)
        if action == ResponseAction.BLOCK_CONNECTION:
            return self._estimate_block_connection(action, target, limit)
        if action == ResponseAction.QUARANTINE_FILE:
            return self._estimate_quarantine_file(action, target, limit)
        if action == ResponseAction.ISOLATE_ENDPOINT:
            return self._estimate_isolate_endpoint(action, target, limit)
        if action == ResponseAction.SNAPSHOT_PROTECT:
            return self._estimate_snapshot_protect(action, target, limit)
        if action == ResponseAction.ALERT:
            return self._estimate_alert(action, target, limit)

        # Fallback for unexpected actions
        return BlastRadiusEstimate(
            action=action,
            target=target,
            impact_score=50.0,
            threshold=limit,
            requires_approval=True,
            approval_reason=f"Unknown or uncalibrated action type: {action.value}",
            risk_level="MEDIUM",
        )

    def _estimate_process_action(
        self, action: ResponseAction, target: dict[str, Any], threshold: float
    ) -> BlastRadiusEstimate:
        pid = target.get("pid")
        base_impact = 35.0 if action == ResponseAction.TERMINATE_PROCESS else 25.0

        if pid is None or not isinstance(pid, int):
            return BlastRadiusEstimate(
                action=action,
                target=target,
                impact_score=base_impact,
                threshold=threshold,
                requires_approval=base_impact >= threshold,
                approval_reason=f"Invalid or missing PID for {action.value}",
                risk_level="LOW",
                diff_summary=f"[-] {action.value} without valid PID",
            )

        root_proc, children = self.inspector.get_process_tree(pid)
        if root_proc is None:
            root_proc = ProcessBlast(
                pid=pid,
                name=target.get("process_name", "unknown"),
                is_root=True,
            )

        all_procs = [root_proc, *children]
        all_pids = [p.pid for p in all_procs]
        child_pids = [c.pid for c in children]

        open_sockets = self.inspector.get_open_sockets(all_pids)
        open_files = self.inspector.get_open_files(all_pids)
        dependent_services = self.inspector.get_dependent_services(pid, root_proc.name)

        child_weight = min(len(children) * 10.0, 30.0)
        socket_weight = min(len(open_sockets) * 5.0, 25.0)
        file_weight = min(len(open_files) * 2.0, 10.0)
        service_weight = 25.0 if dependent_services else 0.0

        total_impact = min(base_impact + child_weight + socket_weight + file_weight + service_weight, 100.0)

        if total_impact >= 80.0:
            risk_level = "CRITICAL"
        elif total_impact >= 60.0:
            risk_level = "HIGH"
        elif total_impact >= 35.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        requires_approval = total_impact >= threshold
        approval_reason = ""
        if requires_approval:
            reasons = []
            if len(children) > 0:
                reasons.append(f"{len(children)} child process(es)")
            if len(open_sockets) > 0:
                reasons.append(f"{len(open_sockets)} open socket(s)")
            if dependent_services:
                reasons.append(f"dependent services: {', '.join(dependent_services)}")
            reason_str = ", ".join(reasons) if reasons else "high base impact"
            approval_reason = (
                f"Impact score {total_impact:.1f} >= threshold {threshold:.1f} ({action.value}: {reason_str})"
            )

        est = BlastRadiusEstimate(
            action=action,
            target=target,
            impact_score=round(total_impact, 1),
            threshold=threshold,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
            risk_level=risk_level,
            processes_affected=all_procs,
            process_tree_children=child_pids,
            open_socket_count=len(open_sockets),
            open_sockets=open_sockets,
            dependent_system_services=dependent_services,
            affected_files=open_files,
        )
        est.diff_summary = est.to_diff()
        return est

    def _estimate_block_connection(
        self, action: ResponseAction, target: dict[str, Any], threshold: float
    ) -> BlastRadiusEstimate:
        ip = str(target.get("ip", ""))
        port = target.get("port")
        port_int = int(port) if port is not None else None

        active_connections = self.inspector.get_connections_to_target(ip, port_int)
        base_impact = 20.0
        conn_weight = min(len(active_connections) * 15.0, 45.0)

        critical_port_weight = 25.0 if port_int in (53, 88, 389, 445, 636) else 0.0
        total_impact = min(base_impact + conn_weight + critical_port_weight, 100.0)

        risk_level = "HIGH" if total_impact >= 60.0 else ("MEDIUM" if total_impact >= 35.0 else "LOW")
        requires_approval = total_impact >= threshold
        approval_reason = ""
        if requires_approval:
            approval_reason = (
                f"Impact score {total_impact:.1f} >= threshold {threshold:.1f} "
                f"(blocks {ip}:{port_int or '*'} affecting {len(active_connections)} active connection(s))"
            )

        affected_pids = [c.pid for c in active_connections if c.pid is not None]
        procs: list[ProcessBlast] = []
        for p in set(affected_pids):
            root, _ = self.inspector.get_process_tree(p)
            if root:
                procs.append(root)

        est = BlastRadiusEstimate(
            action=action,
            target=target,
            impact_score=round(total_impact, 1),
            threshold=threshold,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
            risk_level=risk_level,
            processes_affected=procs,
            open_socket_count=len(active_connections),
            open_sockets=active_connections,
        )
        est.diff_summary = est.to_diff()
        return est

    def _estimate_quarantine_file(
        self, action: ResponseAction, target: dict[str, Any], threshold: float
    ) -> BlastRadiusEstimate:
        fpath = str(target.get("path", ""))
        base_impact = 25.0

        pids = self.inspector.is_file_open_by_processes(fpath)
        locked_weight = min(len(pids) * 25.0, 50.0)

        path_lower = fpath.lower()
        sys_dirs = ("/bin/", "/usr/bin/", "/lib/", "/etc/", "c:\\windows", "c:\\program files")
        is_sys = any(p in path_lower for p in sys_dirs)
        sys_weight = 30.0 if is_sys else 0.0

        total_impact = min(base_impact + locked_weight + sys_weight, 100.0)
        risk_level = "CRITICAL" if total_impact >= 80.0 else ("HIGH" if total_impact >= 60.0 else "MEDIUM")

        requires_approval = total_impact >= threshold
        approval_reason = ""
        if requires_approval:
            reasons = []
            if pids:
                reasons.append(f"open by {len(pids)} active process(es)")
            if is_sys:
                reasons.append("system executable/library location")
            approval_reason = (
                f"Impact score {total_impact:.1f} >= threshold {threshold:.1f} "
                f"(quarantine {fpath}: {', '.join(reasons)})"
            )

        procs: list[ProcessBlast] = []
        for p in set(pids):
            root, _ = self.inspector.get_process_tree(p)
            if root:
                procs.append(root)

        est = BlastRadiusEstimate(
            action=action,
            target=target,
            impact_score=round(total_impact, 1),
            threshold=threshold,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
            risk_level=risk_level,
            processes_affected=procs,
            affected_files=[fpath] if fpath else [],
        )
        est.diff_summary = est.to_diff()
        return est

    def _estimate_isolate_endpoint(
        self, action: ResponseAction, target: dict[str, Any], threshold: float
    ) -> BlastRadiusEstimate:
        total_sockets = self.inspector.get_system_socket_count()
        base_impact = 85.0
        socket_weight = min((total_sockets // 10) * 2.0, 15.0)
        total_impact = min(base_impact + socket_weight, 100.0)

        requires_approval = total_impact >= threshold
        approval_reason = (
            f"Impact score {total_impact:.1f} >= threshold {threshold:.1f} "
            f"(endpoint isolation severs network connectivity for {total_sockets} active socket(s))"
        )

        est = BlastRadiusEstimate(
            action=action,
            target=target,
            impact_score=round(total_impact, 1),
            threshold=threshold,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
            risk_level="CRITICAL",
            open_socket_count=total_sockets,
            metadata={"total_system_sockets": total_sockets},
        )
        est.diff_summary = est.to_diff()
        return est

    def _estimate_snapshot_protect(
        self, action: ResponseAction, target: dict[str, Any], threshold: float
    ) -> BlastRadiusEstimate:
        impact_score = 10.0
        est = BlastRadiusEstimate(
            action=action,
            target=target,
            impact_score=impact_score,
            threshold=threshold,
            requires_approval=impact_score >= threshold,
            approval_reason="",
            risk_level="LOW",
            metadata={"protective_snapshot": True},
        )
        est.diff_summary = est.to_diff()
        return est

    def _estimate_alert(
        self, action: ResponseAction, target: dict[str, Any], threshold: float
    ) -> BlastRadiusEstimate:
        est = BlastRadiusEstimate(
            action=action,
            target=target,
            impact_score=0.0,
            threshold=threshold,
            requires_approval=False,
            approval_reason="",
            risk_level="LOW",
        )
        est.diff_summary = "[-] ALERT: Non-destructive, zero host blast radius."
        return est


__all__ = [
    "DEFAULT_IMPACT_THRESHOLD",
    "BlastRadiusEstimate",
    "BlastRadiusEstimator",
    "MockSystemInspector",
    "ProcessBlast",
    "PsutilSystemInspector",
    "SocketBlast",
    "SystemInspector",
]
