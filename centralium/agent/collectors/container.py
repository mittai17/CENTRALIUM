"""Container and cloud-workload awareness collector and enrichment.

Capabilities:
1. Parses /proc/<pid>/cgroup and /proc/<pid>/mountinfo to identify container workloads:
   - Identifies container_id, runtime (docker, containerd, k8s, crio, podman), and pod_name / pod_uid.
2. Implements container-escape heuristics:
   - Sensitive socket mounts (/var/run/docker.sock, containerd.sock, podman.sock)
   - Privileged flags / capabilities (e.g., CAP_SYS_ADMIN, CapEff full mask)
   - nsenter execution targeting host PID 1 namespaces
   - Host PID namespace sharing within a container
3. Enriches NormalizedEvent instances with container metadata and escape risk indicators.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

from centralium.agent.models import NormalizedEvent

log = logging.getLogger(__name__)

# Hex ID pattern for containers (typically 64 hex characters or 12 short)
_CONTAINER_HEX_RE = re.compile(r"([0-9a-fA-F]{64}|[0-9a-fA-F]{12})")
# Kubernetes pod UID pattern
_K8S_POD_UID_RE = re.compile(r"pod([0-9a-fA-F\-]{36}|[0-9a-fA-F_]{32,})")


@dataclass
class ContainerMetadata:
    """Container context for an inspected process."""

    container_id: str | None = None
    runtime: str = "host"  # "docker", "containerd", "k8s", "crio", "podman", "host"
    pod_name: str | None = None
    pod_uid: str | None = None
    is_container: bool = False
    privileged: bool = False
    escape_risk: bool = False
    escape_indicators: list[str] = field(default_factory=list)


def _extract_container_id(path: str) -> str | None:
    m_scope = re.search(r"[-/]([0-9a-fA-F]{64,})(?:\.scope)?", path)
    if m_scope:
        return m_scope.group(1)
    m_64 = re.search(r"([0-9a-fA-F]{64,})", path)
    if m_64:
        return m_64.group(1)
    m_12 = re.search(r"[-/]([0-9a-fA-F]{12})(?:\.scope)?", path)
    if m_12:
        return m_12.group(1)
    return None


def parse_cgroup_text(text: str) -> tuple[str | None, str, str | None, str | None]:
    """Parse /proc/<pid>/cgroup lines (v1 and v2).

    Returns:
        (container_id, runtime, pod_name, pod_uid)
    """
    container_id: str | None = None
    runtime: str = "host"
    pod_name: str | None = None
    pod_uid: str | None = None

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        path = parts[2]

        # Check Kubernetes
        if "kubepods" in path:
            runtime = "k8s"
            uid_match = _K8S_POD_UID_RE.search(path)
            if uid_match:
                pod_uid = uid_match.group(1).replace("_", "-")
                pod_name = f"pod-{pod_uid[:8]}"
            container_id = _extract_container_id(path)
            return container_id, runtime, pod_name, pod_uid

        # Check Docker
        if "docker" in path:
            runtime = "docker"
            container_id = _extract_container_id(path)
            return container_id, runtime, pod_name, pod_uid

        # Check containerd
        if "containerd" in path or "cri-containerd" in path:
            runtime = "containerd"
            container_id = _extract_container_id(path)
            return container_id, runtime, pod_name, pod_uid

        # Check CRI-O
        if "crio" in path:
            runtime = "crio"
            container_id = _extract_container_id(path)
            return container_id, runtime, pod_name, pod_uid

        # Check Podman
        if "libpod" in path or "podman" in path:
            runtime = "podman"
            container_id = _extract_container_id(path)
            return container_id, runtime, pod_name, pod_uid

    return container_id, runtime, pod_name, pod_uid


def parse_mountinfo_text(text: str) -> dict[str, Any]:
    """Parse /proc/<pid>/mountinfo to identify sensitive or dangerous mounts.

    Returns dict with detected socket mounts and root mounts.
    """
    has_docker_sock = False
    has_containerd_sock = False
    has_podman_sock = False
    has_host_root = False
    mounted_sockets: list[str] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        mount_point = parts[4]

        if "docker.sock" in line:
            has_docker_sock = True
            mounted_sockets.append(mount_point)
        if "containerd.sock" in line:
            has_containerd_sock = True
            mounted_sockets.append(mount_point)
        if "podman.sock" in line:
            has_podman_sock = True
            mounted_sockets.append(mount_point)

        # Host root filesystem mounted inside container (e.g. /host, /rootfs, /hostfs)
        if mount_point in {"/host", "/rootfs", "/hostfs", "/mnt/host"} and parts[3] == "/":
            has_host_root = True

    return {
        "has_docker_socket": has_docker_sock,
        "has_containerd_socket": has_containerd_sock,
        "has_podman_socket": has_podman_sock,
        "has_host_root": has_host_root,
        "mounted_sockets": mounted_sockets,
    }


def check_privileged_status(status_text: str) -> bool:
    """Parse /proc/<pid>/status to determine if process has privileged capabilities.

    Specifically checks for CapEff with CAP_SYS_ADMIN (bit 21, 0x200000) or full capabilities.
    """
    for line in status_text.splitlines():
        line = line.strip()
        if line.startswith("CapEff:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                try:
                    val = int(parts[1].strip(), 16)
                    # Check CAP_SYS_ADMIN (bit 21 = 0x200000)
                    if (val & 0x00200000) != 0 or val >= 0x3FFFFFFFFF:
                        return True
                except ValueError:
                    pass
    return False


def check_nsenter_escape(command_line: str | None, process_name: str | None) -> bool:
    """Detect nsenter execution attempting to switch to host namespace (PID 1)."""
    pname = (process_name or "").lower()
    cmd = (command_line or "").lower()
    if "nsenter" in pname or "nsenter" in cmd:
        # Check target PID 1 (host system init)
        if "-t 1" in cmd or "--target 1" in cmd or "--target=1" in cmd:
            return True
        # Check entering all namespaces (-m, -u, -i, -n, -p)
        if any(flag in cmd for flag in ("--mount", "--uts", "--ipc", "--net", "--pid")):
            return True
    return False


class ContainerEnricher:
    """Enriches telemetry events with container metadata and escape risk analysis."""

    def __init__(self, proc_root: str = "/proc") -> None:
        self.proc_root = proc_root

    def inspect_pid(
        self,
        pid: int,
        cgroup_text: str | None = None,
        mountinfo_text: str | None = None,
        status_text: str | None = None,
        proc1_comm: str | None = None,
    ) -> ContainerMetadata:
        """Inspect a PID or synthetic /proc texts to build ContainerMetadata."""
        meta = ContainerMetadata()

        # 1. Parse cgroup
        cg_text = cgroup_text
        if cg_text is None:
            cg_path = os.path.join(self.proc_root, str(pid), "cgroup")
            if os.path.exists(cg_path):
                try:
                    with open(cg_path, encoding="utf-8", errors="replace") as f:
                        cg_text = f.read()
                except OSError:
                    pass

        if cg_text:
            cid, rtime, pod, puid = parse_cgroup_text(cg_text)
            meta.container_id = cid
            meta.runtime = rtime
            meta.pod_name = pod
            meta.pod_uid = puid
            meta.is_container = bool(cid or rtime != "host")

        # 2. Check capabilities / privileged
        st_text = status_text
        if st_text is None:
            st_path = os.path.join(self.proc_root, str(pid), "status")
            if os.path.exists(st_path):
                try:
                    with open(st_path, encoding="utf-8", errors="replace") as f:
                        st_text = f.read()
                except OSError:
                    pass

        if st_text:
            meta.privileged = check_privileged_status(st_text)

        # 3. Check mountinfo
        mi_text = mountinfo_text
        if mi_text is None:
            mi_path = os.path.join(self.proc_root, str(pid), "mountinfo")
            if os.path.exists(mi_path):
                try:
                    with open(mi_path, encoding="utf-8", errors="replace") as f:
                        mi_text = f.read()
                except OSError:
                    pass

        # 4. Container Escape Heuristics
        indicators: list[str] = []
        if mi_text:
            mounts = parse_mountinfo_text(mi_text)
            if mounts["has_docker_socket"]:
                indicators.append("docker_socket_mounted")
            if mounts["has_containerd_socket"]:
                indicators.append("containerd_socket_mounted")
            if mounts["has_podman_socket"]:
                indicators.append("podman_socket_mounted")
            if mounts["has_host_root"]:
                indicators.append("host_root_mounted")

        if meta.is_container and meta.privileged:
            indicators.append("privileged_container")

        # 5. Check host PID namespace sharing
        p1_comm = proc1_comm
        if p1_comm is None and meta.is_container:
            p1_path = os.path.join(self.proc_root, "1", "comm")
            if os.path.exists(p1_path):
                try:
                    with open(p1_path, encoding="utf-8", errors="replace") as f:
                        p1_comm = f.read().strip()
                except OSError:
                    pass

        if meta.is_container and p1_comm and p1_comm.lower() in {"systemd", "init"}:
            indicators.append("host_pid_namespace_shared")

        if indicators:
            meta.escape_risk = True
            meta.escape_indicators = indicators

        return meta

    def enrich_event(
        self,
        event: NormalizedEvent,
        cgroup_text: str | None = None,
        mountinfo_text: str | None = None,
        status_text: str | None = None,
    ) -> NormalizedEvent:
        """Enrich a NormalizedEvent with container context and escape indicators."""
        pid = event.pid or 0
        meta = self.inspect_pid(
            pid=pid,
            cgroup_text=cgroup_text,
            mountinfo_text=mountinfo_text,
            status_text=status_text,
        )

        # Check command-line for nsenter escape
        if check_nsenter_escape(event.command_line, event.process_name):
            if "nsenter_host_escape" not in meta.escape_indicators:
                meta.escape_indicators.append("nsenter_host_escape")
            meta.escape_risk = True

        event.raw_metadata.update(
            {
                "container_id": meta.container_id,
                "container_runtime": meta.runtime,
                "pod_name": meta.pod_name,
                "pod_uid": meta.pod_uid,
                "is_container": meta.is_container,
                "container_privileged": meta.privileged,
                "container_escape_risk": meta.escape_risk,
                "container_escape_indicators": meta.escape_indicators,
            }
        )
        return event
