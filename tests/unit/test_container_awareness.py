"""Unit tests for container and cloud-workload awareness collector."""

from __future__ import annotations

from centralium.agent.collectors.container import (
    ContainerEnricher,
    check_nsenter_escape,
    check_privileged_status,
    parse_cgroup_text,
    parse_mountinfo_text,
)
from centralium.agent.models import EventType, NormalizedEvent


def test_parse_cgroup_docker_v1_and_v2():
    # cgroup v1 Docker
    cg_v1 = "1:name=systemd:/docker/a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123"
    cid, runtime, pod, _ = parse_cgroup_text(cg_v1)
    assert runtime == "docker"
    assert cid == "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123"
    assert pod is None

    # cgroup v2 Docker
    cg_v2 = "0::/system.slice/docker-b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef01234567.scope"
    cid, runtime, pod, _ = parse_cgroup_text(cg_v2)
    assert runtime == "docker"
    assert cid == "b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef01234567"


def test_parse_cgroup_kubernetes():
    # cgroup v1 Kubernetes pod
    cg_k8s = "11:memory:/kubepods/burstable/pod12345678-1234-1234-1234-123456789abc/fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    cid, runtime, pod, puid = parse_cgroup_text(cg_k8s)
    assert runtime == "k8s"
    assert cid == "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    assert pod == "pod-12345678"
    assert puid == "12345678-1234-1234-1234-123456789abc"

    # cgroup v2 Kubernetes pod with containerd
    cg_k8s_v2 = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod87654321-4321-4321-4321-cba987654321.slice/cri-containerd-1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff.scope"
    cid, runtime, pod, puid = parse_cgroup_text(cg_k8s_v2)
    assert runtime == "k8s"
    assert cid == "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
    assert pod == "pod-87654321"


def test_parse_cgroup_host_process():
    cg_host = "0::/user.slice/user-1000.slice/session-2.scope"
    cid, runtime, pod, _ = parse_cgroup_text(cg_host)
    assert runtime == "host"
    assert cid is None
    assert pod is None


def test_parse_mountinfo_dangerous_mounts():
    # Docker socket mount inside container
    mountinfo = """36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext4 /dev/root rw,errors=continue
    40 36 0:33 / /var/run/docker.sock rw,nosuid,nodev master:2 - tmpfs tmpfs rw
    41 36 8:1 / /host rw,relatime master:3 - ext4 /dev/sda1 rw
    """
    res = parse_mountinfo_text(mountinfo)
    assert res["has_docker_socket"] is True
    assert res["has_host_root"] is True


def test_privileged_capabilities():
    # Full capabilities or CAP_SYS_ADMIN
    status_priv = """Name:\tbash
    Umask:\t0022
    CapInh:\t0000000000000000
    CapPrm:\t000001ffffffffff
    CapEff:\t000001ffffffffff
    CapBnd:\t000001ffffffffff
    """
    assert check_privileged_status(status_priv) is True

    # Unprivileged process
    status_unpriv = """Name:\tnode
    CapEff:\t0000000000000000
    """
    assert check_privileged_status(status_unpriv) is False


def test_nsenter_escape_detection():
    assert check_nsenter_escape("nsenter -t 1 -m -u -i -n -p /bin/sh", "nsenter") is True
    assert check_nsenter_escape("nsenter --target 1 --mount /bin/bash", "nsenter") is True
    assert check_nsenter_escape("python3 app.py", "python3") is False


def test_container_event_enrichment():
    enricher = ContainerEnricher()
    ev = NormalizedEvent(
        event_type=EventType.PROCESS_START,
        pid=1337,
        process_name="nsenter",
        command_line="nsenter -t 1 -m -u -i -n -p /bin/bash",
    )

    cg_sample = "1:name=systemd:/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    mi_sample = "50 36 0:30 / /var/run/docker.sock rw master:1 - tmpfs tmpfs rw"
    st_sample = "CapEff:\t000001ffffffffff"

    enriched = enricher.enrich_event(
        ev,
        cgroup_text=cg_sample,
        mountinfo_text=mi_sample,
        status_text=st_sample,
    )

    meta = enriched.raw_metadata
    assert meta["container_id"] == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    assert meta["container_runtime"] == "docker"
    assert meta["is_container"] is True
    assert meta["container_privileged"] is True
    assert meta["container_escape_risk"] is True
    assert "docker_socket_mounted" in meta["container_escape_indicators"]
    assert "privileged_container" in meta["container_escape_indicators"]
    assert "nsenter_host_escape" in meta["container_escape_indicators"]
