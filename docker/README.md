# Centralium Container & Isolated Namespace Test Harness

This directory contains the testing harness to verify Centralium's live firewall manipulation (`iptables`, `nftables`) and auditd tailing in an isolated Linux environment without risking host network connectivity or system state.

## Design & Safety Rules

1. **Host Isolation**: Real firewall rules (`iptables` / `nftables`) are never applied to the host's default network namespace.
2. **Two Execution Modes**:
   - **Rootless Network Namespace (`unshare -rn`)**: Uses Linux user and network namespaces (`CLONE_NEWUSER | CLONE_NEWNET`) to give the runner root netfilter privileges inside an isolated network namespace. No root privileges or Docker daemon required.
   - **Container (`Dockerfile.auditd_nftables`)**: Builds an Ubuntu 24.04 image with `auditd`, `iptables`, `nftables`, and `iproute2`. Runs with `--cap-add=NET_ADMIN` inside a throwaway container.

## What Runs Real vs Mocked

| Component | Test Mode | Real Kernel / System | Mock / Stub | Notes |
|---|---|---|---|---|
| **iptables connection blocking** | Container / `unshare -rn` | **Real** | - | Creates real `CENTRALIUM_BLOCK` chain and rules in isolated netns. |
| **iptables endpoint isolation** | Container / `unshare -rn` | **Real** | - | Creates real `CENTRALIUM_ISO` chain with default DROP and management ACCEPT. |
| **nftables connection blocking** | Container / `unshare -rn` | **Real** (where supported) | - | Creates real `inet centralium` table and output hook rules. |
| **auditd tailing** | Container / local | **Real log tailer & parser** | Synthetic records | `AuditdCollector` tails live files, tracks rotation, and parses OCSF events. Kernel netlink audit socket requires host root. |
| **Windows ETW / netsh** | Linux / CI | - | **Mocked / Argv verified** | Netsh/wevtutil tested via argv assertions and fixtures; tested in CI on Windows runner. |

## Running the Harness

### 1. Isolated Network Namespace (Default, Fast, Rootless)
```bash
./docker/run_container_tests.sh
```

### 2. Full Container (Podman / Docker)
```bash
./docker/run_container_tests.sh --container
```

The run generates a machine-readable JSON report at `docker/container_verification_report.json`.
