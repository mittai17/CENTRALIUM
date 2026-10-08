#!/usr/bin/env bash
# Runner for Centralium live auditd and firewall container/namespace tests.
# Executes inside an isolated throwaway network/user namespace so host network
# is NEVER touched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== CENTRALIUM CONTAINER & NETWORK HARNESS ==="

# Check mode: Container (Docker/Podman) vs Local unshare namespace
if [ "${1:-}" = "--container" ] || [ "${1:-}" = "container" ]; then
    ENGINE=""
    if command -v podman &>/dev/null; then
        ENGINE="podman"
    elif command -v docker &>/dev/null; then
        ENGINE="docker"
    fi

    if [ -z "${ENGINE}" ]; then
        echo "Error: Neither podman nor docker found in PATH." >&2
        exit 1
    fi

    echo "Building container image using ${ENGINE}..."
    "${ENGINE}" build -t centralium-test-harness:latest -f "${SCRIPT_DIR}/Dockerfile.auditd_nftables" "${REPO_ROOT}"

    echo "Running container with NET_ADMIN capability in throwaway container..."
    "${ENGINE}" run --rm --cap-add=NET_ADMIN centralium-test-harness:latest local
    exit 0
fi

# Default: Local throwaway user+network namespace via unshare
if command -v unshare &>/dev/null; then
    echo "Executing in isolated user & network namespace via 'unshare -rn'..."
    PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
    if [ ! -x "${PYTHON_BIN}" ]; then
        PYTHON_BIN="python3"
    fi

    unshare -rn bash -c "
        # Bring loopback up inside isolated netns
        ip link set lo up 2>/dev/null || true
        export PYTHONPATH=\"${REPO_ROOT}\"
        \"${PYTHON_BIN}\" \"${SCRIPT_DIR}/test_container_live.py\"
    "
else
    echo "unshare not available; running directly with available privileges..."
    PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
    if [ ! -x "${PYTHON_BIN}" ]; then
        PYTHON_BIN="python3"
    fi
    "${PYTHON_BIN}" "${SCRIPT_DIR}/test_container_live.py"
fi
