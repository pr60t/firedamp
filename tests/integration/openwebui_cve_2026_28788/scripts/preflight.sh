#!/usr/bin/env bash
# Preflight check for CVE-2026-28788 Lab Environment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

USE_SUDO="${USE_SUDO:-0}"
for arg in "$@"; do
    if [ "$arg" = "--use-sudo" ]; then
        USE_SUDO=1
    fi
done

echo "=== [Firedamp Lab Preflight] CVE-2026-28788 ==="
echo "Lab Directory: ${LAB_DIR}"
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Execution Mode: $([ "$USE_SUDO" = "1" ] && echo "Explicit Sudo Mode" || echo "Standard User Mode")"
echo ""

# 1. Check Python environment
echo "[1/5] Checking Python environment..."
if command -v python3 >/dev/null 2>&1; then
    PY_VER=$(python3 --version 2>&1)
    echo "  ✓ Python found: ${PY_VER}"
else
    echo "  ✗ python3 not found"
    exit 1
fi

# 2. Check Docker CLI & Compose
echo "[2/5] Checking Docker CLI & Compose..."
DOCKER_BIN="docker"
COMPOSE_BIN="docker compose"
if [ "$USE_SUDO" = "1" ]; then
    DOCKER_BIN="sudo -n docker"
    COMPOSE_BIN="sudo -n docker compose"
fi

if $DOCKER_BIN --version >/dev/null 2>&1; then
    DOCKER_VER=$($DOCKER_BIN --version 2>&1)
    echo "  ✓ Docker CLI found: ${DOCKER_VER}"
else
    echo "  ✗ Docker CLI not found or sudo authentication failed"
    exit 1
fi

if $COMPOSE_BIN version >/dev/null 2>&1; then
    COMPOSE_VER=$($COMPOSE_BIN version 2>&1)
    echo "  ✓ Docker Compose found: ${COMPOSE_VER}"
else
    echo "  ✗ Docker Compose not found or sudo authentication failed"
    exit 1
fi

# 3. Check Docker Daemon Connectivity & Permissions
echo "[3/5] Checking Docker Daemon connectivity and permissions..."
DAEMON_STATUS="OK"
DAEMON_BLOCKER=""

if [ "$USE_SUDO" = "1" ]; then
    # Non-interactive check with sudo -n to avoid blocking on credentials
    if ! sudo -n docker info >/dev/null 2>&1; then
        DAEMON_STATUS="UNAVAILABLE"
        DAEMON_BLOCKER="Explicit sudo mode requested, but 'sudo -n docker info' requires operator authentication or password."
        echo "  ! ${DAEMON_BLOCKER}"
    else
        echo "  ✓ Docker daemon is connected and responsive via authorized sudo."
    fi
else
    if [ ! -e /var/run/docker.sock ]; then
        DAEMON_STATUS="UNAVAILABLE"
        DAEMON_BLOCKER="Docker socket /var/run/docker.sock does not exist in the current filesystem namespace."
        echo "  ! ${DAEMON_BLOCKER}"
    elif ! docker info >/dev/null 2>&1; then
        DAEMON_STATUS="UNAVAILABLE"
        DAEMON_BLOCKER="Current user ($(whoami), uid=$(id -u)) lacks read/write access to /var/run/docker.sock."
        echo "  ! ${DAEMON_BLOCKER}"
        echo "    Socket permissions: $(stat -c '%A (%a) Owner: %U (%u) Group: %G (%g)' /var/run/docker.sock 2>/dev/null || true)"
        echo "    User groups: $(id -Gn 2>/dev/null || true)"
    else
        echo "  ✓ Docker daemon is connected and responsive."
    fi
fi

# 4. Check Container Image Manifests & Pinned Digests
echo "[4/5] Checking Container Image Manifests & Digests..."
V085_IMAGE="ghcr.io/open-webui/open-webui:v0.8.5@sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b"
V086_IMAGE="ghcr.io/open-webui/open-webui:v0.8.6@sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea"

echo "  Target v0.8.5: ${V085_IMAGE}"
echo "  Target v0.8.6: ${V086_IMAGE}"
if $DOCKER_BIN manifest inspect "ghcr.io/open-webui/open-webui:v0.8.5" >/dev/null 2>&1; then
    echo "  ✓ Manifest accessible via registry for v0.8.5."
else
    echo "  ! Manifest inspection restricted or network offline."
fi

# 5. Check Port Availability (13085 and 13086)
echo "[5/5] Checking loopback port availability (13085, 13086)..."
python3 - << 'EOF'
import socket
import sys

ports = [13085, 13086]
busy = []
for p in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('127.0.0.1', p))
    except OSError:
        busy.append(p)
    finally:
        s.close()

if busy:
    print(f"  ✗ Ports already in use: {busy}")
    sys.exit(1)
else:
    print("  ✓ Loopback ports 127.0.0.1:13085 and 127.0.0.1:13086 are available.")
EOF

echo ""
echo "=== Preflight Summary ==="
echo "Docker Daemon Status: ${DAEMON_STATUS}"
if [ "${DAEMON_STATUS}" = "OK" ]; then
    echo "Environment is READY for live container testing."
    exit 0
else
    echo "PARTIALLY COMPLETE — LIVE VALIDATION BLOCKED."
    echo "Cause: ${DAEMON_BLOCKER}"
    echo ""
    echo "Authorized Execution Guidance:"
    echo "1. Authorized Sudo Execution (Recommended for hosts where user has sudo access):"
    echo "   An authorized operator can run preflight and Compose commands using sudo:"
    echo "     USE_SUDO=1 bash tests/integration/openwebui_cve_2026_28788/scripts/preflight.sh --use-sudo"
    echo "     sudo docker compose -f tests/integration/openwebui_cve_2026_28788/compose.yaml up -d"
    echo ""
    echo "2. Rootless Docker Environment:"
    echo "   Configure Rootless Docker daemon via dockerd-rootless-setuptool.sh to allow container execution"
    echo "   without host root privileges."
    echo ""
    echo "Security Note: Do NOT run 'chmod 666 /var/run/docker.sock' and do NOT unconditionally add the user"
    echo "to the docker group without operational review, as docker group membership conveys root-equivalent host privileges."
    echo ""
    echo "Deterministic offline simulations remain available via:"
    echo "   python3 -m unittest discover tests/integration/openwebui_cve_2026_28788/simulations/ -v"
    exit 0
fi
