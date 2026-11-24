#!/usr/bin/env bash
# Cleanup CVE-2026-28788 Lab Environment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

USE_SUDO="${USE_SUDO:-0}"
for arg in "$@"; do
    if [ "$arg" = "--use-sudo" ]; then
        USE_SUDO=1
    fi
done

echo "=== [Firedamp Lab Cleanup] CVE-2026-28788 ==="
echo "Teardown containers, volumes, and networks..."

COMPOSE_CMD="docker compose"
if [ "$USE_SUDO" = "1" ]; then
    COMPOSE_CMD="sudo -n docker compose"
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    $COMPOSE_CMD -f "${LAB_DIR}/compose.yaml" down -v --remove-orphans || {
        echo "Note: Docker compose down completed with warnings (e.g. permissions or containers not running)."
    }
else
    echo "Docker compose not available; no containers to clean."
fi

echo "Cleanup complete."
