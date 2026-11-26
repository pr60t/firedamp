#!/usr/bin/env bash
# Firedamp Installer: Canaries for your RAG Stack
# Safe, no-clobber installer.
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << 'EOF'
   ______ _               _                           
  |  ____(_)             | |                          
  | |__   _ _ __ ___   __| | __ _ _ __ ___  _ __     
  |  __| | | '__/ _ \ / _` |/ _` | '_ ` _ \| '_ \    
  | |    | | | |  __/| (_| | (_| | | | | | | |_) |   
  |_|    |_|_|  \___| \__,_|\__,_|_| |_| |_| .__/    
                                           | |       
     Mine Safety & Atmospheric Sensor for RAG |_|       
EOF
echo -e "${NC}"
echo -e "${BOLD}Installing Firedamp...${NC}\n"

# 1. Check Python >= 3.10
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] python3 is required but was not found on your system.${NC}" >&2
    echo "Please install Python 3.10 or higher and retry." >&2
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo -e "${RED}[ERROR] Python 3.10+ is required (found Python ${PY_VER}).${NC}" >&2
    exit 1
fi
echo -e "${GREEN}[+] Python ${PY_VER} detected.${NC}"

# 2. Check git
if ! command -v git >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] git is required but was not found on your system.${NC}" >&2
    exit 1
fi

# 3. Determine installation paths
TARGET_INSTALL_DIR="${FIREDAMP_INSTALL_DIR:-${HOME}/.firedamp}"
BIN_DIR="${FIREDAMP_BIN_DIR:-${HOME}/.local/bin}"

# Validate target path safety: refuse symlinks or root/critical directories
if [ -L "$TARGET_INSTALL_DIR" ]; then
    echo -e "${RED}[ERROR] Target install path is a symlink: ${TARGET_INSTALL_DIR}.${NC}" >&2
    echo "Refusing to install into a symlink for security reasons." >&2
    exit 1
fi

case "$TARGET_INSTALL_DIR" in
    ""|"/"|"/root"|"/bin"|"/usr"|"/usr/bin"|"/etc"|"/tmp"|"/var"|"$HOME")
        echo -e "${RED}[ERROR] Unsafe target install path: ${TARGET_INSTALL_DIR}.${NC}" >&2
        exit 1
        ;;
esac

# 4. Refuse to overwrite existing non-empty directory or git repository
if [ -e "$TARGET_INSTALL_DIR" ]; then
    echo -e "${RED}[ERROR] Installation destination already exists: ${TARGET_INSTALL_DIR}${NC}" >&2
    echo "Firedamp will not overwrite or delete an existing installation or user directory." >&2
    echo "To re-install, please remove or rename the existing directory manually:" >&2
    echo -e "    ${BOLD}mv \"${TARGET_INSTALL_DIR}\" \"${TARGET_INSTALL_DIR}.bak\"${NC}" >&2
    exit 1
fi

# 5. Check if we are running inside an existing Firedamp repository
CURRENT_DIR="$(pwd -P)"
LOCAL_REPO=false
if [ -f "${CURRENT_DIR}/pyproject.toml" ] && [ -f "${CURRENT_DIR}/cli.py" ] && [ -d "${CURRENT_DIR}/core" ]; then
    LOCAL_REPO=true
    REPO_SOURCE="${CURRENT_DIR}"
fi

# 6. Create dedicated staging directory with automatic trap cleanup
STAGING_BASE="${TARGET_INSTALL_DIR%/*}"
mkdir -p "$STAGING_BASE"
STAGING_DIR="$(mktemp -d "${STAGING_BASE}/.firedamp-install-staging.XXXXXXXXXX")"

cleanup_staging() {
    local exit_code=$?
    if [ -d "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
    exit "$exit_code"
}
cleanup_sigint() {
    if [ -d "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
    exit 130
}
cleanup_sigterm() {
    if [ -d "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
    exit 143
}
trap cleanup_staging EXIT
trap cleanup_sigint INT
trap cleanup_sigterm TERM

# 7. Populate staging directory
if [ "$LOCAL_REPO" = true ]; then
    echo -e "${CYAN}[~] Staging from local repository directory: ${REPO_SOURCE}${NC}"
    # Copy tracked working tree or files to staging directory without affecting source
    git clone --depth 1 "file://${REPO_SOURCE}" "${STAGING_DIR}/repo" -q || {
        # Fallback if git clone file:// is restricted: copy repository files
        cp -R "${REPO_SOURCE}/." "${STAGING_DIR}/repo"
    }
else
    echo -e "${CYAN}[~] Cloning Firedamp repository into staging area...${NC}"
    git clone https://github.com/pr60t/firedamp.git "${STAGING_DIR}/repo" -q
fi

# 8. Set up isolated virtual environment in staging
VENV_DIR="${STAGING_DIR}/venv"
echo -e "${CYAN}[~] Creating isolated Python virtual environment...${NC}"
# Use --system-site-packages if system packages are available, enabling hermetic/offline install when dependencies are pre-installed
VENV_FLAGS=()
if python3 -c "import typer, rich, pydantic, yaml" >/dev/null 2>&1; then
    VENV_FLAGS+=("--system-site-packages")
fi
python3 -m venv "${VENV_FLAGS[@]}" "$VENV_DIR"

if [ ! -f "${VENV_DIR}/bin/pip" ] || [ ! -f "${VENV_DIR}/bin/python" ]; then
    echo -e "${RED}[ERROR] Failed to create virtual environment.${NC}" >&2
    exit 1
fi

echo -e "${CYAN}[~] Installing Firedamp and dependencies...${NC}"
# Strict execution without hiding errors
PIP_INSTALL_FLAGS=("-e" "${STAGING_DIR}/repo" "-q")
if [ "${#VENV_FLAGS[@]}" -gt 0 ]; then
    # In offline or pre-provisioned environments with system site-packages, use --no-build-isolation
    PIP_INSTALL_FLAGS+=("--no-build-isolation")
fi
"${VENV_DIR}/bin/pip" install "${PIP_INSTALL_FLAGS[@]}"

# 9. Verify that firedamp runs in staging before publishing
if ! "${VENV_DIR}/bin/python" -c "import cli; import core; import probes" >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Python module verification failed in staged environment.${NC}" >&2
    exit 1
fi

# 10. Atomic / no-clobber publication to TARGET_INSTALL_DIR
# We publish the staged directory to TARGET_INSTALL_DIR using renameat2(RENAME_NOREPLACE).
# This provides genuine kernel-enforced atomic no-replace publication.
# If TARGET_INSTALL_DIR already exists (file, directory, empty directory, or symlink),
# renameat2 returns -1 with errno EEXIST (17), and the installer strictly fails closed.
STAGING_PUBLISH_DIR="${STAGING_DIR}/payload"
mkdir -p "$STAGING_PUBLISH_DIR"
mv "${STAGING_DIR}/repo" "${STAGING_PUBLISH_DIR}/repo"
mv "${STAGING_DIR}/venv" "${STAGING_PUBLISH_DIR}/venv"

echo -e "${CYAN}[~] Publishing installation atomically...${NC}"
PUBLISH_SCRIPT='
import ctypes, os, sys, errno

src = sys.argv[1]
dst = sys.argv[2]

if not sys.platform.startswith("linux"):
    sys.stderr.write(f"Atomic no-replace installation requires Linux (found {sys.platform}). Please follow manual installation instructions.\n")
    sys.exit(2)

machine = os.uname().machine
syscall_map = {
    "x86_64": 316,
    "aarch64": 276,
    "arm64": 276,
    "i386": 353,
    "i686": 353,
    "armv7l": 382,
    "armv8l": 382,
}
sys_num = syscall_map.get(machine)
if sys_num is None:
    sys.stderr.write(f"Unsupported architecture for renameat2 syscall: {machine}. Please follow manual installation instructions.\n")
    sys.exit(2)

src_stat = os.stat(os.path.dirname(os.path.abspath(src)))
dst_parent = os.path.dirname(os.path.abspath(dst))
if not os.path.exists(dst_parent):
    os.makedirs(dst_parent, exist_ok=True)
dst_parent_stat = os.stat(dst_parent)
if src_stat.st_dev != dst_parent_stat.st_dev:
    sys.stderr.write(f"Cross-device publication not supported: {src} and {dst} reside on different filesystems.\n")
    sys.exit(3)

libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = -100
RENAME_NOREPLACE = 1

src_bytes = os.fsencode(src)
dst_bytes = os.fsencode(dst)

res = libc.syscall(sys_num, AT_FDCWD, src_bytes, AT_FDCWD, dst_bytes, RENAME_NOREPLACE)
if res != 0:
    err = ctypes.get_errno()
    if err == errno.EEXIST:
        sys.stderr.write(f"Destination collision: {dst} already exists or was created concurrently.\n")
        sys.exit(1)
    else:
        sys.stderr.write(f"Atomic publication failed: {os.strerror(err)} (errno={err})\n")
        sys.exit(4)
sys.exit(0)
'

if ! python3 -c "$PUBLISH_SCRIPT" "$STAGING_PUBLISH_DIR" "$TARGET_INSTALL_DIR"; then
    echo -e "${RED}[ERROR] Atomic publication to ${TARGET_INSTALL_DIR} failed. Refusing to overwrite.${NC}" >&2
    exit 1
fi

# Verify publication post-conditions:
# Staging payload must be gone, destination must exist and contain expected layout
if [ -e "$STAGING_PUBLISH_DIR" ] || [ ! -d "${TARGET_INSTALL_DIR}/repo" ] || [ ! -d "${TARGET_INSTALL_DIR}/venv" ]; then
    echo -e "${RED}[ERROR] Post-publication layout verification failed for ${TARGET_INSTALL_DIR}.${NC}" >&2
    exit 1
fi

# 11. Create launcher in BIN_DIR
mkdir -p "$BIN_DIR"
LAUNCHER="${BIN_DIR}/firedamp"

cat << EOF > "${LAUNCHER}"
#!/usr/bin/env bash
set -e
exec "${TARGET_INSTALL_DIR}/venv/bin/firedamp" "\$@"
EOF
chmod +x "$LAUNCHER"

# 12. End-to-end verification of installed launcher
if ! "$LAUNCHER" version >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Post-install verification failed for ${LAUNCHER}.${NC}" >&2
    exit 1
fi

echo -e "\n${GREEN}[+] Firedamp successfully installed to: ${TARGET_INSTALL_DIR}${NC}"
echo -e "${GREEN}[+] Launcher installed to: ${LAUNCHER}${NC}"

# Check PATH
case ":${PATH:-}:" in
    *:"${BIN_DIR}":*) ;;
    *)
        echo -e "\n${YELLOW}[!] Note: ${BIN_DIR} is not in your current PATH.${NC}"
        echo "Add it to your shell by running:"
        echo -e "    ${BOLD}export PATH=\"${BIN_DIR}:\$PATH\"${NC}"
        echo "Or add that line to your ~/.bashrc or ~/.zshrc."
        ;;
esac

echo -e "\n${BOLD}Quick Test:${NC}"
"$LAUNCHER" version

echo -e "\n${CYAN}To run an atmospheric simulation audit:${NC}"
echo -e "    ${BOLD}${LAUNCHER} scan --dry-run${NC}\n"
