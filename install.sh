#!/usr/bin/env bash
# Firedamp Installer: Canaries for your RAG Stack
# Safe, no-clobber installer.
set -euo pipefail
umask 0022

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

# 3. Determine installation paths and release reference
DEFAULT_FIREDAMP_REF="v0.1.0"
FIREDAMP_REF="${FIREDAMP_REF:-$DEFAULT_FIREDAMP_REF}"
TARGET_INSTALL_DIR="${FIREDAMP_INSTALL_DIR:-${HOME}/.firedamp}"
BIN_DIR="${FIREDAMP_BIN_DIR:-${HOME}/.local/bin}"
LAUNCHER="${BIN_DIR}/firedamp"

# Accepted path policy:
# - TARGET_INSTALL_DIR and BIN_DIR must be non-empty absolute paths without traversal ('..').
# - Critical system directories and $HOME (as install root) are refused.
# - Neither destination leaf nor any existing ancestor directory may be a symlink.
# - Existing BIN_DIR and parent directories must be owned by the current user (or root with sticky bit for /tmp)
#   and must not be world-writable without the sticky bit.
VALIDATE_PATHS_SCRIPT='
import os, stat, sys

target_dir = sys.argv[1]
bin_dir = sys.argv[2]
home_dir = sys.argv[3]

if not target_dir or not bin_dir:
    sys.stderr.write("Installation and binary paths must be non-empty.\n")
    sys.exit(1)

for label, p in [("FIREDAMP_INSTALL_DIR", target_dir), ("FIREDAMP_BIN_DIR", bin_dir)]:
    if "\x00" in p or "\n" in p:
        sys.stderr.write(f"Invalid characters in {label}.\n")
        sys.exit(1)
    if not os.path.isabs(p):
        sys.stderr.write(f"{label} must be an absolute path: {p}\n")
        sys.exit(1)
    parts = p.split(os.sep)
    if ".." in parts:
        sys.stderr.write(f"Path traversal (..) is not allowed in {label}: {p}\n")
        sys.exit(1)

norm_target = os.path.normpath(target_dir)
norm_bin = os.path.normpath(bin_dir)
norm_home = os.path.normpath(home_dir) if home_dir else ""

unsafe_system_paths = {"", "/", "/root", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/local", "/etc", "/tmp", "/var"}
if norm_target in unsafe_system_paths or (norm_home and norm_target == norm_home):
    sys.stderr.write(f"Unsafe target install path: {norm_target}.\n")
    sys.exit(1)

if norm_bin in unsafe_system_paths or (norm_home and norm_bin == norm_home):
    sys.stderr.write(f"Unsafe launcher bin directory: {norm_bin}.\n")
    sys.exit(1)

if os.path.islink(norm_target):
    sys.stderr.write(f"Target install path is a symlink: {norm_target}.\nRefusing to install into a symlink for security reasons.\n")
    sys.exit(1)

if os.path.lexists(norm_target):
    sys.stderr.write(f"Installation destination already exists: {norm_target}\n")
    sys.stderr.write("Firedamp will not overwrite or delete an existing installation or user directory.\n")
    sys.stderr.write(f"To re-install, please remove or rename the existing directory manually:\n    mv \"{norm_target}\" \"{norm_target}.bak\"\n")
    sys.exit(1)

launcher = os.path.join(norm_bin, "firedamp")
if os.path.islink(launcher):
    sys.stderr.write(f"Launcher path is a symlink: {launcher}.\nRefusing to follow or overwrite a launcher symlink.\n")
    sys.exit(1)

if os.path.lexists(launcher):
    sys.stderr.write(f"Launcher destination already exists: {launcher}\n")
    sys.stderr.write("Firedamp will not overwrite or truncate an existing launcher or user file.\n")
    sys.exit(1)

uid = os.geteuid()

def check_ancestors(path_to_check: str, label: str, require_dir_if_exists: bool = False) -> None:
    cur = path_to_check
    checked_leaf = False
    while True:
        if os.path.lexists(cur):
            if os.path.islink(cur):
                sys.stderr.write(f"Refusing {label}: symlink detected in path component {cur}.\n")
                sys.exit(1)
            st = os.lstat(cur)
            if not checked_leaf and require_dir_if_exists and not stat.S_ISDIR(st.st_mode):
                sys.stderr.write(f"Refusing {label}: {cur} exists and is not a directory.\n")
                sys.exit(1)
            if stat.S_ISDIR(st.st_mode):
                # Allow root/nobody-mapped system base directories like /, /home, /tmp (if sticky)
                is_sticky_root_dir = (st.st_uid in (0, 65534) and bool(st.st_mode & stat.S_ISVTX))
                is_safe_system_root = (cur in {"/", "/home", "/Users", "/tmp", "/var", "/var/tmp"} and st.st_uid in (0, 65534))
                if st.st_uid != uid and not is_safe_system_root:
                    sys.stderr.write(f"Unsafe ownership on {label} path component {cur} (uid={st.st_uid}, expected={uid}).\n")
                    sys.exit(1)
                if (st.st_mode & stat.S_IWOTH) and not is_sticky_root_dir:
                    sys.stderr.write(f"Unsafe world-writable permissions on {label} path component {cur}.\n")
                    sys.exit(1)
                if not checked_leaf and require_dir_if_exists:
                    if not os.access(cur, os.W_OK | os.X_OK):
                        sys.stderr.write(f"Insufficient permissions on {label} directory {cur} (not writable).\n")
                        sys.exit(1)
                checked_leaf = True
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
        checked_leaf = True

check_ancestors(os.path.dirname(norm_target), "FIREDAMP_INSTALL_DIR parent", require_dir_if_exists=True)
check_ancestors(norm_bin, "FIREDAMP_BIN_DIR", require_dir_if_exists=True)
'

if ! python3 -c "$VALIDATE_PATHS_SCRIPT" "$TARGET_INSTALL_DIR" "$BIN_DIR" "${HOME:-}"; then
    exit 1
fi
TARGET_INSTALL_DIR="$(python3 -c 'import os,sys; print(os.path.normpath(sys.argv[1]))' "$TARGET_INSTALL_DIR")"
BIN_DIR="$(python3 -c 'import os,sys; print(os.path.normpath(sys.argv[1]))' "$BIN_DIR")"
LAUNCHER="${BIN_DIR}/firedamp"

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
LAUNCHER_STAGING_FILE=""

cleanup_all_staging() {
    if [ -n "${STAGING_DIR:-}" ] && [ -d "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
    if [ -n "${LAUNCHER_STAGING_FILE:-}" ] && [ -e "$LAUNCHER_STAGING_FILE" ]; then
        rm -f "$LAUNCHER_STAGING_FILE"
    fi
}
cleanup_staging() {
    local exit_code=$?
    cleanup_all_staging
    exit "$exit_code"
}
cleanup_sigint() {
    cleanup_all_staging
    exit 130
}
cleanup_sigterm() {
    cleanup_all_staging
    exit 143
}
trap cleanup_staging EXIT
trap cleanup_sigint INT
trap cleanup_sigterm TERM

# 7. Populate staging directory
if [ "$LOCAL_REPO" = true ]; then
    echo -e "${CYAN}[~] Staging from local source directory: ${REPO_SOURCE}${NC}"
    if git -C "$REPO_SOURCE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if [ -n "$(git -C "$REPO_SOURCE" status --porcelain)" ]; then
            echo -e "${RED}[ERROR] Local Git checkout is dirty (has uncommitted changes or untracked files): ${REPO_SOURCE}${NC}" >&2
            echo "Refusing to install because 'git clone' only installs committed HEAD state, not local edits." >&2
            echo "Commit or stash your changes first, or run from a clean checkout / extracted release archive." >&2
            exit 1
        fi
        git clone --depth 1 "file://${REPO_SOURCE}" "${STAGING_DIR}/repo" -q
    else
        # Non-Git local directory (e.g., extracted source tarball): copy safely excluding secrets/caches/venvs
        python3 -c '
import shutil, sys
src, dst = sys.argv[1], sys.argv[2]
def ignore(d, names):
    ignored = set()
    for n in names:
        if n in {".git", ".venv", "__pycache__", "evidence", "graphify-out", "firedamp_release_review_bundle.sh"}:
            ignored.add(n)
        elif n.startswith(".env") and n != ".env.example":
            ignored.add(n)
        elif n.endswith((".pyc", ".pyo")):
            ignored.add(n)
    return ignored
shutil.copytree(src, dst, ignore=ignore)
' "$REPO_SOURCE" "${STAGING_DIR}/repo"
    fi
else
    if [ "$FIREDAMP_REF" = "$DEFAULT_FIREDAMP_REF" ]; then
        echo -e "${CYAN}[~] Cloning Firedamp stable release (${FIREDAMP_REF}) into staging area...${NC}"
    else
        echo -e "${YELLOW}[~] Cloning Firedamp custom reference (${FIREDAMP_REF}) into staging area...${NC}"
    fi
    if ! git clone --depth 1 --branch "$FIREDAMP_REF" https://github.com/pr60t/firedamp.git "${STAGING_DIR}/repo" -q 2>/dev/null; then
        git clone https://github.com/pr60t/firedamp.git "${STAGING_DIR}/repo" -q
        git -C "${STAGING_DIR}/repo" checkout "$FIREDAMP_REF" -q
    fi
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

# 11. Stage and atomically publish launcher in BIN_DIR (separate filesystem object)
mkdir -p "$BIN_DIR"
if [ -L "$BIN_DIR" ] || [ ! -d "$BIN_DIR" ] || [ ! -w "$BIN_DIR" ]; then
    echo -e "${YELLOW}[PARTIAL INSTALL] Firedamp was installed to ${TARGET_INSTALL_DIR}, but ${BIN_DIR} is invalid or not writable.${NC}" >&2
    echo "Refusing to create launcher in an unsafe or unwritable directory." >&2
    echo "You can run Firedamp directly using: ${TARGET_INSTALL_DIR}/venv/bin/firedamp" >&2
    exit 1
fi

LAUNCHER_STAGING_FILE="$(mktemp "${BIN_DIR}/.firedamp-launcher-staging.XXXXXXXXXX")"
cat << EOF > "${LAUNCHER_STAGING_FILE}"
#!/usr/bin/env bash
set -e
exec "${TARGET_INSTALL_DIR}/venv/bin/firedamp" "\$@"
EOF
chmod 0755 "$LAUNCHER_STAGING_FILE"

echo -e "${CYAN}[~] Publishing launcher atomically...${NC}"
if ! python3 -c "$PUBLISH_SCRIPT" "$LAUNCHER_STAGING_FILE" "$LAUNCHER"; then
    echo -e "\n${YELLOW}[PARTIAL INSTALL] Firedamp was installed to ${TARGET_INSTALL_DIR}, but launcher publication to ${LAUNCHER} failed.${NC}" >&2
    echo -e "${RED}[ERROR] Refusing to overwrite or replace existing ${LAUNCHER}.${NC}" >&2
    echo "Recovery options:" >&2
    echo "  1. Run Firedamp directly: ${TARGET_INSTALL_DIR}/venv/bin/firedamp --help" >&2
    echo "  2. Inspect ${LAUNCHER}, remove or rename it if safe, then create a symlink:" >&2
    echo "     ln -s \"${TARGET_INSTALL_DIR}/venv/bin/firedamp\" \"${LAUNCHER}\"" >&2
    exit 1
fi

if [ -e "$LAUNCHER_STAGING_FILE" ] || [ -L "$LAUNCHER" ] || [ ! -f "$LAUNCHER" ] || [ ! -x "$LAUNCHER" ]; then
    echo -e "${YELLOW}[PARTIAL INSTALL] Firedamp was installed to ${TARGET_INSTALL_DIR}, but post-publication verification of ${LAUNCHER} failed.${NC}" >&2
    exit 1
fi

# 12. End-to-end verification of installed application and launcher
INSTALLED_PKG_VER="$("${TARGET_INSTALL_DIR}/venv/bin/python" -c "import importlib.metadata; print(importlib.metadata.version('firedamp'))" 2>/dev/null || true)"
if [ -z "$INSTALLED_PKG_VER" ]; then
    echo -e "${RED}[ERROR] Could not verify installed firedamp package version in ${TARGET_INSTALL_DIR}/venv.${NC}" >&2
    exit 1
fi

if ! "$LAUNCHER" version >/dev/null 2>&1; then
    echo -e "${YELLOW}[PARTIAL INSTALL] Firedamp ${INSTALLED_PKG_VER} was installed to ${TARGET_INSTALL_DIR}, but launcher verification failed for ${LAUNCHER}.${NC}" >&2
    exit 1
fi

echo -e "\n${GREEN}[+] Firedamp ${INSTALLED_PKG_VER} successfully installed to: ${TARGET_INSTALL_DIR}${NC}"
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
