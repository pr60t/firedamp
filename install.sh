#!/usr/bin/env bash
# Firedamp Installer: Canaries for your RAG Stack
# Usage: curl -fsSL https://raw.githubusercontent.com/pr60t/firedamp/main/install.sh | bash

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
    echo -e "${RED}[ERROR] python3 is required but was not found on your system.${NC}"
    echo "Please install Python 3.10 or higher and retry."
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo -e "${RED}[ERROR] Python 3.10+ is required (found Python ${PY_VER}).${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python ${PY_VER} detected.${NC}"

# 2. Check git
if ! command -v git >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] git is required but was not found on your system.${NC}"
    exit 1
fi

# 3. Determine installation directory
INSTALL_DIR="${HOME}/.firedamp"
BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}" 2>/dev/null || true

# Check if script is run from within the cloned repository
if [ -f "pyproject.toml" ] && [ -f "cli.py" ] && [ -d "core" ]; then
    SOURCE_DIR="$(pwd)"
    echo -e "${CYAN}[~] Installing from local repository directory: ${SOURCE_DIR}${NC}"
else
    echo -e "${CYAN}[~] Cloning Firedamp repository into ${INSTALL_DIR}...${NC}"
    if [ -d "${INSTALL_DIR}/.git" ]; then
        cd "${INSTALL_DIR}"
        git fetch origin main -q
        git reset --hard origin/main -q
    else
        rm -rf "${INSTALL_DIR}"
        git clone https://github.com/pr60t/firedamp.git "${INSTALL_DIR}" -q
        cd "${INSTALL_DIR}"
    fi
    SOURCE_DIR="${INSTALL_DIR}"
fi

# 4. Set up Python virtual environment or package installation
VENV_DIR="${SOURCE_DIR}/.venv"
echo -e "${CYAN}[~] Configuring Python environment...${NC}"

# Try to create venv if not present or broken
INSTALLED=false
if [ ! -f "${VENV_DIR}/bin/pip" ]; then
    if python3 -m venv "${VENV_DIR}" >/dev/null 2>&1; then
        echo -e "${GREEN}[+] Virtual environment created at ${VENV_DIR}.${NC}"
    fi
fi

# If venv pip exists, install dependencies in venv and link binary
if [ -f "${VENV_DIR}/bin/pip" ]; then
    "${VENV_DIR}/bin/pip" install --upgrade pip -q 2>/dev/null || true
    "${VENV_DIR}/bin/pip" install -e "${SOURCE_DIR}" -q 2>/dev/null || true
    
    cat << EOF > "${BIN_DIR}/firedamp"
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${SOURCE_DIR}/cli.py" "\$@"
EOF
    chmod +x "${BIN_DIR}/firedamp" 2>/dev/null || true
    INSTALLED=true
fi

# Fallback launcher directly calling system python if venv unavailable
if [ "$INSTALLED" = false ]; then
    echo -e "${CYAN}[~] Setting up launcher script...${NC}"
    if [ -w "${BIN_DIR}" ]; then
        cat << EOF > "${BIN_DIR}/firedamp"
#!/usr/bin/env bash
exec python3 "${SOURCE_DIR}/cli.py" "\$@"
EOF
        chmod +x "${BIN_DIR}/firedamp" 2>/dev/null || true
        INSTALLED=true
    fi
fi

# 5. Verify installation
echo -e "\n${GREEN}[+] Firedamp successfully configured!${NC}"

# Check PATH
case ":${PATH:-}:" in
    *:"${BIN_DIR}":*) ;;
    *)
        echo -e "\n${YELLOW}[!] Note: ${BIN_DIR} is not in your current PATH.${NC}"
        echo "Add it to your shell by running:"
        echo -e "    ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
        echo "Or add that line to your ~/.bashrc or ~/.zshrc."
        ;;
esac

echo -e "\n${BOLD}Quick Test:${NC}"
python3 "${SOURCE_DIR}/cli.py" version

echo -e "\n${CYAN}To run an atmospheric simulation audit:${NC}"
echo -e "    firedamp scan --dry-run\n"
