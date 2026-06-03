#!/usr/bin/env bash
# Itzraven - AI-Powered Security Testing Platform
# One-line: curl -fsSL https://raw.githubusercontent.com/iamaworker-github/itzraven/main/install.sh | bash
set -euo pipefail

# =============================================================================
# Configuration - override via environment
# =============================================================================
REPO_OWNER="${REPO_OWNER:-iamaworker-github}"
REPO_NAME="${REPO_NAME:-itzraven}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/itzraven}"
BRANCH="${BRANCH:-main}"

REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}"

BIN_DIR="${INSTALL_DIR}/bin"
VENV_DIR="${INSTALL_DIR}/venv"
REPO_DIR="${INSTALL_DIR}/repo"
ENV_FILE="${INSTALL_DIR}/.env"

PYTHON_MIN_MAJOR=3; PYTHON_MIN_MINOR=10
NODE_MIN_MAJOR=18
GO_MIN_MAJOR=1; GO_MIN_MINOR=21

# =============================================================================
# Output utilities
# =============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log_info()  { echo -e "${CYAN}INFO${NC}   $*"; }
log_ok()    { echo -e "${GREEN}OK${NC}     $*"; }
log_warn()  { echo -e "${YELLOW}WARN${NC}  $*"; }
log_error() { echo -e "${RED}ERROR${NC} $*"; }
section()   { echo; echo -e "${BOLD}${CYAN}═══ $* ═══${NC}"; echo; }

# =============================================================================
# Helpers
# =============================================================================
maybe_sudo() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    elif command -v sudo &>/dev/null; then sudo "$@"
    else "$@"; fi
}
check_cmd() { command -v "$1" &>/dev/null; }
ver_extract() { echo "$*" | grep -oE '[0-9]+\.[0-9]+' | head -1; }
ver_major() { echo "$1" | cut -d. -f1; }
ver_minor() { echo "$1" | cut -d. -f2; }
ver_ge() {
    local cm=$(ver_major "$1") cn=$(ver_minor "$1") rm=$(ver_major "$2") rn=$(ver_minor "$2")
    [ "$cm" -gt "$rm" ] 2>/dev/null && return 0
    [ "$cm" -eq "$rm" ] 2>/dev/null && [ "$cn" -ge "$rn" ] 2>/dev/null && return 0
    return 1
}
shell_config() {
    [ -n "${ZSH_VERSION:-}" ] || [ -f "$HOME/.zshrc" ] && echo "$HOME/.zshrc" || echo "$HOME/.bashrc"
}

# =============================================================================
# OS / package manager detection
# =============================================================================
detect_os() {
    case "$(uname -s)" in Linux) echo "linux" ;; Darwin) echo "darwin" ;; *) echo "unsupported" ;; esac
}
detect_pm() {
    local os="$1"
    [ "$os" = "darwin" ] && { check_cmd brew && echo "brew" || echo "none"; return; }
    check_cmd apt-get && echo "apt" || (check_cmd pacman && echo "pacman") || (check_cmd dnf && echo "dnf") || echo "none"
}
pm_installed() {
    local pm="$1" pkg="$2"
    case "$pm" in apt) dpkg -s "$pkg" &>/dev/null ;; pacman) pacman -Qi "$pkg" &>/dev/null ;; dnf) dnf list installed "$pkg" &>/dev/null ;; *) return 1 ;; esac
}

# =============================================================================
# Banner
# =============================================================================
show_banner() {
    echo -e "${CYAN}"
    echo "    █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗"
    echo "   ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝"
    echo "   ███████║██████╔╝██║  ███╗██║   ██║███████╗"
    echo "   ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║"
    echo "   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║"
    echo "   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝"
    echo -e "${NC}  ${BOLD}AI-Powered Security Testing Platform${NC}"
    echo -e "  ${CYAN}See Everything. Miss Nothing.${NC}" ; echo
}

# =============================================================================
# Prerequisites check
# =============================================================================
check_prereqs() {
    section "Checking prerequisites"
    local fail=0

    # python3
    if check_cmd python3; then
        local py_raw py_num
        py_raw=$(python3 --version 2>&1)
        py_num=$(ver_extract "$py_raw")
        if ver_ge "$py_num" "${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}"; then
            log_ok "python3 ${py_num}+ (${py_raw})"
        else
            log_error "python3 ${py_num} found, need ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+"; fail=1
        fi
    else
        log_error "python3 not found. Install Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+."; fail=1
    fi

    # pip3
    if check_cmd pip3; then
        log_ok "pip3 ($(pip3 --version 2>&1 | head -1))"
    elif python3 -m pip --version &>/dev/null; then
        log_ok "pip3 (via python3 -m pip)"
    else
        log_warn "pip3 not found, will attempt to install"
    fi

    # node
    if check_cmd node; then
        local node_ver node_major
        node_ver=$(node --version 2>&1)
        node_major=$(echo "$node_ver" | sed 's/^v//' | cut -d. -f1)
        if [ "$node_major" -ge "$NODE_MIN_MAJOR" ] 2>/dev/null; then
            log_ok "node ${node_ver}+"
        else
            log_error "node ${node_ver} found, need v${NODE_MIN_MAJOR}+"; fail=1
        fi
    else
        log_error "node not found. Install Node.js ${NODE_MIN_MAJOR}+."; fail=1
    fi

    # npm
    check_cmd npm && log_ok "npm ($(npm --version 2>&1))" || { log_error "npm not found."; fail=1; }

    # go
    if check_cmd go; then
        local go_raw go_ver
        go_raw=$(go version 2>&1)
        go_ver=$(echo "$go_raw" | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/^go//')
        if ver_ge "$go_ver" "${GO_MIN_MAJOR}.${GO_MIN_MINOR}"; then
            log_ok "go ${go_ver}+ (${go_raw})"
        else
            log_error "go ${go_ver} found, need go${GO_MIN_MAJOR}.${GO_MIN_MINOR}+"; fail=1
        fi
    else
        log_error "go not found. Install Go ${GO_MIN_MAJOR}.${GO_MIN_MINOR}+."; fail=1
    fi

    # git
    check_cmd git && log_ok "git ($(git --version 2>&1))" || { log_error "git not found."; fail=1; }

    [ "$fail" -eq 1 ] && { log_error "Prerequisites check failed. Fix above and re-run."; exit 1; }
    log_ok "All prerequisites met."
}

# =============================================================================
# System dependencies
# =============================================================================
install_system_deps() {
    section "Installing system dependencies"
    local os=$(detect_os) pm=$(detect_pm "$os")

    if [ "$os" = "darwin" ]; then
        if [ "$pm" = "brew" ]; then
            log_info "Using Homebrew on macOS..."
            maybe_sudo brew update --quiet 2>/dev/null || true
            for pkg in nmap dnsutils; do
                if brew list "$pkg" &>/dev/null; then log_ok "$pkg already installed"
                else log_info "Installing $pkg..."; maybe_sudo brew install "$pkg" || log_warn "Failed to install $pkg (non-critical)"; fi
            done
            if ! check_cmd dig; then
                maybe_sudo brew install bind 2>/dev/null && log_ok "bind (dnsutils) installed" || log_warn "bind install failed"
            else log_ok "bind (dnsutils) already available"; fi
        else
            log_warn "Homebrew not found. Install manually: nmap, dnsutils."
        fi
        return
    fi

    # Linux
    local install_cmd="" packages=()
    case "$pm" in
        apt) install_cmd="apt-get install -y -qq"; packages=(nmap dnsutils) ;;
        pacman) install_cmd="pacman -S --noconfirm"; packages=(nmap dnsutils) ;;
        dnf) install_cmd="dnf install -y -q"; packages=(nmap bind-utils) ;;
        *) log_warn "Unknown package manager. Install manually: nmap, dnsutils."; return ;;
    esac

    log_info "Package manager: ${pm}, updating..."
    case "$pm" in apt) maybe_sudo apt-get update -qq || true ;; pacman) maybe_sudo pacman -Sy --noconfirm 2>/dev/null || true ;; dnf) maybe_sudo dnf check-update -q 2>/dev/null || true ;; esac

    local missing=()
    for pkg in "${packages[@]}"; do
        pm_installed "$pm" "$pkg" && log_ok "$pkg already installed" || missing+=("$pkg")
    done
    [ ${#missing[@]} -gt 0 ] && { log_info "Installing: ${missing[*]}..."; maybe_sudo $install_cmd "${missing[@]}" || log_warn "Some packages failed (non-critical)"; }
}

# =============================================================================
# Go tools
# =============================================================================
install_go_tools() {
    section "Installing Go security tools"
    local go_bin="$(go env GOPATH)/bin"
    mkdir -p "$go_bin"
    export PATH="${go_bin}:${PATH}"

    local tools=(
        "github.com/projectdiscovery/httpx/cmd/httpx@latest:pd-httpx"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest:nuclei"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest:naabu"
        "github.com/projectdiscovery/katana/cmd/katana@latest:katana"
        "github.com/lc/gau/v2/cmd/gau@latest:gau"
        "github.com/tomnomnom/waybackurls@latest:waybackurls"
    )

    for entry in "${tools[@]}"; do
        local pkg="${entry%%:*}" bin="${entry##*:}"
        [ -f "${go_bin}/${bin}" ] && { log_ok "${bin} already installed"; continue; }
        log_info "Installing ${bin}..."
        if go install -v "$pkg" 2>/dev/null; then
            [ "$bin" = "pd-httpx" ] && [ -f "${go_bin}/httpx" ] && mv "${go_bin}/httpx" "${go_bin}/pd-httpx"
            log_ok "${bin} installed"
        else
            log_warn "Failed to install ${bin} (non-critical)"
        fi
    done
}

# =============================================================================
# Repository setup
# =============================================================================
setup_repo() {
    section "Setting up repository"
    local in_repo=0
    [ -f "${PWD}/setup.py" ] && [ -d "${PWD}/itzraven" ] && in_repo=1

    [ "$in_repo" -eq 1 ] && [ "${PWD}" = "${REPO_DIR}" ] && { log_ok "Already in repository: ${REPO_DIR}"; return; }

    if [ -d "${REPO_DIR}/.git" ]; then
        log_ok "Repository already cloned at ${REPO_DIR}"
        [ "$in_repo" -eq 1 ] && [ "${PWD}" != "${REPO_DIR}" ] && { log_info "Syncing current dir to ${REPO_DIR}..."; maybe_sudo mkdir -p "$(dirname "$REPO_DIR")"; maybe_sudo cp -a "${PWD}/." "${REPO_DIR}/"; }
        return
    fi

    if [ "$in_repo" -eq 1 ]; then
        log_info "Current directory is the repository. Copying to ${REPO_DIR}..."
        maybe_sudo mkdir -p "$(dirname "$REPO_DIR")"
        maybe_sudo cp -a "${PWD}/." "${REPO_DIR}/"
        log_ok "Repository copied to ${REPO_DIR}"
        return
    fi

    log_info "Cloning ${REPO_URL} to ${REPO_DIR}..."
    maybe_sudo mkdir -p "$(dirname "$REPO_DIR")"
    maybe_sudo git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
    log_ok "Repository cloned to ${REPO_DIR}"
}

# =============================================================================
# Python virtual environment
# =============================================================================
setup_venv() {
    section "Setting up Python virtual environment"
    if [ -d "${VENV_DIR}" ] && [ -f "${VENV_DIR}/bin/python3" ]; then
        log_ok "Virtual environment already exists at ${VENV_DIR}"
    else
        log_info "Creating virtual environment at ${VENV_DIR}..."
        maybe_sudo python3 -m venv "${VENV_DIR}"
        log_ok "Virtual environment created"
    fi

    log_info "Upgrading pip..."
    maybe_sudo "${VENV_DIR}/bin/python3" -m pip install --upgrade pip -q
    log_ok "pip upgraded"

    log_info "Installing core dependencies from requirements.txt..."
    if [ -f "${REPO_DIR}/requirements.txt" ]; then
        maybe_sudo "${VENV_DIR}/bin/pip" install -r "${REPO_DIR}/requirements.txt" -q
        log_ok "Core dependencies installed"
    else
        log_warn "requirements.txt not found"
    fi

    log_info "Installing Itzraven package with web extras..."
    maybe_sudo "${VENV_DIR}/bin/pip" install -e "${REPO_DIR}[web]" -q
    log_ok "Itzraven package installed"

    if "${VENV_DIR}/bin/python3" -c "import playwright" &>/dev/null; then
        log_info "Installing Playwright browsers..."
        "${VENV_DIR}/bin/python3" -m playwright install chromium 2>/dev/null && log_ok "Playwright browser installed" || log_warn "Playwright browser install failed (non-critical)"
    fi
}

# =============================================================================
# Web dashboard build
# =============================================================================
build_web() {
    section "Building web dashboard"
    local web_dir="${REPO_DIR}/web-dashboard"
    [ ! -d "$web_dir" ] && { log_warn "web-dashboard not found, skipping"; return; }
    [ -f "${web_dir}/dist/index.html" ] && { log_ok "Web dashboard already built"; return; }

    log_info "Installing npm dependencies..."
    (cd "$web_dir" && npm install --silent 2>/dev/null) || (cd "$web_dir" && npm install) || { log_warn "npm install failed (non-critical)"; return; }
    log_ok "npm dependencies installed"

    log_info "Building web dashboard..."
    (cd "$web_dir" && npm run build 2>/dev/null) || (cd "$web_dir" && NODE_ENV=production npm run build) || { log_warn "npm run build failed (non-critical)"; return; }
    log_ok "Web dashboard built successfully"
}

# =============================================================================
# Itzraven command
# =============================================================================
create_itzraven_command() {
    section "Creating itzraven command"
    maybe_sudo mkdir -p "$BIN_DIR"

    local venv_itzraven="${VENV_DIR}/bin/itzraven"
    if [ ! -f "$venv_itzraven" ]; then
        log_error "itzraven binary not found in venv, re-installing..."
        maybe_sudo "${VENV_DIR}/bin/pip" install -e "${REPO_DIR}[web]" -q || { log_warn "Could not create itzraven command. Use: ${VENV_DIR}/bin/python3 -m itzraven"; return; }
    fi

    if [ ! -f "$venv_itzraven" ]; then
        log_warn "Creating wrapper script instead."
        maybe_sudo tee "$BIN_DIR/itzraven" > /dev/null <<'WRAPPER'
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python3" -m itzraven "$@"
WRAPPER
        maybe_sudo chmod +x "$BIN_DIR/itzraven"
    else
        maybe_sudo ln -sf "$venv_itzraven" "$BIN_DIR/itzraven"
    fi
    log_ok "itzraven command created at ${BIN_DIR}/itzraven"
}

# =============================================================================
# PATH setup
# =============================================================================
setup_path() {
    section "Setting up PATH"
    local cfg="$(shell_config)"
    local go_bin="$(go env GOPATH 2>/dev/null || echo "${HOME}/go")/bin"
    local path_line="export PATH=\"${BIN_DIR}:${go_bin}:\${PATH}\""
    local marker="# Added by Itzraven installer"

    if [ -f "$cfg" ] && grep -q "${BIN_DIR}" "$cfg" 2>/dev/null; then
        log_ok "PATH already configured in ${cfg}"
    else
        { echo ""; echo "$marker"; echo "$path_line"; } >> "$cfg"
        log_ok "Added ${BIN_DIR} and ${go_bin} to PATH in ${cfg}"
        log_info "Run: source ${cfg}"
    fi
    export PATH="${BIN_DIR}:${go_bin}:${PATH}"
}

# =============================================================================
# .env template
# =============================================================================
create_env_template() {
    section "Creating .env template"
    if [ -f "$ENV_FILE" ]; then
        log_ok ".env already exists at ${ENV_FILE}"
        grep -q "LLM_API_KEY" "$ENV_FILE" 2>/dev/null || log_warn "Your .env is missing LLM_API_KEY"
        return
    fi

    if [ -f "${REPO_DIR}/.env.example" ]; then
        maybe_sudo cp "${REPO_DIR}/.env.example" "$ENV_FILE"
    else
        maybe_sudo tee "$ENV_FILE" > /dev/null << 'ENVEOF'
# Itzraven Configuration
LLM_API_KEY=sk-your-api-key-here
# STRIX_LLM=openai/gpt-4o
ENVEOF
    fi
    log_ok ".env template created at ${ENV_FILE}"
    log_info "${YELLOW}IMPORTANT:${NC} Edit ${ENV_FILE} and set your LLM_API_KEY before running Itzraven."
}

# =============================================================================
# Nuclei templates update
# =============================================================================
update_nuclei_templates() {
    section "Updating Nuclei templates"
    if check_cmd nuclei; then
        log_info "Running nuclei -update-templates..."
        nuclei -update-templates 2>/dev/null && log_ok "Nuclei templates updated" || log_warn "Update failed (non-critical)"
    else
        log_warn "nuclei not in PATH, skipping"
    fi
}

# =============================================================================
# Verification
# =============================================================================
verify_install() {
    section "Verifying installation"
    local errors=0 go_bin="$(go env GOPATH)/bin"

    echo -e "  ${BOLD}Itzraven command:${NC}"
    check_cmd itzraven && echo -e "    $(which itzraven) → ${GREEN}OK${NC}" || { echo -e "    ${RED}NOT FOUND${NC} (run 'source $(shell_config)' and retry)"; errors=1; }

    echo -e "\n  ${BOLD}Go tools (${go_bin}):${NC}"
    for tool in pd-httpx naabu nuclei katana gau waybackurls; do
        if check_cmd "$tool"; then echo -e "    ${tool} → ${GREEN}$(which "$tool")${NC}"
        elif [ -f "${go_bin}/${tool}" ]; then echo -e "    ${tool} → ${YELLOW}${go_bin}/${tool} (not in PATH)${NC}"
        else echo -e "    ${tool} → ${RED}NOT FOUND${NC}"; errors=1; fi
    done

    echo -e "\n  ${BOLD}Python venv:${NC}"
    [ -f "${VENV_DIR}/bin/python3" ] && echo -e "    ${VENV_DIR} → ${GREEN}OK${NC} ($("${VENV_DIR}/bin/python3" --version 2>&1))" || { echo -e "    ${RED}NOT FOUND${NC}"; errors=1; }

    echo -e "\n  ${BOLD}Web dashboard:${NC}"
    [ -f "${REPO_DIR}/web-dashboard/dist/index.html" ] && echo -e "    ${GREEN}OK${NC}" || echo -e "    ${YELLOW}Not built (non-critical)${NC}"

    echo -e "\n  ${BOLD}Nuclei templates:${NC}"
    [ -d "${HOME}/nuclei-templates" ] && echo -e "    ${GREEN}OK${NC}" || echo -e "    ${YELLOW}Not updated (run 'nuclei -update-templates')${NC}"

    return "$errors"
}

# =============================================================================
# Uninstall
# =============================================================================
uninstall() {
    echo; echo -e "${RED}${BOLD}Uninstalling Itzraven...${NC}"; echo
    [ -f "${BIN_DIR}/itzraven" ] && { maybe_sudo rm -f "${BIN_DIR}/itzraven"; log_ok "Removed ${BIN_DIR}/itzraven"; }

    for cfg in "$HOME"/.bashrc "$HOME"/.zshrc "$HOME"/.bash_profile "$HOME"/.profile; do
        [ -f "$cfg" ] && grep -q "Added by Itzraven installer" "$cfg" 2>/dev/null && {
            maybe_sudo sed -i.bak '/# Added by Itzraven installer/{N;d;}' "$cfg" 2>/dev/null || true
            log_ok "Removed PATH entries from ${cfg}"; }
    done

    if [ -d "$INSTALL_DIR" ]; then
        echo -n -e "\n${YELLOW}Remove ${INSTALL_DIR}? [y/N]${NC} "; read -r confirm
        [ "$confirm" = "y" ] || [ "$confirm" = "Y" ] && { maybe_sudo rm -rf "$INSTALL_DIR"; log_ok "Removed ${INSTALL_DIR}"; } || log_info "Skipped removing ${INSTALL_DIR}"
    fi

    echo -e "\n${YELLOW}Go tools (pd-httpx, naabu, etc.) were NOT removed.${NC}"
    echo -e "${YELLOW}To remove: rm -f ~/go/bin/{pd-httpx,naabu,nuclei,katana,gau,waybackurls}${NC}"
    echo -e "${YELLOW}Shell config backups saved as .bak${NC}\n"
    echo -e "${GREEN}Itzraven has been uninstalled.${NC}"
    exit 0
}

# =============================================================================
# Usage / Summary
# =============================================================================
show_usage() {
    echo; echo -e "${BOLD}Usage:${NC}"
    echo "  curl -fsSL ${RAW_URL}/install.sh | bash"
    echo "  curl -fsSL ... | bash -s -- --prefix /opt/itzraven"
    echo "  curl -fsSL ... | bash -s -- --docker"
    echo "  curl -fsSL ... | bash -s -- --uninstall"
    echo; echo -e "${BOLD}Options:${NC}"
    echo "  --prefix DIR    Install to DIR (default: ${INSTALL_DIR})"
    echo "  --docker        Install via Docker (port 8484)"
    echo "  --uninstall     Remove Itzraven"
    echo "  --help, -h      Show this help"
    echo; echo -e "${BOLD}Env vars:${NC}  REPO_OWNER  REPO_NAME  INSTALL_DIR  BRANCH"; echo; exit 0
}

show_summary() {
    echo; echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Itzraven installed successfully!                ║${NC}"
    echo -e "${GREEN}║     See Everything. Miss Nothing.                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"; echo
    echo -e "${BOLD}Quick start (local):${NC}"
    echo -e "  1. Edit ${ENV_FILE} and add your LLM_API_KEY"
    echo -e "  2. Run: source $(shell_config)"
    echo -e "  3a. Full scan: itzraven strix --target https://example.com -m deep"
    echo -e "  3b. Swarm mode: itzraven swarm --target example.com --playbook bug-bounty"
    echo -e "  3c. MCP server: itzraven mcp serve"
    echo; echo -e "${BOLD}Quick start (Docker):${NC}"
    echo -e "  docker run -d --name itzraven -p 8484:8484 -e OPENAI_API_KEY=sk-... iamaworker135/itzraven:latest-ai"
    echo; echo -e "${BOLD}Commands:${NC}  itzraven strix | itzraven swarm | itzraven mcp | itzraven playbook"
    echo -e "${BOLD}Swarm playbooks:${NC}  bug-bounty  external-asm  ci-cd  ctf-solver"
    echo -e "${CYAN}Docs: https://github.com/${REPO_OWNER}/${REPO_NAME}${NC}"; echo
}

# =============================================================================
# Docker install
# =============================================================================
docker_install() {
    show_banner
    echo; echo -e "${CYAN}Installing Itzraven via Docker...${NC}"; echo

    if ! check_cmd docker; then
        log_error "Docker not found. Install Docker first: https://docs.docker.com/engine/install/"
        exit 1
    fi

    log_info "Pulling Itzraven Docker image..."
    docker pull iamaworker135/itzraven:latest-ai

    log_info "Starting Itzraven container on port 8484..."
    docker run -d --name itzraven -p 8484:8484 \
        -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
        -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
        iamaworker135/itzraven:latest-ai

    sleep 2
    if docker ps --filter "name=itzraven" --format "{{.Status}}" | grep -q "Up"; then
        log_ok "Itzraven is running at http://localhost:8484"
        echo; echo -e "${BOLD}Commands:${NC}"
        echo "  docker logs -f itzraven    # View logs"
        echo "  docker stop itzraven       # Stop Itzraven"
        echo "  docker start itzraven      # Start Itzraven"
        echo "  docker rm -f itzraven      # Remove container"
        echo; echo -e "${YELLOW}Set API keys in Docker env or .env file${NC}"
    else
        log_error "Container failed to start. Check: docker logs itzraven"
        exit 1
    fi
    exit 0
}

# =============================================================================
# Main
# =============================================================================
main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --uninstall) uninstall ;;
            --docker) docker_install ;;
            --prefix) shift; INSTALL_DIR="$1"; BIN_DIR="${INSTALL_DIR}/bin"; VENV_DIR="${INSTALL_DIR}/venv"; REPO_DIR="${INSTALL_DIR}/repo"; ENV_FILE="${INSTALL_DIR}/.env" ;;
            --help|-h) show_usage ;;
            *) echo -e "${RED}Unknown option: $1${NC}"; show_usage ;;
        esac
        shift
    done

    show_banner
    check_prereqs
    maybe_sudo mkdir -p "$INSTALL_DIR"
    install_system_deps
    install_go_tools
    setup_repo
    setup_venv
    create_itzraven_command
    setup_path
    create_env_template
    build_web || log_warn "Web dashboard build failed (non-critical)"
    update_nuclei_templates || true
    verify_install || true
    show_summary
}

main "$@"
