#!/usr/bin/env bash
set -euo pipefail

# Hunt GUI full dependency bootstrap (Linux)
# - Installs system packages used by the GUI and scanners
# - Creates/updates a project virtual environment
# - Installs Python dependencies imported by the codebase
# - Installs external CLI tools invoked by dashboard/tool runners
# - Prints a final readiness report

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"

log() { printf "\n[+] %s\n" "$*"; }
warn() { printf "\n[!] %s\n" "$*"; }
info() { printf "    %s\n" "$*"; }

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_with_sudo() {
  if have_cmd sudo; then
    sudo "$@"
  else
    "$@"
  fi
}

safe_run() {
  set +e
  "$@"
  local rc=$?
  set -e
  return "$rc"
}

ensure_python3_available() {
  if have_cmd python3; then
    info "Python3 detected: $(python3 --version 2>/dev/null || echo python3)"
    return
  fi

  if have_cmd apt-get; then
    log "python3 not found. Installing Python 3"
    run_with_sudo apt-get update
    run_with_sudo apt-get install -y python3 python3-venv python3-pip
  fi

  if ! have_cmd python3; then
    warn "python3 is required but not available. Install Python 3 and rerun this script."
    exit 1
  fi
}

install_apt_packages() {
  local pkgs=(
    python3 python3-venv python3-pip python3-dev
    build-essential libssl-dev libffi-dev
    git curl wget jq unzip ca-certificates
    whois dnsutils
    nmap nikto gobuster ffuf feroxbuster
    wpscan joomscan amass subjack eyewitness
  )

  if have_cmd apt-get; then
    log "Installing apt packages"
    run_with_sudo apt-get update
    run_with_sudo apt-get install -y "${pkgs[@]}"
  else
    warn "apt-get not found. Install these packages manually:"
    info "${pkgs[*]}"
  fi
}

install_go_if_needed() {
  if have_cmd go; then
    info "Go already installed: $(go version)"
    return
  fi

  if have_cmd apt-get; then
    log "Installing Go compiler"
    run_with_sudo apt-get install -y golang-go
  else
    warn "Go is required for many recon tools. Please install Go manually."
  fi
}

ensure_go_path() {
  local gopath_bin
  if have_cmd go; then
    gopath_bin="$(go env GOPATH)/bin"
    export PATH="${PATH}:${gopath_bin}"
    for rc in "${HOME}/.zshrc" "${HOME}/.bashrc"; do
      if [ -f "$rc" ] && ! grep -q 'GOPATH/bin' "$rc"; then
        printf '\nexport PATH="$PATH:$(go env GOPATH)/bin"\n' >> "$rc"
      fi
    done
  fi
}

setup_venv_and_python_deps() {
  log "Setting up Python virtual environment"
  python3 -m venv "$VENV_DIR"
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"

  python3 -m pip install --upgrade pip setuptools wheel

  log "Installing Python packages required by source imports"
  python3 -m pip install \
    PyQt5 \
    requests \
    urllib3 \
    beautifulsoup4 \
    mitmproxy \
    cryptography \
    regex \
    keyring \
    pyOpenSSL

  log "Installing Python CLI tools used by dashboard"
  python3 -m pip install \
    wafw00f \
    waymore \
    uro \
    paramspider \
    trufflehog

  deactivate
}

install_go_tool() {
  local module="$1"
  if ! have_cmd go; then
    warn "Skipping go install ${module} (Go not available)"
    return
  fi

  if safe_run go install "$module"; then
    info "Installed: ${module}"
  else
    warn "Failed to install Go tool: ${module}"
  fi
}

install_go_tools() {
  log "Installing Go-based tools"
  install_go_tool github.com/projectdiscovery/katana/cmd/katana@latest
  install_go_tool github.com/projectdiscovery/httpx/cmd/httpx@latest
  install_go_tool github.com/tomnomnom/waybackurls@latest
  install_go_tool github.com/lc/gau/v2/cmd/gau@latest
  install_go_tool github.com/bp0lr/gauplus@latest
  install_go_tool github.com/hakluke/hakrawler@latest
  install_go_tool github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  install_go_tool github.com/jaeles-project/gospider@latest
  install_go_tool github.com/edoardottt/cariddi/cmd/cariddi@latest
  install_go_tool github.com/Josue87/roboxtractor@latest
  install_go_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  install_go_tool github.com/owasp-amass/amass/v4/...@master
}

install_git_tools() {
  local tools_dir="${HOME}/tools"
  mkdir -p "$tools_dir"

  log "Installing repo-based tools"

  if [ ! -d "${tools_dir}/LinkFinder" ]; then
    safe_run git clone https://github.com/GerbenJavado/LinkFinder.git "${tools_dir}/LinkFinder" || true
  fi

  if [ -f "${tools_dir}/LinkFinder/requirements.txt" ]; then
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    safe_run python3 -m pip install -r "${tools_dir}/LinkFinder/requirements.txt" || true
    deactivate
  fi

  if [ ! -d "${tools_dir}/CMSeeK" ]; then
    safe_run git clone https://github.com/Tuhinshubhra/CMSeeK "${tools_dir}/CMSeeK" || true
  fi

  if [ ! -d "${tools_dir}/cloud_enum" ]; then
    safe_run git clone https://github.com/initstring/cloud_enum.git "${tools_dir}/cloud_enum" || true
  fi
}

print_manual_tools_notice() {
  cat <<'EOF'

[!] Some commands referenced by the GUI are ecosystem-specific and may require
    manual installation depending on your distro/toolchain:
    - ipinfo, wad, cmseek, waymore, github-endpoints, github-subdomains,
      gitdorks_go, emailfinder, metafinder, findomain, altdns, byp4xx, smap,
      droopescan, cloud_enum

    The GUI can still run without them, but the corresponding dashboard tasks
    will fail until those commands are available in PATH.
EOF
}

readiness_report() {
  log "Dependency readiness report"

  local required_commands=(
    mitmdump
    curl
    whois
    nmap
    nikto
    gobuster
    ffuf
    feroxbuster
    wpscan
    joomscan
    amass
    subjack
    eyewitness
    katana
    httpx
    waybackurls
    gau
    gauplus
    hakrawler
    nuclei
    gospider
    cariddi
    roboxtractor
    subfinder
    wafw00f
    waymore
    uro
    paramspider
  )

  local missing=()
  for cmd in "${required_commands[@]}"; do
    if have_cmd "$cmd"; then
      info "OK: $cmd"
    else
      info "MISSING: $cmd"
      missing+=("$cmd")
    fi
  done

  if [ "${#missing[@]}" -eq 0 ]; then
    log "All required baseline dependencies are available."
  else
    warn "Missing ${#missing[@]} commands. Install them, then rerun this script."
  fi

  cat <<EOF

Next steps:
  1) Activate virtualenv for GUI runtime:
     source "${VENV_DIR}/bin/activate"
  2) Start the GUI:
      python3 "${ROOT_DIR}/hunt_gui.py"
EOF
}

main() {
  log "Bootstrapping Hunt GUI dependencies on Linux"
  install_apt_packages
  ensure_python3_available
  install_go_if_needed
  ensure_go_path
  setup_venv_and_python_deps
  install_go_tools
  install_git_tools
  print_manual_tools_notice
  readiness_report
}

main "$@"
