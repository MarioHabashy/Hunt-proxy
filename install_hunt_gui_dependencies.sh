#!/usr/bin/env bash
set -uo pipefail
# NOTE: intentionally NOT using `set -e` at the top level.
# With -e, a single failed package in a bulk `apt-get install` or
# `pip install` call kills the ENTIRE script immediately, silently
# skipping every step after it. That was the root cause of runs
# "finishing early" and needing a second run to finish the job.
# Every risky command below is wrapped in safe_run/retry helpers instead,
# so failures are logged and the script always runs to completion.

# Hunt GUI full dependency bootstrap (Linux)
# - Installs system packages used by the GUI and scanners
# - Creates/updates a project virtual environment
# - Installs Python dependencies imported by the codebase
# - Installs external CLI tools invoked by dashboard/tool runners
# - Prints a final readiness report, including anything that failed

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"

# Track failures so the final report is accurate even though nothing
# aborts the script anymore.
FAILED_APT=()
FAILED_PIP=()
FAILED_GO=()
FAILED_GIT=()

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

# Run a command, never let its failure kill the script, return its rc.
safe_run() {
  set +e
  "$@"
  local rc=$?
  set -e
  return "$rc"
}

# Retry a command up to N times (handles transient network blips on
# apt/pip/go index fetches, which is a common cause of one-off failures).
retry() {
  local attempts="$1"; shift
  local delay="$2"; shift
  local n=1
  until "$@"; do
    if [ "$n" -ge "$attempts" ]; then
      return 1
    fi
    warn "Command failed (attempt ${n}/${attempts}): $* -- retrying in ${delay}s"
    sleep "$delay"
    n=$((n + 1))
  done
  return 0
}

ensure_python3_available() {
  if have_cmd python3; then
    info "Python3 detected: $(python3 --version 2>/dev/null || echo python3)"
    return
  fi

  if have_cmd apt-get; then
    log "python3 not found. Installing Python 3"
    retry 3 5 run_with_sudo apt-get update
    retry 3 5 run_with_sudo apt-get install -y python3 python3-venv python3-pip
  fi

  if ! have_cmd python3; then
    warn "python3 is required but not available. Install Python 3 and rerun this script."
    exit 1
  fi
}

install_apt_packages() {
  # NOTE: libgmp-dev/libmpfr-dev/libmpc-dev added so gmpy2 can build
  # from source later if no prebuilt wheel is available for this platform.
  local pkgs=(
    python3 python3-venv python3-pip python3-dev
    build-essential libssl-dev libffi-dev
    libgmp-dev libmpfr-dev libmpc-dev
    git curl wget jq unzip ca-certificates
    whois dnsutils
    nmap nikto gobuster ffuf feroxbuster
    wpscan joomscan amass subjack eyewitness
  )

  if ! have_cmd apt-get; then
    warn "apt-get not found. Install these packages manually:"
    info "${pkgs[*]}"
    return
  fi

  log "Updating apt package index"
  if ! retry 3 5 run_with_sudo apt-get update; then
    warn "apt-get update failed after retries. Package installs below may fail too."
  fi

  log "Installing apt packages (one at a time, so one missing/renamed package can't block the rest)"
  for pkg in "${pkgs[@]}"; do
    if safe_run retry 2 3 run_with_sudo apt-get install -y "$pkg"; then
      info "OK: $pkg"
    else
      warn "Failed to install apt package: $pkg (continuing)"
      FAILED_APT+=("$pkg")
    fi
  done
}

install_go_if_needed() {
  if have_cmd go; then
    info "Go already installed: $(go version)"
    return
  fi

  if have_cmd apt-get; then
    log "Installing Go compiler"
    if ! safe_run retry 3 5 run_with_sudo apt-get install -y golang-go; then
      warn "Failed to install golang-go via apt. Go-based recon tools will be skipped."
    fi
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

pip_install_one() {
  local pkg="$1"
  if safe_run retry 2 5 python3 -m pip install "$pkg"; then
    info "OK: $pkg"
    return 0
  else
    warn "Failed to pip install: $pkg (continuing)"
    FAILED_PIP+=("$pkg")
    return 1
  fi
}

setup_venv_and_python_deps() {
  log "Setting up Python virtual environment"
  if ! safe_run python3 -m venv "$VENV_DIR"; then
    warn "Failed to create virtualenv at $VENV_DIR. Aborting Python dependency install."
    return
  fi
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"

  safe_run python3 -m pip install --upgrade pip setuptools wheel

  log "Installing Python packages required by source imports (one at a time)"
  local core_pkgs=(
    PyQt5
    requests
    urllib3
    beautifulsoup4
    mitmproxy
    cryptography
    regex
    keyring
    pyOpenSSL
    gmpy2
    brotli
    zstandard
    websocket-client
    wsproto
    pyngrok
    boto3
    stripe
  )
  for pkg in "${core_pkgs[@]}"; do
    pip_install_one "$pkg"
  done

  log "Installing Python CLI tools used by dashboard (one at a time)"
  local cli_pkgs=(
    wafw00f
    waymore
    uro
    paramspider
  )
  for pkg in "${cli_pkgs[@]}"; do
    pip_install_one "$pkg"
  done

  # trufflehog's PyPI package is deprecated in favor of the Go binary
  # (installed separately below as a git/go tool where possible). Skip
  # the broken pip package instead of letting it fail the whole batch.
  info "Skipping 'trufflehog' via pip (PyPI package is deprecated); install via:"
  info "  https://github.com/trufflesecurity/trufflehog#installation"

  deactivate
}

install_go_tool() {
  local module="$1"
  if ! have_cmd go; then
    warn "Skipping go install ${module} (Go not available)"
    FAILED_GO+=("$module")
    return
  fi

  if safe_run retry 2 5 go install "$module"; then
    info "Installed: ${module}"
  else
    warn "Failed to install Go tool: ${module}"
    FAILED_GO+=("$module")
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

git_clone_tool() {
  local url="$1"
  local dest="$2"
  if [ -d "$dest" ]; then
    info "Already present: $dest"
    return 0
  fi
  if safe_run retry 2 5 git clone "$url" "$dest"; then
    info "Cloned: $url"
    return 0
  else
    warn "Failed to clone: $url"
    FAILED_GIT+=("$url")
    return 1
  fi
}

install_git_tools() {
  local tools_dir="${HOME}/tools"
  mkdir -p "$tools_dir"

  log "Installing repo-based tools"

  git_clone_tool "https://github.com/GerbenJavado/LinkFinder.git" "${tools_dir}/LinkFinder"

  if [ -f "${tools_dir}/LinkFinder/requirements.txt" ]; then
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    if ! safe_run python3 -m pip install -r "${tools_dir}/LinkFinder/requirements.txt"; then
      warn "Failed to install LinkFinder's requirements.txt"
    fi
    deactivate
  fi

  git_clone_tool "https://github.com/Tuhinshubhra/CMSeeK" "${tools_dir}/CMSeeK"
  git_clone_tool "https://github.com/initstring/cloud_enum.git" "${tools_dir}/cloud_enum"
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

  # --- Consolidated failure summary (this is new: previously a single
  # failure would just kill the script with no summary at all) ---
  if [ "${#FAILED_APT[@]}" -gt 0 ] || [ "${#FAILED_PIP[@]}" -gt 0 ] || \
     [ "${#FAILED_GO[@]}" -gt 0 ] || [ "${#FAILED_GIT[@]}" -gt 0 ]; then
    warn "Some install steps failed and were skipped:"
    [ "${#FAILED_APT[@]}" -gt 0 ] && info "apt packages: ${FAILED_APT[*]}"
    [ "${#FAILED_PIP[@]}" -gt 0 ] && info "pip packages: ${FAILED_PIP[*]}"
    [ "${#FAILED_GO[@]}" -gt 0 ] && info "go tools: ${FAILED_GO[*]}"
    [ "${#FAILED_GIT[@]}" -gt 0 ] && info "git clones: ${FAILED_GIT[*]}"
    info "Re-running this script is safe (already-installed items are skipped fast)"
    info "and will retry only what's still missing."
  else
    log "No install failures recorded this run."
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