#!/usr/bin/env bash
set -uo pipefail

# Hunt-Proxy Core Dependency Installer
# This script installs only the essential dependencies for Hunt-Proxy
# and clones the tool from GitHub to /usr/share/hunt-proxy

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/share/hunt-proxy"
VENV_DIR="${INSTALL_DIR}/.venv"
DESKTOP_DIR="/usr/share/applications"
BIN_DIR="/usr/local/bin"

# Track failures
FAILED_APT=()
FAILED_PIP=()
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

safe_run() {
  set +e
  "$@"
  local rc=$?
  set -e
  return "$rc"
}

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
  local pkgs=(
    python3 python3-venv python3-pip python3-dev
    build-essential libssl-dev libffi-dev
    git curl wget unzip ca-certificates
    # Additional tools needed for Hunt-Proxy
    dnsutils net-tools
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

  log "Installing apt packages"
  for pkg in "${pkgs[@]}"; do
    if safe_run retry 2 3 run_with_sudo apt-get install -y "$pkg"; then
      info "OK: $pkg"
    else
      warn "Failed to install apt package: $pkg (continuing)"
      FAILED_APT+=("$pkg")
    fi
  done
}

setup_venv_and_python_deps() {
  log "Setting up Python virtual environment"
  if ! safe_run python3 -m venv "$VENV_DIR"; then
    warn "Failed to create virtualenv at $VENV_DIR. Aborting Python dependency install."
    return
  fi
  
  source "${VENV_DIR}/bin/activate"
  
  safe_run python3 -m pip install --upgrade pip setuptools wheel

  log "Installing Hunt-Proxy Python dependencies"
  
  # Core dependencies for Hunt-Proxy
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
	botocore
	stripe
  )

  for pkg in "${core_pkgs[@]}"; do
    if safe_run retry 2 5 python3 -m pip install "$pkg"; then
      info "OK: $pkg"
    else
      warn "Failed to pip install: $pkg (continuing)"
      FAILED_PIP+=("$pkg")
    fi
  done
  
  # Install any additional requirements if present
  if [ -f "${INSTALL_DIR}/requirements.txt" ]; then
    log "Installing from requirements.txt"
    if ! safe_run python3 -m pip install -r "${INSTALL_DIR}/requirements.txt"; then
      warn "Failed to install requirements.txt"
    fi
  fi
  
  deactivate
}

clone_hunt_proxy() {
  log "Cloning Hunt-Proxy to ${INSTALL_DIR}"
  
  # Check if already installed
  if [ -d "${INSTALL_DIR}/.git" ]; then
    info "Hunt-Proxy already cloned, pulling latest changes"
    (cd "${INSTALL_DIR}" && run_with_sudo git pull)
    return 0
  fi
  
  # Clone the repository
  if safe_run run_with_sudo git clone https://github.com/marioHabashy/hunt-proxy.git "${INSTALL_DIR}"; then
    info "Successfully cloned Hunt-Proxy"
    # Set proper permissions
    run_with_sudo chown -R $(whoami):$(whoami) "${INSTALL_DIR}" 2>/dev/null || true
    return 0
  else
    warn "Failed to clone Hunt-Proxy"
    FAILED_GIT+=("hunt-proxy")
    return 1
  fi
}

create_desktop_entry() {
  log "Creating desktop entry for Hunt-Proxy"
  
  local desktop_file="${DESKTOP_DIR}/hunt-proxy.desktop"
  local logo_path="${INSTALL_DIR}/logo.png"          # Your actual logo from the repo
  local icon_path="/usr/share/icons/hunt-proxy.png"  # Where we copy it for the system

  # Check if logo.png exists in the cloned repository
  if [ -f "${logo_path}" ]; then
    info "Using logo from repository: ${logo_path}"
    run_with_sudo cp "${logo_path}" "${icon_path}"
    final_icon="${icon_path}"
  else
    warn "logo.png not found in repository. Creating fallback icon."
    # Create fallback icon only if logo is missing
    if have_cmd python3; then
      python3 -c "
from PIL import Image, ImageDraw, ImageFont
img = Image.new('RGB', (256, 256), color='#2b2b2b')
d = ImageDraw.Draw(img)
d.text((128, 128), 'HP', fill='#00ff00', anchor='mm')
img.save('${INSTALL_DIR}/fallback-icon.png')
" 2>/dev/null || true
      final_icon="${INSTALL_DIR}/fallback-icon.png"
    else
      final_icon="utilities-terminal"  # System default fallback
    fi
  fi

  # Create desktop entry using the final icon
  cat > /tmp/hunt-proxy.desktop <<EOF
[Desktop Entry]
Name=Hunt-Proxy
Comment=Web Application Penetration Testing Proxy
Exec=${BIN_DIR}/hunt-proxy
Icon=${final_icon}
Terminal=false
Type=Application
Categories=Development;Network;Security;
StartupNotify=false
EOF

  run_with_sudo mv /tmp/hunt-proxy.desktop "${desktop_file}"
  run_with_sudo chmod +x "${desktop_file}"
  
  create_launcher_script
  info "Desktop entry created with icon: ${final_icon}"
}

create_launcher_script() {
  local launcher="${BIN_DIR}/hunt-proxy"
  
  cat > /tmp/hunt-proxy <<EOF
#!/bin/bash
source "${VENV_DIR}/bin/activate"
python3 "${INSTALL_DIR}/main.py" "\$@"
EOF

  run_with_sudo mv /tmp/hunt-proxy "${launcher}"
  run_with_sudo chmod +x "${launcher}"
}

create_uninstall_script() {
  log "Creating uninstall script"
  
  cat > /tmp/uninstall-hunt-proxy.sh <<EOF
#!/bin/bash
echo "Removing Hunt-Proxy..."
sudo rm -rf ${INSTALL_DIR}
sudo rm -f ${BIN_DIR}/hunt-proxy
sudo rm -f ${DESKTOP_DIR}/hunt-proxy.desktop
echo "Hunt-Proxy uninstalled"
EOF

  run_with_sudo mv /tmp/uninstall-hunt-proxy.sh "${INSTALL_DIR}/uninstall.sh"
  run_with_sudo chmod +x "${INSTALL_DIR}/uninstall.sh"
}

readiness_report() {
  log "Hunt-Proxy Installation Complete"
  
  # Check for required commands
  local required_commands=(
    python3
    pip3
    git
    curl
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
    log "All required dependencies are available."
  else
    warn "Missing ${#missing[@]} commands. Install them then rerun this script."
  fi
  
  # Summary of any failures
  if [ "${#FAILED_APT[@]}" -gt 0 ] || [ "${#FAILED_PIP[@]}" -gt 0 ] || [ "${#FAILED_GIT[@]}" -gt 0 ]; then
    warn "Some install steps failed:"
    [ "${#FAILED_APT[@]}" -gt 0 ] && info "apt packages: ${FAILED_APT[*]}"
    [ "${#FAILED_PIP[@]}" -gt 0 ] && info "pip packages: ${FAILED_PIP[*]}"
    [ "${#FAILED_GIT[@]}" -gt 0 ] && info "git clones: ${FAILED_GIT[*]}"
  else
    log "All installations completed successfully!"
  fi

  cat <<EOF

Installation Location: ${INSTALL_DIR}
Virtual Environment: ${VENV_DIR}
Desktop Launcher: Hunt-Proxy (available in application menu)

To run Hunt-Proxy:
  1. From terminal: hunt-proxy
  2. From desktop: Search for "Hunt-Proxy" in applications
EOF
}

main() {
  log "Installing Hunt-Proxy Core Dependencies"
  
  # Install system packages
  install_apt_packages
  ensure_python3_available
  
  # Clone the tool
  clone_hunt_proxy
  
  # Setup Python environment
  setup_venv_and_python_deps
  
  # Create desktop integration
  create_desktop_entry
  create_uninstall_script
  
  # Final report
  readiness_report
}

main "$@"