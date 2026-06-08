#!/usr/bin/env bash
# Snypshark installer — Debian/Ubuntu and Arch Linux
# Usage:
#   ./install.sh              # install (system-wide command, requires sudo for sys deps)
#   ./install.sh --user       # install to ~/.local/bin (no sudo needed for command link)
#   ./install.sh --uninstall  # remove command link and venv

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
SYSTEM_BIN="/usr/local/bin/snypshark"
USER_BIN="${HOME}/.local/bin/snypshark"

# --- Colour helpers ---
_red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }

log()   { _green  "[+] $*"; }
warn()  { _yellow "[!] $*"; }
error() { _red    "[ERROR] $*"; exit 1; }

# --- Distro detection ---
detect_distro() {
    if [[ -f /etc/debian_version ]] || command -v apt-get &>/dev/null; then
        echo "debian"
    elif [[ -f /etc/arch-release ]] || command -v pacman &>/dev/null; then
        echo "arch"
    else
        echo "unknown"
    fi
}

# --- System dependency installation ---
install_deps_debian() {
    log "Detected: Debian / Ubuntu / Mint"
    log "Updating package lists..."
    sudo apt-get update -q

    log "Installing: python3 python3-pip python3-venv tshark"
    # Pre-answer the tshark debconf prompt so it does not block
    echo "wireshark-common wireshark-common/install-setuid boolean true" \
        | sudo debconf-set-selections
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv tshark
}

install_deps_arch() {
    log "Detected: Arch Linux / Manjaro"
    log "Synchronising package database..."
    sudo pacman -Sy --noconfirm

    log "Installing: python python-pip wireshark-cli"
    # python-venv is bundled with python on Arch
    sudo pacman -S --noconfirm python python-pip wireshark-cli
}

install_system_deps() {
    local distro
    distro="$(detect_distro)"

    case "$distro" in
        debian) install_deps_debian ;;
        arch)   install_deps_arch   ;;
        *)
            warn "Could not detect a supported package manager."
            warn "Please ensure these are installed before continuing:"
            warn "  python3 (>= 3.8)  python3-pip  python3-venv  tshark"
            read -rp "Continue anyway? [y/N] " answer
            [[ "${answer,,}" == "y" ]] || exit 1
            ;;
    esac
}

# --- Python virtual environment ---
setup_venv() {
    if [[ -d "$VENV_DIR" ]]; then
        warn "Existing venv found at ${VENV_DIR} — removing and recreating."
        rm -rf "$VENV_DIR"
    fi

    log "Creating virtual environment: ${VENV_DIR}"
    python3 -m venv "$VENV_DIR"

    log "Upgrading pip..."
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet

    log "Installing Snypshark and Python dependencies..."
    "$VENV_DIR/bin/pip" install -e "$PROJECT_DIR" --quiet
}

# --- Command wrapper ---
install_system_command() {
    local venv_bin="${VENV_DIR}/bin/snypshark"
    [[ -f "$venv_bin" ]] || error "Entry point not found at ${venv_bin}. Check setup.py."

    log "Installing command to ${SYSTEM_BIN} (requires sudo)..."
    sudo tee "$SYSTEM_BIN" > /dev/null <<EOF
#!/usr/bin/env bash
exec "${venv_bin}" "\$@"
EOF
    sudo chmod +x "$SYSTEM_BIN"
    log "Command available: snypshark"
}

install_user_command() {
    local venv_bin="${VENV_DIR}/bin/snypshark"
    [[ -f "$venv_bin" ]] || error "Entry point not found at ${venv_bin}. Check setup.py."

    mkdir -p "${HOME}/.local/bin"
    tee "$USER_BIN" > /dev/null <<EOF
#!/usr/bin/env bash
exec "${venv_bin}" "\$@"
EOF
    chmod +x "$USER_BIN"
    log "Command installed to ${USER_BIN}"

    # Check PATH
    if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
        warn "~/.local/bin is not in your PATH."
        warn "Add this line to your ~/.bashrc or ~/.zshrc:"
        warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# --- Wireshark group ---
add_wireshark_group() {
    local target_user="${SUDO_USER:-$USER}"
    if getent group wireshark &>/dev/null; then
        log "Adding '${target_user}' to the wireshark group for non-root capture..."
        sudo usermod -aG wireshark "$target_user"
        warn "Group change takes effect after re-login."
        warn "For this session run: newgrp wireshark"
    fi
}

# --- Uninstall ---
do_uninstall() {
    log "Uninstalling Snypshark..."

    if [[ -f "$SYSTEM_BIN" ]]; then
        sudo rm -f "$SYSTEM_BIN"
        log "Removed ${SYSTEM_BIN}"
    fi

    if [[ -f "$USER_BIN" ]]; then
        rm -f "$USER_BIN"
        log "Removed ${USER_BIN}"
    fi

    if [[ -d "$VENV_DIR" ]]; then
        rm -rf "$VENV_DIR"
        log "Removed ${VENV_DIR}"
    fi

    log "Uninstall complete."
    exit 0
}

# --- Main ---

USER_MODE=false

for arg in "$@"; do
    case "$arg" in
        --uninstall) do_uninstall ;;
        --user)      USER_MODE=true ;;
        --help|-h)
            echo "Usage: ./install.sh [--user] [--uninstall]"
            echo ""
            echo "  (no flags)    Install system-wide to /usr/local/bin (uses sudo)"
            echo "  --user        Install to ~/.local/bin (no sudo for command link)"
            echo "  --uninstall   Remove command link and venv"
            exit 0
            ;;
        *)
            error "Unknown argument: ${arg}. Use --help for usage."
            ;;
    esac
done

echo ""
log "Snypshark Installer"
log "Project directory: ${PROJECT_DIR}"
echo ""

if [[ "$USER_MODE" == false ]]; then
    install_system_deps
fi

setup_venv

if [[ "$USER_MODE" == true ]]; then
    install_user_command
else
    install_system_command
    add_wireshark_group
fi

echo ""
log "Installation complete."
echo ""
echo "  Get started:"
echo "    snypshark --help"
echo "    snypshark capture.pcap"
echo "    snypshark capture.pcap --batch --security --export json"
echo ""
