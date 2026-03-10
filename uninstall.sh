#!/usr/bin/env bash
set -euo pipefail

# rusthole uninstaller

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

[[ $EUID -eq 0 ]] || { echo -e "${RED}[x]${NC} Run as root" >&2; exit 1; }

# Stop and disable service
if systemctl is-active rusthole &>/dev/null; then
    systemctl stop rusthole
    info "Stopped rusthole service"
fi
if systemctl is-enabled rusthole &>/dev/null; then
    systemctl disable rusthole
    info "Disabled rusthole service"
fi

# Remove service file
rm -f /etc/systemd/system/rusthole.service
systemctl daemon-reload 2>/dev/null || true
info "Removed systemd service"

# Remove binary
rm -f /usr/local/bin/rusthole
info "Removed binary"

# Ask about data
echo ""
warn "Config and data are preserved:"
warn "  Config: /etc/rusthole/"
warn "  Data:   /var/lib/rusthole/"
echo ""
read -rp "Remove config and data too? [y/N] " answer
if [[ "${answer,,}" == "y" ]]; then
    rm -rf /etc/rusthole /var/lib/rusthole
    info "Removed config and data"
fi

# Remove user
if id rusthole &>/dev/null; then
    userdel rusthole 2>/dev/null || true
    info "Removed rusthole user"
fi

info "rusthole uninstalled."
