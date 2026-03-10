#!/usr/bin/env bash
set -euo pipefail

# rusthole installer
# Usage: curl -fsSL https://raw.githubusercontent.com/KevinKickass/rusthole/main/install.sh | sudo bash

REPO="KevinKickass/rusthole"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rusthole"
DATA_DIR="/var/lib/rusthole"
SERVICE_USER="rusthole"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# --- Pre-flight checks ---

[[ $EUID -eq 0 ]] || error "Run as root: curl -fsSL ... | sudo bash"

command -v curl >/dev/null 2>&1 || error "curl is required but not installed"

# --- Detect architecture ---

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case "$ARCH" in
    x86_64|amd64)   SUFFIX="linux-amd64-static" ;;
    aarch64|arm64)   SUFFIX="linux-arm64" ;;
    *)               error "Unsupported architecture: $ARCH" ;;
esac

case "$OS" in
    linux)  ;;
    darwin)
        case "$ARCH" in
            x86_64|amd64) SUFFIX="macos-amd64" ;;
            aarch64|arm64) SUFFIX="macos-arm64" ;;
        esac
        ;;
    *)  error "Unsupported OS: $OS" ;;
esac

info "Detected: $OS/$ARCH -> rusthole-$SUFFIX"

# --- Get latest release ---

info "Fetching latest release from GitHub..."
LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
[[ -n "$LATEST" ]] || error "Could not determine latest release"
info "Latest release: $LATEST"

# --- Download binary ---

URL="https://github.com/$REPO/releases/download/$LATEST/rusthole-$SUFFIX"
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

info "Downloading rusthole-$SUFFIX..."
curl -fsSL -o "$TMPFILE" "$URL" || error "Download failed. Check $URL"

chmod +x "$TMPFILE"

# Quick sanity check
"$TMPFILE" --version 2>/dev/null || warn "Binary doesn't support --version (that's okay)"

# --- Install binary ---

install -m 0755 "$TMPFILE" "$INSTALL_DIR/rusthole"
info "Installed to $INSTALL_DIR/rusthole"

# --- Create user ---

if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || true
    info "Created system user: $SERVICE_USER"
fi

# --- Create directories ---

mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

# --- Default config ---

if [[ ! -f "$CONFIG_DIR/rusthole.toml" ]]; then
    cat > "$CONFIG_DIR/rusthole.toml" << 'TOML'
[dns]
listen = "0.0.0.0:53"
upstream = ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"]

[web]
listen = "0.0.0.0:8080"

[database]
path = "/var/lib/rusthole/rusthole.db"

[blocklists]
urls = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
]
update_interval_hours = 24
TOML
    info "Created default config at $CONFIG_DIR/rusthole.toml"
else
    warn "Config already exists at $CONFIG_DIR/rusthole.toml — not overwriting"
fi

# --- systemd service ---

if [[ -d /etc/systemd/system ]]; then
    cat > /etc/systemd/system/rusthole.service << EOF
[Unit]
Description=rusthole DNS sinkhole
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/rusthole --config $CONFIG_DIR/rusthole.toml
WorkingDirectory=$DATA_DIR
Restart=on-failure
RestartSec=5

# Hardening
ProtectSystem=strict
ReadWritePaths=$DATA_DIR
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes

# DNS needs port 53
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    info "Created systemd service: rusthole.service"
    info ""
    info "To start:   systemctl start rusthole"
    info "To enable:  systemctl enable rusthole"
    info "Dashboard:  http://$(hostname -I | awk '{print $1}'):8080"
else
    warn "No systemd found — you'll need to start rusthole manually:"
    warn "  $INSTALL_DIR/rusthole --config $CONFIG_DIR/rusthole.toml"
fi

# --- Raspberry Pi specific hints ---

if grep -qi 'raspberry\|bcm2' /proc/cpuinfo 2>/dev/null; then
    info ""
    info "Raspberry Pi detected! To use as your network DNS:"
    info "  1. systemctl enable --now rusthole"
    info "  2. Point your router's DNS to $(hostname -I | awk '{print $1}')"
    info "  3. Or per device: set DNS to $(hostname -I | awk '{print $1}')"
fi

info ""
info "rusthole $LATEST installed successfully."
