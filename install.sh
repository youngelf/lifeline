#!/usr/bin/env bash
# ==============================================================================
# Lifeline Installer for Ubuntu 26.04
# Author: Vikram Aggarwal
# License: GNU General Public License v3.0 or later (GPL-3.0-or-later)
# Bug fixes, cleanups, and feature improvements are warmly encouraged.
# ==============================================================================
# Installs the Python 3 stdlib package to /opt/lifeline/src, creates wrapper
# binaries in /usr/local/bin and /usr/local/libexec, copies example configs
# into /etc/lifeline/ (never overwriting existing configs), and registers the
# systemd unit + AppArmor local drop-in.
#
# Usage:
#   sudo ./install.sh             # Install and enable lifeline.service
#   sudo ./install.sh --dry-run   # Print actions without modifying the system
#   sudo ./install.sh --uninstall # Remove binaries/service (keeps /etc/lifeline)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPT_DIR="/opt/lifeline"
ETC_DIR="/etc/lifeline"
BIN_DIR="/usr/local/bin"
LIBEXEC_DIR="/usr/local/libexec"
SYSTEMD_DIR="/etc/systemd/system"
APPARMOR_LOCAL_DIR="/etc/apparmor.d/local"
MAN_DIR="/usr/local/share/man/man8"

DRY_RUN=0
UNINSTALL=0

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[DRY-RUN] $*"
    else
        "$@"
    fi
}

if [[ "$DRY_RUN" -eq 0 && "$EUID" -ne 0 ]]; then
    echo "Please run as root (e.g. sudo $0)" >&2
    exit 1
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
    echo "Uninstalling lifeline..."
    run systemctl disable --now lifeline.service || true
    run rm -f "$SYSTEMD_DIR/lifeline.service"
    run rm -f "$BIN_DIR/lifelined" "$BIN_DIR/lifelinectl" "$BIN_DIR/lifeline-tray" "$LIBEXEC_DIR/lifeline-lease-hook"
    run rm -rf "$OPT_DIR"
    run rm -f "$APPARMOR_LOCAL_DIR/usr.sbin.dnsmasq"
    run rm -f "$MAN_DIR/lifeline.8" "$MAN_DIR/lifelinectl.8" "$MAN_DIR/lifelined.8"
    run systemctl daemon-reload
    echo "Removed binaries and service. Preserved $ETC_DIR (remove manually if desired)."
    exit 0
fi

echo "Checking prerequisites (python3, dnsmasq-base, nftables, iproute2)..."
for cmd in python3 dnsmasq nft ip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required tool '$cmd'. Install packages: sudo apt install -y python3 dnsmasq-base nftables iproute2" >&2
        exit 1
    fi
done

echo "Installing lifeline source to $OPT_DIR/src ..."
run mkdir -p "$OPT_DIR/src" "$ETC_DIR/hosts.d" "$BIN_DIR" "$LIBEXEC_DIR"
run rm -rf "$OPT_DIR/src/lifeline"
run cp -r "$SCRIPT_DIR/src/lifeline" "$OPT_DIR/src/"

write_wrapper() {
    local target="$1"
    local module="$2"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[DRY-RUN] write wrapper $target -> python3 -m $module"
        return
    fi
    cat >"$target" <<EOF
#!/bin/sh
PYTHONPATH="$OPT_DIR/src\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHONPATH
exec /usr/bin/python3 -m $module "\$@"
EOF
    chmod 0755 "$target"
}

write_wrapper "$BIN_DIR/lifelined" "lifeline.daemon"
write_wrapper "$BIN_DIR/lifelinectl" "lifeline.cli"
write_wrapper "$BIN_DIR/lifeline-tray" "lifeline.tray"
run install -m 0755 "$SCRIPT_DIR/scripts/lifeline-lease-hook" "$LIBEXEC_DIR/lifeline-lease-hook"

if [[ ! -f "$ETC_DIR/config.toml" ]]; then
    run install -m 0644 "$SCRIPT_DIR/config/config.toml.example" "$ETC_DIR/config.toml"
else
    echo "Keeping existing $ETC_DIR/config.toml"
fi

if [[ ! -f "$ETC_DIR/dhcp_hosts.csv" ]]; then
    run install -m 0644 "$SCRIPT_DIR/config/dhcp_hosts.csv.example" "$ETC_DIR/dhcp_hosts.csv"
else
    echo "Keeping existing $ETC_DIR/dhcp_hosts.csv"
fi

if [[ ! -f "$ETC_DIR/config.env" ]]; then
    run install -m 0644 "$SCRIPT_DIR/config/config.env.example" "$ETC_DIR/config.env"
fi

if [[ -d /etc/apparmor.d/local ]]; then
    run install -m 0644 "$SCRIPT_DIR/apparmor/usr.sbin.dnsmasq.local" "$APPARMOR_LOCAL_DIR/usr.sbin.dnsmasq"
    if command -v apparmor_parser >/dev/null 2>&1 && [[ -f /etc/apparmor.d/usr.sbin.dnsmasq ]]; then
        run apparmor_parser -r /etc/apparmor.d/usr.sbin.dnsmasq || true
    fi
fi

run install -m 0644 "$SCRIPT_DIR/systemd/lifeline.service" "$SYSTEMD_DIR/lifeline.service"
run mkdir -p "$MAN_DIR"
run install -m 0644 "$SCRIPT_DIR/man/lifeline.8" "$MAN_DIR/lifeline.8"
run install -m 0644 "$SCRIPT_DIR/man/lifelinectl.8" "$MAN_DIR/lifelinectl.8"
run install -m 0644 "$SCRIPT_DIR/man/lifelined.8" "$MAN_DIR/lifelined.8"
run mkdir -p /usr/local/share/lifeline/shell /usr/local/share/icons/hicolor/scalable/apps
run install -m 0644 "$SCRIPT_DIR/shell/lifeline-prompt.sh" /usr/local/share/lifeline/shell/lifeline-prompt.sh
for svg in "$SCRIPT_DIR"/icons/*.svg; do
    run install -m 0644 "$svg" "/usr/local/share/icons/hicolor/scalable/apps/$(basename "$svg")"
done
if command -v mandb >/dev/null 2>&1; then
    run mandb -q || true
fi
run systemctl daemon-reload
run systemctl enable lifeline.service

echo ""
echo "Lifeline installed successfully!"
echo "Next steps:"
echo "  1. Edit $ETC_DIR/config.toml (or $ETC_DIR/config.env) and $ETC_DIR/dhcp_hosts.csv"
echo "  2. Validate:  sudo lifelinectl validate"
echo "  3. Start:     sudo systemctl start lifeline"
echo "  4. Monitor:   sudo lifelinectl status"
