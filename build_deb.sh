#!/usr/bin/env bash
# ==============================================================================
# Author: Vikram Aggarwal
# License: GNU General Public License v3.0 or later (GPL-3.0-or-later)
# Bug fixes, cleanups, and feature improvements are warmly encouraged.
#
# Build architecture-independent (.deb, Architecture: all) package for Lifeline
# Works across arm64, armhf/arm32, i386/x86, and amd64/x64 Ubuntu/Debian hosts.
# Output: dist/lifeline_<version>_all.deb
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${1:-0.15.0}"
OUT_DIR="$SCRIPT_DIR/dist"
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

PKG_ROOT="$STAGE_DIR/lifeline_${VERSION}_all"
mkdir -p \
    "$PKG_ROOT/DEBIAN" \
    "$PKG_ROOT/usr/bin" \
    "$PKG_ROOT/usr/libexec/lifeline" \
    "$PKG_ROOT/usr/lib/python3/dist-packages" \
    "$PKG_ROOT/usr/lib/systemd/system" \
    "$PKG_ROOT/usr/share/doc/lifeline" \
    "$PKG_ROOT/usr/share/lifeline/shell" \
    "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps" \
    "$PKG_ROOT/usr/share/man/man8" \
    "$PKG_ROOT/etc/lifeline/hosts.d" \
    "$PKG_ROOT/etc/xdg/autostart" \
    "$PKG_ROOT/etc/apparmor.d/local"

# 1. Python package (installed cleanly onto standard Debian dist-packages path)
cp -r "$SCRIPT_DIR/src/lifeline" "$PKG_ROOT/usr/lib/python3/dist-packages/"
find "$PKG_ROOT/usr/lib/python3/dist-packages/lifeline" -name '__pycache__' -exec rm -rf {} +

# 2. Executables & dnsmasq lease hook
cat >"$PKG_ROOT/usr/bin/lifelined" <<'EOF'
#!/usr/bin/python3
import sys
from lifeline.daemon import main
if __name__ == "__main__":
    raise SystemExit(main())
EOF
chmod 0755 "$PKG_ROOT/usr/bin/lifelined"

cat >"$PKG_ROOT/usr/bin/lifelinectl" <<'EOF'
#!/usr/bin/python3
import sys
from lifeline.cli import main
if __name__ == "__main__":
    raise SystemExit(main())
EOF
chmod 0755 "$PKG_ROOT/usr/bin/lifelinectl"

cat >"$PKG_ROOT/usr/bin/lifeline-tray" <<'EOF'
#!/usr/bin/python3
import sys
from lifeline.tray import main
if __name__ == "__main__":
    raise SystemExit(main())
EOF
chmod 0755 "$PKG_ROOT/usr/bin/lifeline-tray"

cat >"$PKG_ROOT/usr/libexec/lifeline/lease-hook" <<'EOF'
#!/usr/bin/python3
import sys
from lifeline.lease_hook import main
if __name__ == "__main__":
    raise SystemExit(main())
EOF
chmod 0755 "$PKG_ROOT/usr/libexec/lifeline/lease-hook"

# 3. Default configuration files (marked as conffiles so apt preserves edits)
install -m 0644 "$SCRIPT_DIR/config/config.toml.example" "$PKG_ROOT/etc/lifeline/config.toml"
install -m 0644 "$SCRIPT_DIR/config/config.env.example" "$PKG_ROOT/etc/lifeline/config.env"
install -m 0644 "$SCRIPT_DIR/config/dhcp_hosts.csv.example" "$PKG_ROOT/etc/lifeline/dhcp_hosts.csv"

# 4. Systemd unit, AppArmor drop-in, and documentation
install -m 0644 "$SCRIPT_DIR/packaging/debian/lifeline.service" "$PKG_ROOT/usr/lib/systemd/system/lifeline.service"
install -m 0644 "$SCRIPT_DIR/apparmor/usr.sbin.dnsmasq.local" "$PKG_ROOT/etc/apparmor.d/local/usr.sbin.dnsmasq"
install -m 0644 "$SCRIPT_DIR/README.md" "$PKG_ROOT/usr/share/doc/lifeline/README.md"
install -m 0644 "$SCRIPT_DIR/USER.md" "$PKG_ROOT/usr/share/doc/lifeline/USER.md"
install -m 0644 "$SCRIPT_DIR/LICENSE" "$PKG_ROOT/usr/share/doc/lifeline/LICENSE"
install -m 0644 "$SCRIPT_DIR/packaging/debian/copyright" "$PKG_ROOT/usr/share/doc/lifeline/copyright"
install -m 0644 "$SCRIPT_DIR/config/config.toml.example" "$PKG_ROOT/usr/share/doc/lifeline/config.toml.example"
install -m 0644 "$SCRIPT_DIR/config/dhcp_hosts.csv.example" "$PKG_ROOT/usr/share/doc/lifeline/dhcp_hosts.csv.example"
install -m 0644 "$SCRIPT_DIR/shell/lifeline-prompt.sh" "$PKG_ROOT/usr/share/lifeline/shell/lifeline-prompt.sh"
install -m 0644 "$SCRIPT_DIR/packaging/desktop/lifeline-tray.desktop" "$PKG_ROOT/etc/xdg/autostart/lifeline-tray.desktop"
for svg in "$SCRIPT_DIR"/icons/*.svg; do
    install -m 0644 "$svg" "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps/$(basename "$svg")"
done

for mp in lifeline.8 lifelinectl.8 lifelined.8; do
    gzip -n -9 -c "$SCRIPT_DIR/man/$mp" >"$PKG_ROOT/usr/share/man/man8/${mp}.gz"
    chmod 0644 "$PKG_ROOT/usr/share/man/man8/${mp}.gz"
done

# 5. DEBIAN metadata & maintainer hooks
INSTALLED_KB="$(du -sk "$PKG_ROOT" | awk '{print $1}')"
sed "s/@VERSION@/${VERSION}/g" "$SCRIPT_DIR/packaging/debian/control.in" >"$PKG_ROOT/DEBIAN/control"
echo "Installed-Size: ${INSTALLED_KB}" >>"$PKG_ROOT/DEBIAN/control"

install -m 0644 "$SCRIPT_DIR/packaging/debian/conffiles" "$PKG_ROOT/DEBIAN/conffiles"
install -m 0755 "$SCRIPT_DIR/packaging/debian/postinst" "$PKG_ROOT/DEBIAN/postinst"
install -m 0755 "$SCRIPT_DIR/packaging/debian/prerm" "$PKG_ROOT/DEBIAN/prerm"
install -m 0755 "$SCRIPT_DIR/packaging/debian/postrm" "$PKG_ROOT/DEBIAN/postrm"

mkdir -p "$OUT_DIR"
OUT_DEB="$OUT_DIR/lifeline_${VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$PKG_ROOT" "$OUT_DEB"
echo "Built: $OUT_DEB"
