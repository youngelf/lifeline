# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Desktop system tray applet and transition notifier (`lifeline-tray`).

Reads `/run/lifeline/status.json` periodically in the user's graphical session
(zero root privileges needed) and displays:
- Color-coded status icon (PRIMARY=green, SECONDARY=blue, FAILOVER=amber, IDLE=gray)
- Mode, reason, active uplinks (Wi-Fi + VPN/Tailscale), probe RTT latency,
  peer laptops, and active DHCP client leases in the menu
- Desktop notifications on mode transitions (`Notify` / `notify-send`)

Prefers the modern GTK-free `AyatanaAppIndicatorGlib` 2.0 (`Gio.Menu` +
`Gio.SimpleActionGroup`) backend; falls back to legacy `AyatanaAppIndicator3` /
`AppIndicator3` or `notify-send` if the `AyatanaAppIndicatorGlib` typelib is
not installed.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Optional

DEFAULT_STATUS_PATH = Path("/run/lifeline/status.json")
ICON_SEARCH_DIRS = (
    Path("/usr/share/icons/hicolor/scalable/apps"),
    Path("/usr/local/share/icons/hicolor/scalable/apps"),
    Path(__file__).resolve().parents[2] / "icons",
)

MODE_ICON_MAP = {
    "PRIMARY": "lifeline-primary",
    "SECONDARY": "lifeline-secondary",
    "FAILOVER": "lifeline-failover",
    "ELECTION": "lifeline-failover",
    "IDLE": "lifeline-idle",
}


def read_status_snapshot(
    status_path: Path = DEFAULT_STATUS_PATH,
    *,
    max_age_sec: float = 15.0,
) -> Optional[dict]:
    """Read `/run/lifeline/status.json` if present, valid, and not stale."""
    if not status_path.exists():
        return None
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    updated = float(data.get("updated_at_epoch", 0))
    if max_age_sec > 0 and (time.time() - updated) > max_age_sec:
        return None
    return data


def format_tray_summary(data: Optional[dict]) -> tuple[str, str, list[str]]:
    """Return `(icon_name, short_label, menu_lines)` for the tray menu."""
    if data is None:
        return (
            "lifeline-idle",
            "LL:OFF",
            ["Status: lifelined not running"],
        )

    mode = str(data.get("mode", "IDLE")).upper()
    icon = MODE_ICON_MAP.get(mode, "lifeline-idle")
    leases = data.get("leases", [])
    ifaces = data.get("interfaces", {})
    health = data.get("health", {})
    elec = data.get("election", {})

    if mode == "PRIMARY":
        label = f"LL:PRI({len(leases)})"
    elif mode == "SECONDARY":
        label = "LL:SEC"
    elif mode == "FAILOVER":
        label = "LL:FAIL"
    elif mode == "ELECTION":
        label = "LL:ELEC"
    else:
        label = "LL:IDLE"

    uplinks = ", ".join(ifaces.get("uplinks") or []) or "-"
    rtt = health.get("wifi_latency_ms")
    rtt_str = f"{rtt} ms" if rtt is not None else "-"
    lines = [
        f"Mode: {mode} ({data.get('reason', '')})",
        f"ETH: {ifaces.get('eth') or '-'} (carrier={ifaces.get('eth_carrier')}) | Wi-Fi: {ifaces.get('wifi') or '-'}",
        f"Uplinks: {uplinks} | Wi-Fi RTT: {rtt_str}",
        f"Peers: {len(elec.get('peers', []))} | Active Leases: {len(leases)}",
    ]
    for lease in leases[:10]:
        host = lease.get("hostname") or "-"
        lines.append(f"  {lease.get('ip')}  {lease.get('mac')}  ({host})")
    if len(leases) > 10:
        lines.append(f"  ... +{len(leases) - 10} more leases")
    return icon, label, lines


def build_gio_menu(lines: list[str]):
    """Build a `Gio.Menu` for `AyatanaAppIndicatorGlib` (uses `indicator.` action prefix)."""
    from gi.repository import Gio

    menu = Gio.Menu.new()
    info_section = Gio.Menu.new()
    for line in lines:
        info_section.append(line, "indicator.noop")
    menu.append_section(None, info_section)

    ctl_section = Gio.Menu.new()
    ctl_section.append("View Live Logs (journalctl)", "indicator.view-logs")
    ctl_section.append("Quit Tray", "indicator.quit")
    menu.append_section(None, ctl_section)
    return menu


def _find_icon_theme_dir() -> Optional[str]:
    for d in ICON_SEARCH_DIRS:
        if (d / "lifeline-primary.svg").exists():
            return str(d)
    return None


def _send_desktop_notification(title: str, body: str, icon_name: str, notify_mod=None) -> None:
    if notify_mod is not None:
        try:
            n = notify_mod.Notification.new(title, body, icon_name)
            n.show()
            return
        except Exception:
            pass
    ns_bin = shutil.which("notify-send")
    if not ns_bin:
        return
    try:
        subprocess.Popen(
            [ns_bin, "-a", "Lifeline", "-i", icon_name, title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


def _open_logs_terminal() -> None:
    for term in ("gnome-terminal", "x-terminal-emulator", "konsole", "xfce4-terminal", "xterm"):
        tbin = shutil.which(term)
        if tbin:
            cmd = (
                [tbin, "--", "journalctl", "-u", "lifeline", "-f"]
                if term == "gnome-terminal"
                else [tbin, "-e", "journalctl -u lifeline -f"]
            )
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return


def _init_notify():
    try:
        import gi

        gi.require_version("Notify", "0.7")
        from gi.repository import Notify

        Notify.init("Lifeline")
        return Notify
    except (ValueError, ImportError):
        return None


def _run_notify_only(status_path: Path, poll_sec: float) -> int:
    notify_mod = _init_notify()
    last_mode: Optional[str] = None
    while True:
        data = read_status_snapshot(status_path)
        mode = str(data.get("mode", "OFF")) if data else "OFF"
        if last_mode is not None and mode != last_mode:
            icon, _, _ = format_tray_summary(data)
            reason = data.get("reason", "service stopped") if data else "service stopped"
            _send_desktop_notification(f"Lifeline -> {mode}", str(reason), icon, notify_mod)
        last_mode = mode
        time.sleep(poll_sec)


def _run_glib_indicator(status_path: Path, poll_sec: float) -> int:
    """Preferred GTK-free AyatanaAppIndicatorGlib 2.0 tray implementation."""
    import gi

    gi.require_version("AyatanaAppIndicatorGlib", "2.0")
    from gi.repository import AyatanaAppIndicatorGlib, Gio, GLib

    notify_mod = _init_notify()
    icon_dir = _find_icon_theme_dir()
    if icon_dir:
        indicator = AyatanaAppIndicatorGlib.Indicator.new_with_path(
            "lifeline-tray",
            "lifeline-idle",
            AyatanaAppIndicatorGlib.IndicatorCategory.SYSTEM_SERVICES,
            icon_dir,
        )
    else:
        indicator = AyatanaAppIndicatorGlib.Indicator.new(
            "lifeline-tray",
            "lifeline-idle",
            AyatanaAppIndicatorGlib.IndicatorCategory.SYSTEM_SERVICES,
        )

    indicator.set_title("Lifeline")
    indicator.set_status(AyatanaAppIndicatorGlib.IndicatorStatus.ACTIVE)

    loop = GLib.MainLoop()
    actions = Gio.SimpleActionGroup.new()

    noop_act = Gio.SimpleAction.new("noop", None)
    noop_act.set_enabled(False)
    actions.add_action(noop_act)

    logs_act = Gio.SimpleAction.new("view-logs", None)
    logs_act.connect("activate", lambda _a, _p: _open_logs_terminal())
    actions.add_action(logs_act)

    quit_act = Gio.SimpleAction.new("quit", None)
    quit_act.connect("activate", lambda _a, _p: loop.quit())
    actions.add_action(quit_act)

    indicator.set_actions(actions)

    state: dict[str, object] = {"last_mode": None, "last_lines": None}

    def on_tick() -> bool:
        data = read_status_snapshot(status_path)
        icon_name, label, lines = format_tray_summary(data)
        mode = str(data.get("mode", "OFF")) if data else "OFF"
        indicator.set_icon(icon_name, mode)
        indicator.set_label(label, "LL:PRI(99)")
        indicator.set_tooltip(icon_name, f"Lifeline: {mode}", lines[0])

        if state["last_lines"] != lines:
            indicator.set_menu(build_gio_menu(lines))
            state["last_lines"] = lines

        if state["last_mode"] is not None and mode != state["last_mode"]:
            reason = data.get("reason", "service stopped") if data else "service stopped"
            _send_desktop_notification(f"Lifeline -> {mode}", str(reason), icon_name, notify_mod)
        state["last_mode"] = mode
        return True

    on_tick()
    GLib.timeout_add(int(poll_sec * 1000), on_tick)
    try:
        loop.run()
    except KeyboardInterrupt:
        pass
    return 0


def _run_legacy_gtk_tray(status_path: Path, poll_sec: float) -> int:
    """Fallback for older environments lacking gir1.2-ayatanaappindicatorglib-2.0."""
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import GLib, Gtk

    indicator_mod = None
    for mod_name in ("AyatanaAppIndicator3", "AppIndicator3"):
        try:
            gi.require_version(mod_name, "0.1")
            indicator_mod = __import__(f"gi.repository.{mod_name}", fromlist=[mod_name])
            break
        except (ValueError, ImportError):
            continue

    if indicator_mod is None:
        print(
            "AyatanaAppIndicatorGlib not installed; falling back to notification watcher. "
            "Install `python3-gi gir1.2-ayatanaappindicatorglib-2.0` for tray icon.",
            file=sys.stderr,
        )
        return _run_notify_only(status_path, poll_sec)

    notify_mod = _init_notify()
    icon_dir = _find_icon_theme_dir()
    if icon_dir:
        theme = Gtk.IconTheme.get_default()
        if theme is not None:
            theme.append_search_path(icon_dir)

    indicator = indicator_mod.Indicator.new(
        "lifeline-tray",
        "lifeline-idle",
        indicator_mod.IndicatorCategory.SYSTEM_SERVICES,
    )
    if icon_dir:
        indicator.set_icon_theme_path(icon_dir)
    indicator.set_status(indicator_mod.IndicatorStatus.ACTIVE)

    state: dict[str, object] = {"last_mode": None, "last_lines": None}

    def rebuild_menu(lines: list[str]) -> None:
        menu = Gtk.Menu()
        for line in lines:
            item = Gtk.MenuItem(label=line)
            item.set_sensitive(False)
            menu.append(item)
        menu.append(Gtk.SeparatorMenuItem())

        logs_item = Gtk.MenuItem(label="View Live Logs (journalctl)")
        logs_item.connect("activate", lambda _w: _open_logs_terminal())
        menu.append(logs_item)

        quit_item = Gtk.MenuItem(label="Quit Tray")
        quit_item.connect("activate", lambda _w: Gtk.main_quit())
        menu.append(quit_item)
        menu.show_all()
        indicator.set_menu(menu)

    def on_tick() -> bool:
        data = read_status_snapshot(status_path)
        icon_name, label, lines = format_tray_summary(data)
        mode = str(data.get("mode", "OFF")) if data else "OFF"
        indicator.set_icon_full(icon_name, mode)
        indicator.set_label(label, "LL:PRI(99)")

        if state["last_lines"] != lines:
            rebuild_menu(lines)
            state["last_lines"] = lines

        if state["last_mode"] is not None and mode != state["last_mode"]:
            reason = data.get("reason", "service stopped") if data else "service stopped"
            _send_desktop_notification(f"Lifeline -> {mode}", str(reason), icon_name, notify_mod)
        state["last_mode"] = mode
        return True

    on_tick()
    GLib.timeout_add(int(poll_sec * 1000), on_tick)
    Gtk.main()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Lifeline desktop tray status applet")
    parser.add_argument("--status-file", type=Path, default=DEFAULT_STATUS_PATH)
    parser.add_argument("--poll-sec", type=float, default=1.5)
    parser.add_argument("--notify-only", action="store_true")
    args = parser.parse_args(argv)

    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return 0

    if args.notify_only:
        return _run_notify_only(args.status_file, args.poll_sec)

    try:
        import gi

        gi.require_version("AyatanaAppIndicatorGlib", "2.0")
        return _run_glib_indicator(args.status_file, args.poll_sec)
    except (ValueError, ImportError):
        try:
            return _run_legacy_gtk_tray(args.status_file, args.poll_sec)
        except ImportError:
            return _run_notify_only(args.status_file, args.poll_sec)


if __name__ == "__main__":
    raise SystemExit(main())
