"""Unit tests for PS1 prompt formatting and desktop tray summary helpers."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from lifeline.cli import format_prompt_status
from lifeline.tray import build_gio_menu, format_tray_summary, read_status_snapshot


class TestPromptAndTray(unittest.TestCase):
    def test_prompt_missing_and_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "status.json"
            self.assertEqual(format_prompt_status(p), "")
            self.assertEqual(format_prompt_status(p, show_stopped=True), "[LL:OFF]")

            p.write_text(
                json.dumps({"mode": "PRIMARY", "leases": [], "updated_at_epoch": 1000}),
                encoding="utf-8",
            )
            self.assertEqual(format_prompt_status(p, now_epoch=2000), "")
            self.assertEqual(format_prompt_status(p, show_stopped=True, now_epoch=2000), "[LL:STALE]")

    def test_prompt_formats_for_bash_and_zsh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "status.json"
            now = int(time.time())
            p.write_text(
                json.dumps(
                    {
                        "mode": "PRIMARY",
                        "leases": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.9.101"}],
                        "updated_at_epoch": now,
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(format_prompt_status(p, now_epoch=now), "[LL:PRI(1)]")
            bash_col = format_prompt_status(p, shell="bash", color=True, now_epoch=now)
            self.assertTrue(bash_col.startswith("\\[\033[32m\\][LL:PRI(1)]\\[\033[0m\\]"))
            zsh_col = format_prompt_status(p, shell="zsh", color=True, now_epoch=now)
            self.assertTrue(zsh_col.startswith("%{\033[32m%}[LL:PRI(1)]%{\033[0m%}"))

    def test_tray_summary_formatting(self) -> None:
        icon_off, lbl_off, lines_off = format_tray_summary(None)
        self.assertEqual((icon_off, lbl_off), ("lifeline-idle", "LL:OFF"))
        self.assertIn("not running", lines_off[0])

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "status.json"
            p.write_text(
                json.dumps(
                    {
                        "mode": "PRIMARY",
                        "reason": "won election",
                        "interfaces": {"eth": "enp0s31f6", "eth_carrier": True, "wifi": "wlp0s20f3", "uplinks": ["wlp0s20f3", "tailscale0"]},
                        "health": {"wifi_latency_ms": 14.2},
                        "election": {"peers": [{"mac": "aa:00:00:00:00:02"}]},
                        "leases": [{"ip": "192.168.9.101", "mac": "aa:bb:cc:dd:ee:01", "hostname": "rig-1"}],
                        "updated_at_epoch": int(time.time()),
                    }
                ),
                encoding="utf-8",
            )
            snap = read_status_snapshot(p)
            icon, lbl, lines = format_tray_summary(snap)
            self.assertEqual(icon, "lifeline-primary")
            self.assertEqual(lbl, "LL:PRI(1)")
            joined = "\n".join(lines)
            self.assertIn("tailscale0", joined)
            self.assertIn("14.2 ms", joined)
            self.assertIn("rig-1", joined)

    def test_build_gio_menu_uses_indicator_prefix(self) -> None:
        try:
            from gi.repository import Gio
        except ImportError:
            self.skipTest("PyGObject Gio not available")
        menu = build_gio_menu(["Mode: PRIMARY", "Active Leases: 1"])
        self.assertIsInstance(menu, Gio.Menu)
        # 2 sections: info items + control actions
        self.assertEqual(menu.get_n_items(), 2)
        info_sec = menu.get_item_link(0, Gio.MENU_LINK_SECTION)
        ctl_sec = menu.get_item_link(1, Gio.MENU_LINK_SECTION)
        self.assertEqual(info_sec.get_n_items(), 2)
        self.assertEqual(ctl_sec.get_n_items(), 2)
        self.assertEqual(
            info_sec.get_item_attribute_value(0, Gio.MENU_ATTRIBUTE_ACTION).get_string(),
            "indicator.noop",
        )
        self.assertEqual(
            ctl_sec.get_item_attribute_value(0, Gio.MENU_ATTRIBUTE_ACTION).get_string(),
            "indicator.view-logs",
        )
        self.assertEqual(
            ctl_sec.get_item_attribute_value(1, Gio.MENU_ATTRIBUTE_ACTION).get_string(),
            "indicator.quit",
        )


if __name__ == "__main__":
    unittest.main()
