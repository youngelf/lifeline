# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Safe kernel sysctl management for IPv4 & IPv6 forwarding.

Key Linux kernel details handled here:
1. IPv4 supports true per-interface forwarding (`net.ipv4.conf.<if>.forwarding`).
   Modifying per-interface flags leaves unrelated interfaces (e.g. `docker0`)
   and global RFC defaults untouched.
2. IPv6 only has a global forwarding switch (`net.ipv6.conf.all.forwarding`).
   Because enabling IPv6 forwarding causes the kernel to drop incoming RAs
   unless `accept_ra=2` (for kernel-RA backends like systemd-networkd; NM uses
   userspace `libndp`), we configure `accept_ra=2` on Wi-Fi *before* enabling
   global IPv6 forwarding when using the `networkd` backend.
3. Supports multiple uplink interfaces (e.g. `wlan0` plus `tailscale0` / `tun0`)
   and snapshots original values once before entering PRIMARY mode.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional, Sequence, Union

LOG = logging.getLogger("lifeline.sysctl")

SYSCTL_ROOT = Path("/proc/sys")


class SysctlManager:
    """Saves, applies, re-asserts, and restores forwarding sysctls."""

    def __init__(self) -> None:
        self._saved: Dict[str, str] = {}

    @staticmethod
    def _key_to_path(key: str) -> Path:
        return SYSCTL_ROOT / key.replace(".", "/")

    def read(self, key: str) -> Optional[str]:
        path = self._key_to_path(key)
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            return None

    def write(self, key: str, value: str) -> bool:
        path = self._key_to_path(key)
        try:
            current = path.read_text(encoding="utf-8").strip()
            if current != value:
                path.write_text(f"{value}\n", encoding="utf-8")
            return True
        except OSError as exc:
            LOG.warning("Failed writing sysctl %s=%s: %s", key, value, exc)
            return False

    def _save_once(self, key: str) -> None:
        if key not in self._saved:
            val = self.read(key)
            if val is not None:
                self._saved[key] = val

    def enable_forwarding(
        self,
        eth_if: str,
        wifi_if: str,
        *,
        uplink_ifs: Optional[Union[str, Sequence[str]]] = None,
        enable_ipv6: bool = True,
        set_wifi_accept_ra_2: bool = False,
    ) -> None:
        """Enable IPv4 (and optionally IPv6) forwarding between `eth_if` and uplinks."""
        uplinks = (
            [wifi_if]
            if uplink_ifs is None
            else ([uplink_ifs] if isinstance(uplink_ifs, str) else list(uplink_ifs))
        )
        all_ifaces = list(dict.fromkeys([eth_if, wifi_if, *uplinks]))

        keys_to_save = ["net.ipv4.conf.all.forwarding"]
        for iface in all_ifaces:
            keys_to_save.append(f"net.ipv4.conf.{iface}.forwarding")
        if enable_ipv6:
            keys_to_save.extend(
                [
                    "net.ipv6.conf.all.forwarding",
                    f"net.ipv6.conf.{wifi_if}.accept_ra",
                ]
            )
            for iface in all_ifaces:
                keys_to_save.append(f"net.ipv6.conf.{iface}.forwarding")

        for key in keys_to_save:
            self._save_once(key)

        self.write("net.ipv4.conf.all.forwarding", "1")
        for iface in all_ifaces:
            self.write(f"net.ipv4.conf.{iface}.forwarding", "1")

        if enable_ipv6:
            if set_wifi_accept_ra_2:
                # Must be set BEFORE net.ipv6.conf.all.forwarding=1 for kernel RA mode.
                self.write(f"net.ipv6.conf.{wifi_if}.accept_ra", "2")
            self.write("net.ipv6.conf.all.forwarding", "1")
            for iface in all_ifaces:
                self.write(f"net.ipv6.conf.{iface}.forwarding", "1")

    def reassert_forwarding(
        self,
        eth_if: str,
        wifi_if: str,
        *,
        uplink_ifs: Optional[Union[str, Sequence[str]]] = None,
        enable_ipv6: bool = True,
        set_wifi_accept_ra_2: bool = False,
    ) -> None:
        """Re-apply forwarding sysctls if NetworkManager rewrote them on roam."""
        self.enable_forwarding(
            eth_if,
            wifi_if,
            uplink_ifs=uplink_ifs,
            enable_ipv6=enable_ipv6,
            set_wifi_accept_ra_2=set_wifi_accept_ra_2,
        )

    def disable_and_restore(self, eth_if: Optional[str] = None) -> None:
        """Restore saved sysctls and explicitly ensure Ethernet forwarding is 0."""
        if eth_if:
            self.write(f"net.ipv4.conf.{eth_if}.forwarding", "0")
            self.write(f"net.ipv6.conf.{eth_if}.forwarding", "0")

        for key, old_val in reversed(list(self._saved.items())):
            self.write(key, old_val)
        self._saved.clear()
