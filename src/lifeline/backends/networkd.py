# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Optional systemd-networkd backend for Ubuntu 26.04 Server / headless nodes.

Writes transient `.network` units into `/run/systemd/network/` (tmpfs) and
invokes `networkctl reload` + `networkctl reconfigure <eth_if>`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from pathlib import Path
import shutil
from typing import Optional

from lifeline.backends.base import InterfacePair, NetworkBackend
from lifeline.net_utils import (
    get_iface_carrier,
    get_iface_mac,
    get_interface_addrs,
    is_physical_iface,
    is_wifi_iface,
    run_cmd,
)

LOG = logging.getLogger("lifeline.backend.networkd")

NETWORKD_RUN_DIR = Path("/run/systemd/network")


class NetworkdBackend(NetworkBackend):
    """Drives `systemd-networkd` via transient `/run/systemd/network/` files."""

    uses_kernel_ra = True

    def __init__(self) -> None:
        self._networkctl = shutil.which("networkctl") or "/usr/bin/networkctl"
        self._resolvectl = shutil.which("resolvectl")

    @staticmethod
    def _unit_path(eth_if: str) -> Path:
        return NETWORKD_RUN_DIR / f"10-lifeline-{eth_if}.network"

    async def discover_interfaces(self, eth_sel: str, wifi_sel: str) -> InterfacePair:
        eth_candidates: list[str] = []
        wifi_candidates: list[str] = []
        for path in sorted(Path("/sys/class/net").iterdir()):
            name = path.name
            if name == "lo" or not is_physical_iface(name):
                continue
            if is_wifi_iface(name):
                wifi_candidates.append(name)
            else:
                eth_candidates.append(name)

        def pick(sel: str, cands: list[str]) -> Optional[str]:
            if sel.lower().startswith("mac:"):
                target = sel[4:].strip().lower()
                for c in cands:
                    if (get_iface_mac(c) or "").lower() == target:
                        return c
                return None
            if sel != "auto":
                return sel if Path(f"/sys/class/net/{sel}").exists() else None
            if not cands:
                return None
            up = [c for c in cands if get_iface_carrier(c)]
            return sorted(up)[0] if up else sorted(cands)[0]

        eth_if = pick(eth_sel, eth_candidates)
        wifi_if = pick(wifi_sel, wifi_candidates)
        return InterfacePair(
            eth_if=eth_if,
            eth_mac=get_iface_mac(eth_if) if eth_if else None,
            wifi_if=wifi_if,
            wifi_mac=get_iface_mac(wifi_if) if wifi_if else None,
        )

    async def _write_and_apply(self, eth_if: str, content: str) -> None:
        NETWORKD_RUN_DIR.mkdir(parents=True, exist_ok=True)
        path = self._unit_path(eth_if)
        path.write_text(content, encoding="utf-8")
        await run_cmd([self._networkctl, "reload"])
        await run_cmd([self._networkctl, "reconfigure", eth_if])

    async def apply_eth_static(
        self,
        eth_if: str,
        v4_cidr: str,
        v6_cidr: Optional[str],
    ) -> None:
        lines = [
            "[Match]",
            f"Name={eth_if}",
            "",
            "[Network]",
            "DHCP=no",
            "IPv6AcceptRA=no",
            f"Address={v4_cidr}",
        ]
        if v6_cidr:
            lines.append(f"Address={v6_cidr}")
        await self._write_and_apply(eth_if, "\n".join(lines) + "\n")

        target_v4 = ipaddress.IPv4Interface(v4_cidr).ip
        target_v6 = ipaddress.IPv6Interface(v6_cidr).ip if v6_cidr else None
        for _ in range(30):
            v4_addrs, v6_addrs = get_interface_addrs(eth_if)
            has_v4 = any(a.ip == target_v4 for a in v4_addrs)
            has_v6 = True if target_v6 is None else any(a.ip == target_v6 for a in v6_addrs)
            if has_v4 and has_v6:
                return
            await asyncio.sleep(0.15)

    async def apply_eth_dhcp_failover(self, eth_if: str, metric: int) -> None:
        content = (
            f"[Match]\nName={eth_if}\n\n"
            "[Network]\nDHCP=yes\nIPv6AcceptRA=yes\n\n"
            f"[DHCPv4]\nRouteMetric={metric}\nUseDNS=yes\nUseRoutes=yes\n\n"
            f"[IPv6AcceptRA]\nRouteMetric={metric}\nUseDNS=yes\n"
        )
        await self._write_and_apply(eth_if, content)

    async def apply_eth_dhcp_standby(self, eth_if: str, metric: int) -> None:
        content = (
            f"[Match]\nName={eth_if}\n\n"
            "[Network]\nDHCP=yes\nIPv6AcceptRA=yes\n\n"
            f"[DHCPv4]\nRouteMetric={metric}\nUseDNS=no\nUseRoutes=no\n\n"
            f"[IPv6AcceptRA]\nRouteMetric={metric}\nUseDNS=no\n"
        )
        await self._write_and_apply(eth_if, content)

    async def set_wifi_dns_default_route(self, wifi_if: str, enabled: bool) -> None:
        if not self._resolvectl or not wifi_if:
            return
        flag = "true" if enabled else "false"
        await run_cmd([self._resolvectl, "default-route", wifi_if, flag])

    async def cleanup(self, eth_if: Optional[str], wifi_if: Optional[str]) -> None:
        for path in NETWORKD_RUN_DIR.glob("10-lifeline-*.network"):
            path.unlink(missing_ok=True)
        if shutil.which("networkctl"):
            await run_cmd([self._networkctl, "reload"])
        if wifi_if:
            await self.set_wifi_dns_default_route(wifi_if, True)
