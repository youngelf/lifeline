# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""NetworkManager backend for Ubuntu 26.04 Desktop.

Creates and activates **temporary in-memory** connection profiles (`save no`)
via `nmcli` so `/etc/netplan/90-NM-*.yaml` is never polluted with stale files,
and cleans them up cleanly on exit.
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

LOG = logging.getLogger("lifeline.backend.nm")

CON_STATIC = "lifeline-eth-static"
CON_FAILOVER = "lifeline-eth-failover"
CON_STANDBY = "lifeline-eth-standby"


class NetworkManagerBackend(NetworkBackend):
    """Drives NetworkManager (`nmcli`) + `systemd-resolved` (`resolvectl`)."""

    uses_kernel_ra = False

    def __init__(self) -> None:
        self._nmcli = shutil.which("nmcli") or "/usr/bin/nmcli"
        self._resolvectl = shutil.which("resolvectl")

    async def _list_nm_devices(self) -> list[tuple[str, str]]:
        """Return `(device_name, nm_type)` pairs for physical network devices."""
        res = await run_cmd([self._nmcli, "-t", "-f", "DEVICE,TYPE", "device", "status"])
        devices: list[tuple[str, str]] = []
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if ":" not in line:
                    continue
                dev, dev_type = line.split(":", 1)
                dev = dev.strip()
                if not dev or dev == "lo":
                    continue
                if is_physical_iface(dev):
                    devices.append((dev, dev_type.strip()))
        if not devices:
            # Fallback to sysfs if NM didn't return anything yet
            for path in sorted(Path("/sys/class/net").iterdir()):
                name = path.name
                if name == "lo" or not is_physical_iface(name):
                    continue
                dev_type = "wifi" if is_wifi_iface(name) else "ethernet"
                devices.append((name, dev_type))
        return devices

    @staticmethod
    def _select_device(
        selector: str,
        candidates: list[str],
        *,
        prefer_carrier: bool = False,
    ) -> Optional[str]:
        sel = selector.strip()
        if sel.lower().startswith("mac:"):
            target_mac = sel[4:].strip().lower()
            for dev in candidates:
                if (get_iface_mac(dev) or "").lower() == target_mac:
                    return dev
            return None
        if sel != "auto":
            return sel if Path(f"/sys/class/net/{sel}").exists() else None
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        if prefer_carrier:
            with_carrier = [d for d in candidates if get_iface_carrier(d)]
            if with_carrier:
                return sorted(with_carrier)[0]
        return sorted(candidates)[0]

    async def discover_interfaces(self, eth_sel: str, wifi_sel: str) -> InterfacePair:
        devices = await self._list_nm_devices()
        eth_candidates = [d for d, t in devices if t == "ethernet" or (t != "wifi" and not is_wifi_iface(d))]
        wifi_candidates = [d for d, t in devices if t == "wifi" or is_wifi_iface(d)]

        eth_if = self._select_device(eth_sel, eth_candidates, prefer_carrier=True)
        wifi_if = self._select_device(wifi_sel, wifi_candidates, prefer_carrier=True)

        return InterfacePair(
            eth_if=eth_if,
            eth_mac=get_iface_mac(eth_if) if eth_if else None,
            wifi_if=wifi_if,
            wifi_mac=get_iface_mac(wifi_if) if wifi_if else None,
        )

    async def _delete_connection_if_exists(self, con_name: str) -> None:
        await run_cmd([self._nmcli, "connection", "delete", con_name])

    async def _delete_all_lifeline_connections(self, keep: Optional[str] = None) -> None:
        for name in (CON_STATIC, CON_FAILOVER, CON_STANDBY):
            if name != keep:
                await self._delete_connection_if_exists(name)

    async def apply_eth_static(
        self,
        eth_if: str,
        v4_cidr: str,
        v6_cidr: Optional[str],
    ) -> None:
        await self._delete_connection_if_exists(CON_STATIC)
        args = [
            self._nmcli,
            "connection",
            "add",
            "save",
            "no",
            "type",
            "ethernet",
            "ifname",
            eth_if,
            "con-name",
            CON_STATIC,
            "autoconnect",
            "no",
            "ipv4.method",
            "manual",
            "ipv4.addresses",
            v4_cidr,
            "ipv4.never-default",
            "yes",
            "ipv4.ignore-auto-dns",
            "yes",
        ]
        if v6_cidr:
            args.extend(
                [
                    "ipv6.method",
                    "manual",
                    "ipv6.addresses",
                    v6_cidr,
                    "ipv6.never-default",
                    "yes",
                    "ipv6.ignore-auto-dns",
                    "yes",
                ]
            )
        else:
            args.extend(["ipv6.method", "ignore"])

        res = await run_cmd(args, timeout=15.0)
        if res.returncode != 0:
            raise RuntimeError(f"nmcli add {CON_STATIC} failed: {res.stderr.strip()}")

        try:
            up_res = await run_cmd(
                [self._nmcli, "-w", "5", "connection", "up", CON_STATIC, "ifname", eth_if],
                timeout=15.0,
            )
            if up_res.returncode != 0:
                raise RuntimeError(
                    f"nmcli up {CON_STATIC} on {eth_if} failed (rc={up_res.returncode}): "
                    f"{up_res.stderr.strip() or up_res.stdout.strip()}"
                )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(f"nmcli up {CON_STATIC} on {eth_if} timed out after 15s") from exc

        await self._delete_all_lifeline_connections(keep=CON_STATIC)

        # Wait for configured IPv4 and non-tentative IPv6 ULA so dnsmasq can bind cleanly.
        target_v4 = ipaddress.IPv4Interface(v4_cidr).ip
        target_v6 = ipaddress.IPv6Interface(v6_cidr).ip if v6_cidr else None
        for _ in range(30):
            v4_addrs, v6_addrs = get_interface_addrs(eth_if)
            has_v4 = any(a.ip == target_v4 for a in v4_addrs)
            has_v6 = True if target_v6 is None else any(a.ip == target_v6 for a in v6_addrs)
            if has_v4 and has_v6:
                return
            await asyncio.sleep(0.15)
        LOG.warning("Timed out waiting for non-tentative static addresses on %s", eth_if)

    async def apply_eth_dhcp_failover(self, eth_if: str, metric: int) -> None:
        await self._delete_connection_if_exists(CON_FAILOVER)
        args = [
            self._nmcli,
            "connection",
            "add",
            "save",
            "no",
            "type",
            "ethernet",
            "ifname",
            eth_if,
            "con-name",
            CON_FAILOVER,
            "autoconnect",
            "no",
            "ipv4.method",
            "auto",
            "ipv4.route-metric",
            str(metric),
            "ipv4.never-default",
            "no",
            "ipv4.ignore-auto-dns",
            "no",
            "ipv4.may-fail",
            "yes",
            "ipv6.method",
            "auto",
            "ipv6.route-metric",
            str(metric),
            "ipv6.never-default",
            "no",
            "ipv6.ignore-auto-dns",
            "no",
            "ipv6.may-fail",
            "yes",
        ]
        res = await run_cmd(args, timeout=15.0)
        if res.returncode != 0:
            raise RuntimeError(
                f"nmcli add {CON_FAILOVER} on {eth_if} failed (rc={res.returncode}): "
                f"{res.stderr.strip() or res.stdout.strip()}"
            )
        # If Ethernet has no link yet, activate asynchronously (-w 0) so startup never blocks
        # or times out waiting for a DHCP server on an unplugged cable.
        wait_arg = "3" if get_iface_carrier(eth_if) else "0"
        try:
            up_res = await run_cmd(
                [self._nmcli, "-w", wait_arg, "connection", "up", CON_FAILOVER, "ifname", eth_if],
                timeout=15.0,
            )
            if up_res.returncode != 0:
                LOG.warning(
                    "nmcli up %s on %s returned rc=%d (DHCP may still be pending): %s",
                    CON_FAILOVER,
                    eth_if,
                    up_res.returncode,
                    up_res.stderr.strip() or up_res.stdout.strip(),
                )
        except asyncio.TimeoutError:
            LOG.warning("nmcli up %s on %s timed out waiting for DHCP; continuing", CON_FAILOVER, eth_if)
        await self._delete_all_lifeline_connections(keep=CON_FAILOVER)

    async def apply_eth_dhcp_standby(self, eth_if: str, metric: int) -> None:
        await self._delete_connection_if_exists(CON_STANDBY)
        args = [
            self._nmcli,
            "connection",
            "add",
            "save",
            "no",
            "type",
            "ethernet",
            "ifname",
            eth_if,
            "con-name",
            CON_STANDBY,
            "autoconnect",
            "no",
            "ipv4.method",
            "auto",
            "ipv4.route-metric",
            str(metric),
            "ipv4.never-default",
            "yes",
            "ipv4.ignore-auto-dns",
            "yes",
            "ipv4.may-fail",
            "yes",
            "ipv6.method",
            "auto",
            "ipv6.route-metric",
            str(metric),
            "ipv6.never-default",
            "yes",
            "ipv6.ignore-auto-dns",
            "yes",
            "ipv6.may-fail",
            "yes",
        ]
        res = await run_cmd(args, timeout=15.0)
        if res.returncode != 0:
            raise RuntimeError(
                f"nmcli add {CON_STANDBY} on {eth_if} failed (rc={res.returncode}): "
                f"{res.stderr.strip() or res.stdout.strip()}"
            )
        wait_arg = "2" if get_iface_carrier(eth_if) else "0"
        try:
            up_res = await run_cmd(
                [self._nmcli, "-w", wait_arg, "connection", "up", CON_STANDBY, "ifname", eth_if],
                timeout=15.0,
            )
            if up_res.returncode != 0:
                LOG.debug(
                    "nmcli up %s returned rc=%d (%s)",
                    CON_STANDBY,
                    up_res.returncode,
                    up_res.stderr.strip() or up_res.stdout.strip(),
                )
        except asyncio.TimeoutError:
            LOG.debug("nmcli up %s timed out; continuing", CON_STANDBY)
        await self._delete_all_lifeline_connections(keep=CON_STANDBY)

    async def set_wifi_dns_default_route(self, wifi_if: str, enabled: bool) -> None:
        if not self._resolvectl or not wifi_if:
            return
        flag = "true" if enabled else "false"
        res = await run_cmd([self._resolvectl, "default-route", wifi_if, flag])
        if res.returncode != 0:
            LOG.debug("resolvectl default-route %s %s failed: %s", wifi_if, flag, res.stderr.strip())

    async def cleanup(self, eth_if: Optional[str], wifi_if: Optional[str]) -> None:
        await self._delete_all_lifeline_connections(keep=None)
        if wifi_if:
            await self.set_wifi_dns_default_route(wifi_if, True)
