# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Low-level Linux networking helpers (sysfs, iproute2, subprocesses).

All helpers are self-contained and use Python 3 stdlib + standard Ubuntu 26.04
utilities (`ip`, `resolvectl`, `nft`, `nmcli`).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import json
import logging
from pathlib import Path
import subprocess
from typing import Optional, Sequence

LOG = logging.getLogger("lifeline.net")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_cmd_sync(
    args: Sequence[str],
    *,
    input_text: Optional[str] = None,
    timeout: float = 10.0,
    check: bool = False,
) -> CommandResult:
    """Execute a subprocess synchronously and capture stdout/stderr."""
    proc = subprocess.run(
        list(args),
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, args, output=proc.stdout, stderr=proc.stderr
        )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


async def run_cmd(
    args: Sequence[str],
    *,
    input_text: Optional[str] = None,
    timeout: float = 10.0,
    check: bool = False,
) -> CommandResult:
    """Execute a subprocess asynchronously with timeout protection."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input_text.encode("utf-8") if input_text is not None else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    rc = proc.returncode or 0
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, args, output=stdout, stderr=stderr)
    return CommandResult(rc, stdout, stderr)


def read_sysfs_str(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def get_iface_mac(ifname: str) -> Optional[str]:
    """Return normalized lowercase MAC address of `ifname` (sysfs with netlink fallback)."""
    mac = read_sysfs_str(Path(f"/sys/class/net/{ifname}/address"))
    if mac:
        return mac.lower()
    res = run_cmd_sync(["ip", "-j", "link", "show", "dev", ifname])
    if res.returncode == 0 and res.stdout.strip():
        try:
            items = json.loads(res.stdout)
            if items and items[0].get("address"):
                return str(items[0]["address"]).lower()
        except json.JSONDecodeError:
            pass
    return None


def get_iface_carrier(ifname: str) -> bool:
    """Return True if Linux reports L1 carrier UP on `ifname`."""
    oper = read_sysfs_str(Path(f"/sys/class/net/{ifname}/carrier"))
    if oper is not None:
        return oper == "1"
    state = read_sysfs_str(Path(f"/sys/class/net/{ifname}/operstate"))
    if state is not None:
        return state == "up"
    res = run_cmd_sync(["ip", "-j", "link", "show", "dev", ifname])
    if res.returncode == 0 and res.stdout.strip():
        try:
            items = json.loads(res.stdout)
            if items:
                flags = items[0].get("flags", [])
                return "LOWER_UP" in flags or items[0].get("operstate") == "UP"
        except json.JSONDecodeError:
            pass
    return False


def is_physical_iface(ifname: str) -> bool:
    """Return True if `/sys/class/net/<ifname>/device` exists (excludes virtual NICs)."""
    return Path(f"/sys/class/net/{ifname}/device").exists()


def is_wifi_iface(ifname: str) -> bool:
    """Return True if sysfs identifies `ifname` as an IEEE 802.11 wireless device."""
    return (
        Path(f"/sys/class/net/{ifname}/wireless").exists()
        or Path(f"/sys/class/net/{ifname}/phy80211").exists()
    )


def get_interface_addrs(ifname: str) -> tuple[list[ipaddress.IPv4Interface], list[ipaddress.IPv6Interface]]:
    """Query global/non-tentative IPv4 & IPv6 addresses currently assigned to `ifname`."""
    res = run_cmd_sync(["ip", "-j", "addr", "show", "dev", ifname])
    v4: list[ipaddress.IPv4Interface] = []
    v6: list[ipaddress.IPv6Interface] = []
    if res.returncode != 0 or not res.stdout.strip():
        return v4, v6
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return v4, v6

    for item in data:
        for info in item.get("addr_info", []):
            if info.get("tentative"):
                continue
            family = info.get("family")
            local = info.get("local")
            prefixlen = info.get("prefixlen")
            if not local or prefixlen is None:
                continue
            if family == "inet":
                v4.append(ipaddress.IPv4Interface(f"{local}/{prefixlen}"))
            elif family == "inet6":
                addr = ipaddress.IPv6Interface(f"{local}/{prefixlen}")
                if not addr.ip.is_link_local:
                    v6.append(addr)
    return v4, v6


def get_interface_gateways(ifname: str) -> tuple[Optional[ipaddress.IPv4Address], Optional[ipaddress.IPv6Address]]:
    """Return default IPv4 and IPv6 gateway nexthops currently configured for `ifname`."""
    gw4: Optional[ipaddress.IPv4Address] = None
    gw6: Optional[ipaddress.IPv6Address] = None

    r4 = run_cmd_sync(["ip", "-4", "-j", "route", "show", "default", "dev", ifname])
    if r4.returncode == 0 and r4.stdout.strip():
        try:
            for route in json.loads(r4.stdout):
                if route.get("gateway"):
                    gw4 = ipaddress.IPv4Address(route["gateway"])
                    break
        except (json.JSONDecodeError, ValueError):
            pass

    r6 = run_cmd_sync(["ip", "-6", "-j", "route", "show", "default", "dev", ifname])
    if r6.returncode == 0 and r6.stdout.strip():
        try:
            for route in json.loads(r6.stdout):
                if route.get("gateway"):
                    gw6 = ipaddress.IPv6Address(route["gateway"])
                    break
        except (json.JSONDecodeError, ValueError):
            pass

    return gw4, gw6


def get_effective_egress_dev(target_ip: str = "1.1.1.1") -> Optional[str]:
    """Query the kernel FIB (including policy routing like Tailscale table 52) for egress dev."""
    flag = "-6" if ":" in target_ip else "-4"
    res = run_cmd_sync(["ip", flag, "-j", "route", "get", target_ip])
    if res.returncode == 0 and res.stdout.strip():
        try:
            items = json.loads(res.stdout)
            if items and items[0].get("dev"):
                return str(items[0]["dev"])
        except json.JSONDecodeError:
            pass
    return None


def list_up_tunnel_interfaces(
    prefixes: Sequence[str],
    *,
    exclude: Sequence[str] = (),
) -> list[str]:
    """Return active UP interface names matching any VPN/tunnel prefix."""
    res = run_cmd_sync(["ip", "-j", "link", "show", "up"])
    if res.returncode != 0 or not res.stdout.strip():
        return []
    excluded = set(exclude) | {"lo"}
    found: list[str] = []
    try:
        items = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    for item in items:
        name = str(item.get("ifname", ""))
        if not name or name in excluded:
            continue
        if any(name.startswith(p) for p in prefixes):
            found.append(name)
    return sorted(found)


def resolve_uplink_interfaces(
    *,
    eth_if: str,
    wifi_if: str,
    uplink_mode: str,
    explicit_interfaces: Sequence[str],
    tunnel_prefixes: Sequence[str],
) -> tuple[str, ...]:
    """Resolve the ordered tuple of allowed egress interfaces for PRIMARY forwarding.

    In `auto_tunnel` mode, includes `wifi_if`, the kernel's effective internet
    egress interface (catching Tailscale/WireGuard/OpenVPN/VMware tunnels even
    when they use policy routing tables), any UP interfaces matching
    `tunnel_prefixes`, and any extra `explicit_interfaces`.
    """
    if uplink_mode == "wifi_only":
        return (wifi_if,)
    if uplink_mode == "explicit":
        seen = [i for i in explicit_interfaces if i and i not in ("lo", eth_if)]
        return tuple(dict.fromkeys(seen or [wifi_if]))

    # auto_tunnel
    candidates: list[str] = [wifi_if]
    for probe_ip in ("1.1.1.1", "2606:4700:4700::1111"):
        dev = get_effective_egress_dev(probe_ip)
        if dev and dev not in ("lo", eth_if):
            candidates.append(dev)
    candidates.extend(list_up_tunnel_interfaces(tunnel_prefixes, exclude=(eth_if,)))
    candidates.extend(i for i in explicit_interfaces if i and i not in ("lo", eth_if))
    return tuple(dict.fromkeys(candidates))
