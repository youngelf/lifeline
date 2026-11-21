# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Connectivity and L2/DHCP probes for Lifeline.

Implements three critical probes in pure Python 3 stdlib:
1. **Policy-routed Wi-Fi health probe** (`WifiProber`):
   Maintains a dedicated Linux policy routing table (default `table 200`,
   `rule from <WIFI_IP> lookup 200 priority 10200`) and executes non-blocking
   TCP connect probes bound via `SO_BINDTODEVICE` + source Wi-Fi IP. This
   guarantees probes NEVER leak onto Ethernet in FAILOVER mode and pass strict
   `rp_filter=1` checks.
2. **Raw `AF_PACKET` DHCP server detector** (`probe_dhcp_server`):
   Crafts and sends an RFC 2131 `DHCPDISCOVER` frame directly over Ethernet
   without binding UDP port 68 (avoiding `EADDRINUSE` conflicts with NM).
3. **Raw `AF_PACKET` ARP DAD probe** (`probe_arp_conflict`):
   Implements RFC 5227 ARP duplicate-address detection for `ETH_IP` with zero
   dependency on external `arping` variants.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import logging
import os
import random
import select
import socket
import struct
import time
from typing import Iterable, Optional

from lifeline.config import parse_target_endpoint
from lifeline.net_utils import run_cmd_sync

LOG = logging.getLogger("lifeline.probe")

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"


@dataclass(frozen=True)
class DhcpOfferInfo:
    server_ip: str
    server_mac: str
    offered_ip: str
    xid: int


@dataclass(frozen=True)
class WifiProbeResult:
    healthy: bool
    v4_ok: bool
    v6_ok: bool
    detail: str
    latency_ms: Optional[float] = None


def mac_str_to_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def mac_bytes_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])


def _ones_complement_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_dhcp_discover_frame(src_mac: str, xid: int) -> bytes:
    """Build a complete Ethernet + IPv4 + UDP + BOOTP/DHCPDISCOVER packet."""
    src_mac_b = mac_str_to_bytes(src_mac)
    dst_mac_b = b"\xff\xff\xff\xff\xff\xff"

    # BOOTP header (236 bytes) + magic cookie (4) + options (padded >= 300 total)
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,  # op: BOOTREQUEST
        1,  # htype: Ethernet
        6,  # hlen: 6
        0,  # hops
        xid & 0xFFFFFFFF,
        0,  # secs
        0x8000,  # flags: Broadcast bit so servers may broadcast DHCPOFFER
        b"\x00\x00\x00\x00",  # ciaddr
        b"\x00\x00\x00\x00",  # yiaddr
        b"\x00\x00\x00\x00",  # siaddr
        b"\x00\x00\x00\x00",  # giaddr
        src_mac_b + b"\x00" * 10,  # chaddr
        b"\x00" * 64,  # sname
        b"\x00" * 128,  # file
    )
    options = bytes(
        [
            53, 1, 1,        # Option 53: DHCP Message Type = DHCPDISCOVER (1)
            55, 3, 1, 3, 6,  # Option 55: Parameter Request List (mask, router, dns)
            255,             # End
        ]
    )
    dhcp_payload = bootp + DHCP_MAGIC_COOKIE + options
    if len(dhcp_payload) < 300:
        dhcp_payload += b"\x00" * (300 - len(dhcp_payload))

    udp_len = 8 + len(dhcp_payload)
    src_ip = b"\x00\x00\x00\x00"
    dst_ip = b"\xff\xff\xff\xff"

    # Compute UDP checksum with IPv4 pseudo-header
    udp_header_zero = struct.pack("!HHHH", 68, 67, udp_len, 0)
    pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 17, udp_len)
    udp_cksum = _ones_complement_checksum(pseudo + udp_header_zero + dhcp_payload)
    if udp_cksum == 0:
        udp_cksum = 0xFFFF
    udp_header = struct.pack("!HHHH", 68, 67, udp_len, udp_cksum)

    # IPv4 header (20 bytes)
    ip_total_len = 20 + udp_len
    ip_hdr_zero = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # Version 4, IHL 5
        0,     # DSCP/ECN
        ip_total_len,
        xid & 0xFFFF,
        0,     # Flags/Fragment
        64,    # TTL
        17,    # Protocol: UDP
        0,     # Checksum placeholder
        src_ip,
        dst_ip,
    )
    ip_cksum = _ones_complement_checksum(ip_hdr_zero)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        xid & 0xFFFF,
        0,
        64,
        17,
        ip_cksum,
        src_ip,
        dst_ip,
    )

    eth_hdr = struct.pack("!6s6sH", dst_mac_b, src_mac_b, ETH_P_IP)
    return eth_hdr + ip_hdr + udp_header + dhcp_payload


def parse_dhcp_offer_frame(
    frame: bytes,
    expected_xid: int,
    our_mac: str,
) -> Optional[DhcpOfferInfo]:
    """Parse an incoming raw Ethernet frame and return `DhcpOfferInfo` if it is a matching DHCPOFFER."""
    if len(frame) < 14 + 20 + 8 + 240:
        return None
    dst_mac_b, src_mac_b, eth_type = struct.unpack("!6s6sH", frame[:14])
    if eth_type != ETH_P_IP:
        return None
    src_mac = mac_bytes_to_str(src_mac_b)
    if src_mac == our_mac.lower():
        return None
    # Accept broadcast or unicast addressed to us
    dst_mac = mac_bytes_to_str(dst_mac_b)
    if dst_mac not in ("ff:ff:ff:ff:ff:ff", our_mac.lower()):
        return None

    ip_start = 14
    ihl = (frame[ip_start] & 0x0F) * 4
    if ihl < 20 or len(frame) < ip_start + ihl + 8 + 240:
        return None
    ip_proto = frame[ip_start + 9]
    if ip_proto != 17:
        return None
    ip_src_str = socket.inet_ntoa(frame[ip_start + 12 : ip_start + 16])

    udp_start = ip_start + ihl
    sport, dport, _udp_len, _cksum = struct.unpack("!HHHH", frame[udp_start : udp_start + 8])
    if sport != 67 or dport != 68:
        return None

    bootp_start = udp_start + 8
    bootp = frame[bootp_start:]
    if len(bootp) < 240:
        return None
    op, _htype, _hlen, _hops, xid = struct.unpack("!BBBBI", bootp[:8])
    if op != 2 or xid != (expected_xid & 0xFFFFFFFF):
        return None
    if bootp[236:240] != DHCP_MAGIC_COOKIE:
        return None

    offered_ip = socket.inet_ntoa(bootp[16:20])
    msg_type: Optional[int] = None
    server_id: Optional[str] = None

    idx = 240
    while idx < len(bootp):
        opt = bootp[idx]
        if opt == 0:
            idx += 1
            continue
        if opt == 255:
            break
        if idx + 1 >= len(bootp):
            break
        opt_len = bootp[idx + 1]
        val = bootp[idx + 2 : idx + 2 + opt_len]
        if len(val) < opt_len:
            break
        if opt == 53 and opt_len == 1:
            msg_type = val[0]
        elif opt == 54 and opt_len == 4:
            server_id = socket.inet_ntoa(val)
        idx += 2 + opt_len

    if msg_type != 2:  # 2 = DHCPOFFER
        return None

    return DhcpOfferInfo(
        server_ip=server_id or ip_src_str,
        server_mac=src_mac,
        offered_ip=offered_ip,
        xid=xid,
    )


def probe_dhcp_server_sync(
    ifname: str,
    our_mac: str,
    timeout_sec: float = 1.5,
    ignore_ips: Optional[set[str]] = None,
) -> Optional[DhcpOfferInfo]:
    """Send a raw `DHCPDISCOVER` on `ifname` and wait up to `timeout_sec` for a `DHCPOFFER`.

    Ignores offers originating from `our_mac` or any IP in `ignore_ips`.
    """
    ignore_ips = ignore_ips or set()
    xid = random.getrandbits(32)
    frame = build_dhcp_discover_frame(our_mac, xid)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    try:
        sock.bind((ifname, ETH_P_IP))
        sock.setblocking(False)
        sock.send(frame)
        deadline = time.monotonic() + timeout_sec
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            rlist, _, _ = select.select([sock], [], [], remaining)
            if not rlist:
                return None
            pkt = sock.recv(4096)
            offer = parse_dhcp_offer_frame(pkt, xid, our_mac)
            if offer is None:
                continue
            if offer.server_ip in ignore_ips:
                continue
            return offer
    except OSError as exc:
        LOG.debug("DHCPDISCOVER probe failed on %s: %s", ifname, exc)
        return None
    finally:
        sock.close()


def build_arp_probe_frame(src_mac: str, target_ip: str) -> bytes:
    """Build an RFC 5227 ARP Probe frame (sender IP = 0.0.0.0, target IP = `target_ip`)."""
    src_mac_b = mac_str_to_bytes(src_mac)
    dst_mac_b = b"\xff\xff\xff\xff\xff\xff"
    eth_hdr = struct.pack("!6s6sH", dst_mac_b, src_mac_b, ETH_P_ARP)
    arp_body = struct.pack(
        "!HHBBH6s4s6s4s",
        1,       # HTYPE Ethernet
        ETH_P_IP,
        6,       # HLEN
        4,       # PLEN
        1,       # OPER: ARP Request
        src_mac_b,
        b"\x00\x00\x00\x00",  # sender IP 0.0.0.0 per RFC 5227
        b"\x00" * 6,          # target MAC 00:00:00:00:00:00
        socket.inet_aton(target_ip),
    )
    return eth_hdr + arp_body


def parse_arp_conflict_frame(frame: bytes, target_ip: str, our_mac: str) -> Optional[str]:
    """Return conflicting MAC address if `frame` is an ARP reply/probe claiming `target_ip`."""
    if len(frame) < 42:
        return None
    _dst, _src, eth_type = struct.unpack("!6s6sH", frame[:14])
    if eth_type != ETH_P_ARP:
        return None
    htype, ptype, hlen, plen, oper, sha, spa, _tha, _tpa = struct.unpack(
        "!HHBBH6s4s6s4s", frame[14:42]
    )
    if htype != 1 or ptype != ETH_P_IP or hlen != 6 or plen != 4:
        return None
    sender_mac = mac_bytes_to_str(sha)
    if sender_mac == our_mac.lower():
        return None
    sender_ip = socket.inet_ntoa(spa)
    if oper in (1, 2) and sender_ip == target_ip:
        return sender_mac
    return None


def probe_arp_conflict_sync(
    ifname: str,
    our_mac: str,
    target_ip: str,
    timeout_sec: float = 1.0,
) -> Optional[str]:
    """Check if another host on `ifname` already owns `target_ip`.

    Returns the conflicting peer's MAC address if a conflict exists, else None.
    """
    frame = build_arp_probe_frame(our_mac, target_ip)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    try:
        sock.bind((ifname, ETH_P_ARP))
        sock.setblocking(False)
        for _ in range(2):
            sock.send(frame)
            deadline = time.monotonic() + (timeout_sec / 2.0)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                rlist, _, _ = select.select([sock], [], [], remaining)
                if not rlist:
                    break
                pkt = sock.recv(2048)
                conflict = parse_arp_conflict_frame(pkt, target_ip, our_mac)
                if conflict:
                    return conflict
        return None
    except OSError as exc:
        LOG.debug("ARP conflict check error on %s: %s", ifname, exc)
        return None
    finally:
        sock.close()


class PolicyRouteManager:
    """Manages Linux policy routing table (`table 200`) for Wi-Fi-bound probes."""

    def __init__(self, table_id: int = 200, rule_priority: int = 4000) -> None:
        self.table_id = table_id
        self.rule_priority = rule_priority
        self._active_v4: Optional[tuple[str, str, str]] = None  # (iface, ip, gw)
        self._active_v6: Optional[tuple[str, str, str]] = None

    def sync(
        self,
        wifi_if: Optional[str],
        wifi_ip4: Optional[ipaddress.IPv4Address],
        wifi_gw4: Optional[ipaddress.IPv4Address],
        wifi_ip6: Optional[ipaddress.IPv6Address],
        wifi_gw6: Optional[ipaddress.IPv6Address],
    ) -> None:
        """Keep `table 200` and source `ip rule`s in sync with current Wi-Fi L3 info."""
        desired_v4 = (
            (wifi_if, str(wifi_ip4), str(wifi_gw4))
            if (wifi_if and wifi_ip4 and wifi_gw4)
            else None
        )
        if desired_v4 != self._active_v4:
            self._clear_v4()
            if desired_v4 is not None:
                iface, ip_s, gw_s = desired_v4
                r1 = run_cmd_sync(
                    ["ip", "route", "replace", "default", "via", gw_s, "dev", iface, "table", str(self.table_id)]
                )
                r2 = run_cmd_sync(
                    [
                        "ip",
                        "rule",
                        "add",
                        "from",
                        f"{ip_s}/32",
                        "lookup",
                        str(self.table_id),
                        "priority",
                        str(self.rule_priority),
                    ]
                )
                if r1.returncode == 0 and r2.returncode == 0:
                    self._active_v4 = desired_v4
                else:
                    LOG.warning("Failed installing IPv4 probe policy route: %s %s", r1.stderr, r2.stderr)

        desired_v6 = (
            (wifi_if, str(wifi_ip6), str(wifi_gw6))
            if (wifi_if and wifi_ip6 and wifi_gw6)
            else None
        )
        if desired_v6 != self._active_v6:
            self._clear_v6()
            if desired_v6 is not None:
                iface, ip6_s, gw6_s = desired_v6
                r1 = run_cmd_sync(
                    ["ip", "-6", "route", "replace", "default", "via", gw6_s, "dev", iface, "table", str(self.table_id)]
                )
                r2 = run_cmd_sync(
                    [
                        "ip",
                        "-6",
                        "rule",
                        "add",
                        "from",
                        f"{ip6_s}/128",
                        "lookup",
                        str(self.table_id),
                        "priority",
                        str(self.rule_priority),
                    ]
                )
                if r1.returncode == 0 and r2.returncode == 0:
                    self._active_v6 = desired_v6
                else:
                    LOG.debug("Failed installing IPv6 probe policy route: %s %s", r1.stderr, r2.stderr)

    def _clear_v4(self) -> None:
        run_cmd_sync(["ip", "rule", "del", "priority", str(self.rule_priority)])
        run_cmd_sync(["ip", "route", "flush", "table", str(self.table_id)])
        self._active_v4 = None

    def _clear_v6(self) -> None:
        run_cmd_sync(["ip", "-6", "rule", "del", "priority", str(self.rule_priority)])
        run_cmd_sync(["ip", "-6", "route", "flush", "table", str(self.table_id)])
        self._active_v6 = None

    def cleanup(self) -> None:
        """Remove all lifeline probe routing rules and table entries."""
        self._clear_v4()
        self._clear_v6()


async def _tcp_probe_bound(
    family: socket.AddressFamily,
    iface: str,
    local_ip: str,
    remote_ip: str,
    remote_port: int,
    timeout_sec: float,
) -> Optional[float]:
    """Attempt a TCP connect strictly bound to `(iface, local_ip)`.

    Returns TCP handshake RTT in milliseconds on success, or None on failure.
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode("utf-8") + b"\x00")
        sock.bind((local_ip, 0))
        addr = (remote_ip, remote_port) if family == socket.AF_INET else (remote_ip, remote_port, 0, 0)
        t0 = time.monotonic()
        await asyncio.wait_for(loop.sock_connect(sock, addr), timeout=timeout_sec)
        return round((time.monotonic() - t0) * 1000.0, 2)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        sock.close()


async def probe_wifi_connectivity(
    wifi_if: str,
    wifi_ip4: Optional[ipaddress.IPv4Address],
    wifi_gw4: Optional[ipaddress.IPv4Address],
    wifi_ip6: Optional[ipaddress.IPv6Address],
    wifi_gw6: Optional[ipaddress.IPv6Address],
    *,
    mode: str,
    ipv4_targets: Iterable[str],
    ipv6_targets: Iterable[str],
    timeout_sec: float,
) -> WifiProbeResult:
    """Probe Wi-Fi connectivity strictly over `wifi_if` (never over Ethernet)."""
    if mode == "gateway":
        tasks_v4 = (
            [
                _tcp_probe_bound(
                    socket.AF_INET, wifi_if, str(wifi_ip4), str(wifi_gw4), port, timeout_sec
                )
                for port in (53, 80, 443)
            ]
            if (wifi_ip4 and wifi_gw4)
            else []
        )
        results = await asyncio.gather(*tasks_v4) if tasks_v4 else []
        rtts = [r for r in results if r is not None]
        v4_ok = bool(rtts)
        best_rtt = min(rtts) if rtts else None
        detail = f"gateway rtt={best_rtt:.1f}ms" if best_rtt is not None else "gateway"
        return WifiProbeResult(healthy=v4_ok, v4_ok=v4_ok, v6_ok=False, detail=detail, latency_ms=best_rtt)

    # mode == "internet"
    v4_tasks = []
    if wifi_ip4 and wifi_gw4:
        for t in ipv4_targets:
            host, port = parse_target_endpoint(t)
            v4_tasks.append(
                _tcp_probe_bound(socket.AF_INET, wifi_if, str(wifi_ip4), host, port, timeout_sec)
            )

    v6_tasks = []
    if wifi_ip6 and wifi_gw6:
        for t in ipv6_targets:
            host, port = parse_target_endpoint(t)
            v6_tasks.append(
                _tcp_probe_bound(socket.AF_INET6, wifi_if, str(wifi_ip6), host, port, timeout_sec)
            )

    v4_results = await asyncio.gather(*v4_tasks) if v4_tasks else []
    v6_results = await asyncio.gather(*v6_tasks) if v6_tasks else []
    v4_rtts = [r for r in v4_results if r is not None]
    v6_rtts = [r for r in v6_results if r is not None]
    v4_ok = bool(v4_rtts)
    v6_ok = bool(v6_rtts)
    all_rtts = v4_rtts + v6_rtts
    best_rtt = min(all_rtts) if all_rtts else None
    healthy = v4_ok or v6_ok
    detail = (
        f"v4={v4_ok} v6={v6_ok} rtt={best_rtt:.1f}ms"
        if best_rtt is not None
        else f"v4={v4_ok} v6={v6_ok}"
    )
    return WifiProbeResult(
        healthy=healthy, v4_ok=v4_ok, v6_ok=v6_ok, detail=detail, latency_ms=best_rtt
    )
