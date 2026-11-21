# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Multi-laptop coordination beacons and deterministic latency-aware election.

Up to 5 (or more) laptops running `lifeline` may sit on the same Ethernet
switch simultaneously. This module implements a lightweight link-local IPv6
multicast (`ff02::1`, UDP port 41924, bound strictly to the Ethernet interface)
presence protocol:

- Works even when Ethernet has **no IPv4 address** (e.g., in SECONDARY mode
  while another laptop's table-only DHCP server does not list this laptop).
- Every active `lifeline` daemon broadcasts a small JSON beacon every
  `beacon_interval_sec` containing its `priority`, `wifi_ok`, and EWMA probe
  `latency_ms`.
- Election rank & split-brain tie-breaking order by:
  `(priority, latency_bucket(latency_ms), eth_mac.lower())`
  so among equal-priority laptops, the one with noticeably lower Wi-Fi probe
  connection latency wins, while `latency_bucket_ms` prevents jitter flapping
  and `eth_mac` guarantees a deterministic tie-break.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import socket
import struct
import time
from typing import Dict, Optional

LOG = logging.getLogger("lifeline.election")

MCAST_GROUP_V6 = "ff02::1"
UNKNOWN_LATENCY_BUCKET = 999_999


@dataclass(frozen=True)
class PeerRecord:
    node_id: str
    mac: str
    state: str
    priority: int
    wifi_ok: bool
    last_seen: float
    latency_ms: Optional[float] = None


def latency_bucket(latency_ms: Optional[float], bucket_ms: float = 20.0) -> int:
    """Quantize probe latency into coarse buckets so tiny jitter doesn't flip rank."""
    if latency_ms is None or latency_ms < 0:
        return UNKNOWN_LATENCY_BUCKET
    step = bucket_ms if bucket_ms > 0 else 20.0
    return int(round(latency_ms / step))


def compute_rank(
    our_priority: int,
    our_mac: str,
    peers: Dict[str, PeerRecord],
    *,
    now: float,
    peer_timeout_sec: float,
    our_latency_ms: Optional[float] = None,
    latency_bucket_ms: float = 20.0,
) -> tuple[int, bool, bool]:
    """Compute `(election_rank, peer_primary_seen, peer_primary_outranks_us)`.

    Deterministic ordering key is `(priority, latency_bucket, mac.lower())` where
    smaller tuple wins (lower priority -> lower probe latency -> lower MAC).
    """
    our_key = (
        our_priority,
        latency_bucket(our_latency_ms, latency_bucket_ms),
        our_mac.lower(),
    )
    active_peers = [
        p
        for p in peers.values()
        if (now - p.last_seen) <= peer_timeout_sec and p.mac.lower() != our_mac.lower()
    ]

    peer_primary_seen = any(p.state == "PRIMARY" for p in active_peers)

    def peer_key(p: PeerRecord) -> tuple[int, int, str]:
        return (p.priority, latency_bucket(p.latency_ms, latency_bucket_ms), p.mac.lower())

    peer_primary_outranks_us = any(
        p.state == "PRIMARY" and peer_key(p) < our_key
        for p in active_peers
    )

    outranking_candidates = sum(
        1
        for p in active_peers
        if p.wifi_ok and peer_key(p) < our_key
    )
    return outranking_candidates, peer_primary_seen, peer_primary_outranks_us


def encode_beacon(
    node_id: str,
    mac: str,
    state: str,
    priority: int,
    wifi_ok: bool,
    seq: int,
    latency_ms: Optional[float] = None,
) -> bytes:
    payload = {
        "v": 1,
        "node_id": node_id,
        "mac": mac.lower(),
        "state": state,
        "priority": priority,
        "wifi_ok": wifi_ok,
        "latency_ms": round(latency_ms, 1) if latency_ms is not None else None,
        "seq": seq,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_beacon(data: bytes) -> Optional[dict]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict) or obj.get("v") != 1:
        return None
    if not isinstance(obj.get("mac"), str) or not isinstance(obj.get("state"), str):
        return None
    if not isinstance(obj.get("priority"), int) or not isinstance(obj.get("wifi_ok"), bool):
        return None
    lat = obj.get("latency_ms")
    if lat is not None and not isinstance(lat, (int, float)):
        return None
    return obj


class BeaconBus:
    """Async UDP link-local multicast beacon sender & listener on Ethernet."""

    def __init__(
        self,
        port: int = 41924,
        peer_timeout_sec: float = 4.0,
        latency_bucket_ms: float = 20.0,
    ) -> None:
        self.port = port
        self.peer_timeout_sec = peer_timeout_sec
        self.latency_bucket_ms = latency_bucket_ms
        self.peers: Dict[str, PeerRecord] = {}
        self._iface: Optional[str] = None
        self._ifindex: int = 0
        self._sock: Optional[socket.socket] = None
        self._rx_task: Optional[asyncio.Task] = None
        self._seq: int = 0

    def bind(self, ifname: str) -> None:
        if self._iface == ifname and self._sock is not None:
            return
        self.close()
        try:
            ifindex = socket.if_nametoindex(ifname)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode("utf-8") + b"\x00")
            sock.bind(("::", self.port, 0, ifindex))
            mreq = socket.inet_pton(socket.AF_INET6, MCAST_GROUP_V6) + struct.pack("@I", ifindex)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack("@I", ifindex))
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
            sock.setblocking(False)
            self._sock = sock
            self._iface = ifname
            self._ifindex = ifindex
            self._rx_task = asyncio.create_task(self._recv_loop())
            LOG.debug("BeaconBus bound to %s (ifindex=%d port=%d)", ifname, ifindex, self.port)
        except OSError as exc:
            LOG.warning("Unable to bind BeaconBus on %s: %s", ifname, exc)
            self.close()

    async def _recv_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while self._sock is not None:
            try:
                data, _addr = await loop.sock_recvfrom(self._sock, 2048)
            except asyncio.CancelledError:
                return
            except OSError as exc:
                LOG.debug("BeaconBus recv error: %s", exc)
                await asyncio.sleep(0.5)
                continue

            msg = decode_beacon(data)
            if not msg:
                continue
            now = time.monotonic()
            mac = msg["mac"].lower()
            lat = msg.get("latency_ms")
            self.peers[mac] = PeerRecord(
                node_id=str(msg.get("node_id", mac)),
                mac=mac,
                state=msg["state"],
                priority=msg["priority"],
                wifi_ok=msg["wifi_ok"],
                last_seen=now,
                latency_ms=float(lat) if lat is not None else None,
            )

    def send_beacon(
        self,
        node_id: str,
        our_mac: str,
        state: str,
        priority: int,
        wifi_ok: bool,
        latency_ms: Optional[float] = None,
    ) -> None:
        if self._sock is None or self._ifindex == 0:
            return
        self._seq += 1
        pkt = encode_beacon(node_id, our_mac, state, priority, wifi_ok, self._seq, latency_ms)
        try:
            self._sock.sendto(pkt, (MCAST_GROUP_V6, self.port, 0, self._ifindex))
        except OSError as exc:
            LOG.debug("BeaconBus send failed on %s: %s", self._iface, exc)

    def prune_stale(self, now: float) -> None:
        stale = [k for k, v in self.peers.items() if (now - v.last_seen) > self.peer_timeout_sec * 3]
        for k in stale:
            del self.peers[k]

    def get_election_view(
        self,
        our_priority: int,
        our_mac: str,
        our_latency_ms: Optional[float] = None,
        now: Optional[float] = None,
    ) -> tuple[int, bool, bool]:
        ts = time.monotonic() if now is None else now
        self.prune_stale(ts)
        return compute_rank(
            our_priority,
            our_mac,
            self.peers,
            now=ts,
            peer_timeout_sec=self.peer_timeout_sec,
            our_latency_ms=our_latency_ms,
            latency_bucket_ms=self.latency_bucket_ms,
        )

    def close(self) -> None:
        if self._rx_task is not None:
            self._rx_task.cancel()
            self._rx_task = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._iface = None
        self._ifindex = 0
