# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Pure, side-effect-free state machine for Lifeline mode & election transitions.

Modes:
    IDLE       - Ethernet carrier is down (cable unplugged). No DHCP server, no
                 forwarding.
    FAILOVER   - Wi-Fi is unhealthy (or startup safe default). Ethernet asks an
                 upstream DHCP server for an IP, gateway, and DNS; forwarding is
                 blocked.
    SECONDARY  - Wi-Fi is healthy AND Ethernet carrier is up, but ANOTHER DHCP
                 server (external router or another lifeline PRIMARY) is active.
                 Ethernet stays in standby DHCP (never-default, ignore-auto-dns)
                 while Wi-Fi stays the laptop's uplink; routinely monitors the
                 primary DHCP server.
    ELECTION   - Wi-Fi is healthy, Ethernet carrier is up, and no primary DHCP
                 server was heard. Waits deterministic `rank * rank_backoff_sec`
                 before claiming PRIMARY so up to 5 laptops never collide.
    PRIMARY    - Wi-Fi is healthy, Ethernet carrier is up, and this laptop owns
                 the segment: manual `ETH_IP`, `dnsmasq` running with MAC table,
                 IPv4+IPv6 forwarding + NAT enabled for active DHCP clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Mode(str, Enum):
    IDLE = "IDLE"
    FAILOVER = "FAILOVER"
    SECONDARY = "SECONDARY"
    ELECTION = "ELECTION"
    PRIMARY = "PRIMARY"


@dataclass(frozen=True)
class StateMachineParams:
    fail_threshold: int = 3
    recover_threshold: int = 4
    min_dwell_sec: float = 15.0
    primary_miss_threshold: int = 2
    rank_backoff_sec: float = 2.0
    yield_to_external_dhcp: bool = True


@dataclass(frozen=True)
class TickObservation:
    """Snapshot of network & peer observations fed into `StateMachine.step()`."""

    now: float
    eth_carrier: bool
    wifi_link_up: bool
    wifi_probe_ok: Optional[bool]
    external_dhcp_seen: Optional[bool]
    peer_primary_seen: bool
    peer_primary_outranks_us: bool
    election_rank: int
    in_resume_grace: bool = False
    force_mode: Optional[str] = None


@dataclass(frozen=True)
class TransitionResult:
    previous: Mode
    current: Mode
    changed: bool
    reason: str


class StateMachine:
    """Deterministic state machine with hysteresis, dwell timer, and election."""

    def __init__(self, params: StateMachineParams, initial_now: float = 0.0) -> None:
        self.params = params
        self.mode: Mode = Mode.FAILOVER
        self.mode_entered_at: float = initial_now
        self.wifi_ok_streak: int = 0
        self.wifi_fail_streak: int = 0
        self.primary_miss_streak: int = 0
        self.election_started_at: float = initial_now
        self.last_reason: str = "startup safe default"

    def _dwell_elapsed(self, now: float) -> bool:
        return (now - self.mode_entered_at) >= self.params.min_dwell_sec

    def _transition(self, target: Mode, now: float, reason: str) -> TransitionResult:
        prev = self.mode
        if target == prev:
            return TransitionResult(prev, target, False, reason)
        self.mode = target
        self.mode_entered_at = now
        self.last_reason = reason
        if target == Mode.ELECTION:
            self.election_started_at = now
        if target != Mode.SECONDARY:
            self.primary_miss_streak = 0
        return TransitionResult(prev, target, True, reason)

    def _update_wifi_streaks(self, obs: TickObservation) -> None:
        if not obs.wifi_link_up:
            self.wifi_ok_streak = 0
            if not obs.in_resume_grace:
                self.wifi_fail_streak += 1
            return

        if obs.wifi_probe_ok is True:
            self.wifi_ok_streak += 1
            self.wifi_fail_streak = 0
        elif obs.wifi_probe_ok is False:
            self.wifi_ok_streak = 0
            if not obs.in_resume_grace:
                self.wifi_fail_streak += 1

    def wifi_is_healthy(self, obs: TickObservation) -> bool:
        return obs.wifi_link_up and self.wifi_ok_streak >= self.params.recover_threshold

    def wifi_has_failed(self, obs: TickObservation) -> bool:
        if obs.in_resume_grace:
            return False
        return self.wifi_fail_streak >= self.params.fail_threshold

    def step(self, obs: TickObservation) -> TransitionResult:
        """Advance the state machine by one tick and return any transition."""
        self._update_wifi_streaks(obs)

        # Operator manual override for field testing / maintenance.
        if obs.force_mode in ("failover", "secondary", "primary"):
            forced = Mode(obs.force_mode.upper())
            if self.mode != forced:
                return self._transition(forced, obs.now, f"manual override -> {forced.value}")
            return TransitionResult(self.mode, self.mode, False, "manual override held")

        # 1. Ethernet carrier loss immediately suspends serving/DHCP activity.
        if not obs.eth_carrier:
            if self.mode != Mode.IDLE:
                return self._transition(Mode.IDLE, obs.now, "ethernet carrier down")
            return TransitionResult(self.mode, self.mode, False, "ethernet carrier still down")

        # 2. Returning from IDLE when Ethernet cable is plugged back in.
        if self.mode == Mode.IDLE:
            if self.wifi_is_healthy(obs):
                if obs.external_dhcp_seen or obs.peer_primary_seen:
                    return self._transition(
                        Mode.SECONDARY, obs.now, "carrier restored; active DHCP server detected"
                    )
                return self._transition(
                    Mode.ELECTION, obs.now, "carrier restored with healthy Wi-Fi; starting election"
                )
            return self._transition(
                Mode.FAILOVER, obs.now, "carrier restored while Wi-Fi unhealthy"
            )

        # 3. FAILOVER mode: wait for Wi-Fi recovery (with hysteresis + dwell).
        if self.mode == Mode.FAILOVER:
            if self.wifi_is_healthy(obs) and self._dwell_elapsed(obs.now):
                if obs.external_dhcp_seen or obs.peer_primary_seen:
                    return self._transition(
                        Mode.SECONDARY,
                        obs.now,
                        "Wi-Fi recovered; existing DHCP server active -> SECONDARY",
                    )
                return self._transition(
                    Mode.ELECTION,
                    obs.now,
                    "Wi-Fi recovered and no DHCP server active -> ELECTION",
                )
            return TransitionResult(self.mode, self.mode, False, "holding FAILOVER")

        # 4. In any Wi-Fi-dependent mode (SECONDARY, ELECTION, PRIMARY), Wi-Fi failure -> FAILOVER.
        if self.wifi_has_failed(obs):
            if self.mode in (Mode.ELECTION, Mode.SECONDARY) or self._dwell_elapsed(obs.now):
                return self._transition(
                    Mode.FAILOVER,
                    obs.now,
                    f"Wi-Fi failed ({self.wifi_fail_streak} consecutive failures)",
                )

        # 5. SECONDARY mode: monitor external DHCP server & peer PRIMARY beacon.
        if self.mode == Mode.SECONDARY:
            if obs.peer_primary_seen or obs.external_dhcp_seen is True:
                self.primary_miss_streak = 0
                return TransitionResult(self.mode, self.mode, False, "primary DHCP active")
            if obs.external_dhcp_seen is False and not obs.peer_primary_seen:
                self.primary_miss_streak += 1
                if (
                    self.primary_miss_streak >= self.params.primary_miss_threshold
                    and self._dwell_elapsed(obs.now)
                ):
                    return self._transition(
                        Mode.ELECTION,
                        obs.now,
                        f"primary DHCP inactive ({self.primary_miss_streak} missed checks)",
                    )
            return TransitionResult(self.mode, self.mode, False, "monitoring primary DHCP")

        # 6. ELECTION mode: deterministic rank-based wait before promoting to PRIMARY.
        if self.mode == Mode.ELECTION:
            if obs.peer_primary_seen or obs.external_dhcp_seen is True:
                return self._transition(
                    Mode.SECONDARY, obs.now, "another primary appeared during election"
                )
            # Rank 0 waits a tiny settle window (0.5s); rank N waits 0.5s + N * backoff.
            required_wait = 0.5 + max(0, obs.election_rank) * self.params.rank_backoff_sec
            if (obs.now - self.election_started_at) >= required_wait:
                return self._transition(
                    Mode.PRIMARY,
                    obs.now,
                    f"won election (rank {obs.election_rank}, waited {required_wait:.1f}s)",
                )
            return TransitionResult(
                self.mode,
                self.mode,
                False,
                f"waiting election backoff (rank {obs.election_rank})",
            )

        # 7. PRIMARY mode: check for split-brain peer or newly attached external DHCP router.
        if self.mode == Mode.PRIMARY:
            if obs.peer_primary_seen and obs.peer_primary_outranks_us:
                return self._transition(
                    Mode.SECONDARY,
                    obs.now,
                    "higher-priority lifeline PRIMARY detected; yielding",
                )
            if self.params.yield_to_external_dhcp and obs.external_dhcp_seen is True:
                return self._transition(
                    Mode.SECONDARY,
                    obs.now,
                    "external DHCP server appeared on Ethernet; yielding",
                )
            return TransitionResult(self.mode, self.mode, False, "serving PRIMARY")

        return TransitionResult(self.mode, self.mode, False, "no change")
