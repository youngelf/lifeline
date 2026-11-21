# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Abstract interface for OS network-configuration backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class InterfacePair:
    eth_if: Optional[str]
    eth_mac: Optional[str]
    wifi_if: Optional[str]
    wifi_mac: Optional[str]


class NetworkBackend(ABC):
    """Abstraction over NetworkManager (Desktop) and systemd-networkd (Server)."""

    # True if kernel processes incoming RAs on Wi-Fi (needs accept_ra=2 when forwarding=1).
    # NetworkManager handles RAs in userspace via libndp, so False for NM.
    uses_kernel_ra: bool = False

    @abstractmethod
    async def discover_interfaces(self, eth_sel: str, wifi_sel: str) -> InterfacePair:
        """Resolve `eth` and `wifi` selectors ("auto", name, or "mac:...")."""

    @abstractmethod
    async def apply_eth_static(
        self,
        eth_if: str,
        v4_cidr: str,
        v6_cidr: Optional[str],
    ) -> None:
        """Configure `eth_if` with manual static IPv4 (+ optional ULA IPv6) and NO default route."""

    @abstractmethod
    async def apply_eth_dhcp_failover(self, eth_if: str, metric: int) -> None:
        """Configure `eth_if` as a primary DHCPv4/v6 client accepting gateway & DNS."""

    @abstractmethod
    async def apply_eth_dhcp_standby(self, eth_if: str, metric: int) -> None:
        """Configure `eth_if` as a standby DHCP client (never-default, ignore-auto-dns, may-fail)."""

    @abstractmethod
    async def set_wifi_dns_default_route(self, wifi_if: str, enabled: bool) -> None:
        """Enable or disable `systemd-resolved` default-route DNS usage on `wifi_if`."""

    @abstractmethod
    async def cleanup(self, eth_if: Optional[str], wifi_if: Optional[str]) -> None:
        """Remove temporary runtime profiles and restore default Wi-Fi DNS routing."""
