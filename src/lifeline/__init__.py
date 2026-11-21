# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Lifeline: Wi-Fi-aware Ethernet router and DHCP failover daemon.

Provides portable, fail-safe Ethernet sharing when Wi-Fi is healthy, automatic
secondary standby & deterministic leader election when multiple laptops or an
external DHCP server share the same Ethernet switch, and automatic DHCP-client
failover when Wi-Fi connectivity drops.
"""

__version__ = "0.1.0"
__author__ = "Vikram Aggarwal"
__license__ = "GPL-3.0-or-later"
__all__ = ["__version__", "__author__", "__license__"]
