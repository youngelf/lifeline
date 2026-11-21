# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Network configuration backends for Lifeline."""

from lifeline.backends.base import InterfacePair, NetworkBackend
from lifeline.backends.networkd import NetworkdBackend
from lifeline.backends.networkmanager import NetworkManagerBackend

__all__ = [
    "InterfacePair",
    "NetworkBackend",
    "NetworkManagerBackend",
    "NetworkdBackend",
]
