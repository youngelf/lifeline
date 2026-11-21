# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""`dnsmasq --dhcp-script` lease hook updating nftables allowlist sets.

Invoked sequentially by `dnsmasq` as root whenever a lease is added (`add`),
refreshed/reloaded (`old`), or expired/released (`del`).

Only active when `LIFELINE_FWD_POLICY == "active_leases"` (the default).
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Optional

from lifeline.dhcp import parse_dnsmasq_leases
from lifeline.net_utils import run_cmd_sync

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _normalize_mac(raw: str) -> Optional[str]:
    cleaned = raw.strip().lower()
    if MAC_RE.match(cleaned):
        return cleaned
    return None


def _nft(args: list[str]) -> int:
    nft_bin = shutil.which("nft") or "/usr/sbin/nft"
    return run_cmd_sync([nft_bin, *args]).returncode


def handle_lease_event(
    action: str,
    id_or_mac: str,
    ip_str: str,
    *,
    env: dict[str, str],
) -> int:
    """Process one dnsmasq lease event and update nftables sets accordingly."""
    policy = env.get("LIFELINE_FWD_POLICY", "active_leases")
    if policy != "active_leases":
        return 0
    if action not in ("add", "old", "del"):
        return 0

    table = env.get("LIFELINE_NFT_TABLE", "lifeline")
    lease_file = Path(env.get("LIFELINE_LEASE_FILE", "/run/lifeline/dnsmasq.leases"))

    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return 0

    if isinstance(ip_obj, ipaddress.IPv4Address):
        mac = _normalize_mac(id_or_mac)
        if not mac:
            return 0
        if action in ("add", "old"):
            _nft(["add", "element", "inet", table, "allowed_v4", f"{{ {ip_obj} . {mac} }}"])
            _nft(["add", "element", "inet", table, "allowed_v6_mac", f"{{ {mac} }}"])
        elif action == "del":
            _nft(["destroy", "element", "inet", table, "allowed_v4", f"{{ {ip_obj} . {mac} }}"])
            # Only remove MAC from allowed_v6_mac if no other active lease uses this MAC.
            still_active = any(
                lease.mac == mac and lease.ip != str(ip_obj)
                for lease in parse_dnsmasq_leases(lease_file)
            )
            if not still_active:
                _nft(["destroy", "element", "inet", table, "allowed_v6_mac", f"{{ {mac} }}"])
        return 0

    # IPv6 lease event: dnsmasq supplies the client's hardware MAC in DNSMASQ_MAC.
    mac = _normalize_mac(env.get("DNSMASQ_MAC", ""))
    if not mac:
        return 0
    if action in ("add", "old"):
        _nft(["add", "element", "inet", table, "allowed_v6_mac", f"{{ {mac} }}"])
    elif action == "del":
        still_active = any(
            lease.mac == mac and lease.ip != str(ip_obj)
            for lease in parse_dnsmasq_leases(lease_file)
        )
        if not still_active:
            _nft(["destroy", "element", "inet", table, "allowed_v6_mac", f"{{ {mac} }}"])
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 3:
        return 0
    action, id_or_mac, ip_str = args[0], args[1], args[2]
    return handle_lease_event(action, id_or_mac, ip_str, env=dict(os.environ))


if __name__ == "__main__":
    sys.exit(main())
