# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Atomic `nftables` forwarding/NAT rulesets and optional `ufw` coexistence.

All Lifeline packet-filtering and NAT rules live inside a single isolated
`table inet <nft_table>` (default `lifeline`) so host rules (e.g. Docker) are
never flushed or overwritten.

- In `PRIMARY` mode (`active_leases` policy):
  * Supports both Wi-Fi and active VPN/tunnel uplinks (`oifname { "wlan0", "tailscale0", ... }`).
  * IPv4 forwarding requires `ip saddr . ether saddr @allowed_v4` (anti-spoof).
  * IPv6 forwarding requires `ip6 saddr <ULA/64> ether saddr @allowed_v6_mac`.
  * Return traffic (`uplinks -> ETH`) is permitted only for `ct state established,related`.
  * TCP SYN MSS clamping (`maxseg size set rt mtu`) prevents path-MTU blackholes on VPN tunnels.
  * Outbound IPv4 and IPv6 ULA traffic is masqueraded onto the active uplink(s).
- In `FAILOVER`, `SECONDARY`, and `IDLE` modes:
  * All forwarding entering or leaving `ETH` is explicitly dropped and NAT rules
    are absent.
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
from typing import Iterable, Sequence, Union

from lifeline.config import LifelineConfig
from lifeline.dhcp import parse_dnsmasq_leases
from lifeline.net_utils import run_cmd_sync

LOG = logging.getLogger("lifeline.firewall")


def _fmt_if_expr(ifaces: Sequence[str]) -> str:
    unique = list(dict.fromkeys(ifaces))
    if len(unique) == 1:
        return f'"{unique[0]}"'
    quoted = ", ".join(f'"{i}"' for i in unique)
    return f"{{ {quoted} }}"


def render_primary_ruleset(
    cfg: LifelineConfig,
    eth_if: str,
    uplink_ifs: Union[str, Sequence[str]],
    allowed_v4_pairs: Iterable[tuple[str, str]] = (),
    allowed_v6_macs: Iterable[str] = (),
) -> str:
    """Render an atomic nftables script for PRIMARY sharing mode."""
    uplinks = [uplink_ifs] if isinstance(uplink_ifs, str) else list(uplink_ifs)
    if not uplinks:
        raise ValueError("At least one uplink interface is required for PRIMARY ruleset")
    uplink_expr = _fmt_if_expr(uplinks)

    table = cfg.forwarding.nft_table
    v4_subnet = str(cfg.lan.eth_ip.network)
    v6_subnet = str(cfg.lan.eth_ipv6_prefix)
    policy = cfg.forwarding.policy
    enable_v6 = cfg.forwarding.ipv6_mode == "ula_nat66"

    v4_elems = ", ".join(f"{ip} . {mac}" for ip, mac in sorted(set(allowed_v4_pairs)))
    v6_elems = ", ".join(sorted(set(allowed_v6_macs)))

    lines = [
        f"destroy table inet {table}",
        f"table inet {table} {{",
        "    set allowed_v4 {",
        "        type ipv4_addr . ether_addr",
    ]
    if v4_elems:
        lines.append(f"        elements = {{ {v4_elems} }}")
    lines.extend(
        [
            "    }",
            "    set allowed_v6_mac {",
            "        type ether_addr",
        ]
    )
    if v6_elems:
        lines.append(f"        elements = {{ {v6_elems} }}")
    lines.extend(
        [
            "    }",
            "    chain allow_fwd {",
            "        tcp flags syn tcp option maxseg size set rt mtu",
            "        accept",
            "    }",
            "    chain forward {",
            "        type filter hook forward priority filter; policy accept;",
        ]
    )

    if policy == "subnet":
        lines.append(
            f'        iifname "{eth_if}" oifname {uplink_expr} ip saddr {v4_subnet} jump allow_fwd'
        )
        if enable_v6:
            lines.append(
                f'        iifname "{eth_if}" oifname {uplink_expr} ip6 saddr {v6_subnet} jump allow_fwd'
            )
    else:
        lines.append(
            f'        iifname "{eth_if}" oifname {uplink_expr} ip saddr . ether saddr @allowed_v4 jump allow_fwd'
        )
        if enable_v6:
            lines.append(
                f'        iifname "{eth_if}" oifname {uplink_expr} ip6 saddr {v6_subnet} ether saddr @allowed_v6_mac jump allow_fwd'
            )

    lines.extend(
        [
            f'        iifname {uplink_expr} oifname "{eth_if}" ct state established,related jump allow_fwd',
            f'        iifname "{eth_if}" drop',
            f'        oifname "{eth_if}" drop',
            "    }",
            "    chain postrouting {",
            "        type nat hook postrouting priority srcnat; policy accept;",
            f'        iifname "{eth_if}" oifname {uplink_expr} ip saddr {v4_subnet} masquerade',
        ]
    )
    if enable_v6:
        lines.append(
            f'        iifname "{eth_if}" oifname {uplink_expr} ip6 saddr {v6_subnet} masquerade'
        )
    lines.extend(["    }", "}"])
    return "\n".join(lines) + "\n"


def render_block_ruleset(table: str, eth_if: str) -> str:
    """Render an atomic nftables script blocking all forwarding on `eth_if`."""
    return (
        f"destroy table inet {table}\n"
        f"table inet {table} {{\n"
        f"    chain forward {{\n"
        f"        type filter hook forward priority filter; policy accept;\n"
        f'        iifname "{eth_if}" drop\n'
        f'        oifname "{eth_if}" drop\n'
        f"    }}\n"
        f"}}\n"
    )


def _ip_in_dynamic_pool(cfg: LifelineConfig, ip_str: str) -> bool:
    if not cfg.dhcp.dynamic_pool_start or not cfg.dhcp.dynamic_pool_end:
        return False
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return int(cfg.dhcp.dynamic_pool_start) <= int(addr) <= int(cfg.dhcp.dynamic_pool_end)


def compute_initial_allowlists(cfg: LifelineConfig) -> tuple[list[tuple[str, str]], list[str]]:
    """Seed nftables allowlists according to `forwarding.policy` and `dynamic_pool`."""
    if cfg.forwarding.policy == "static_table":
        v4 = [(str(h.ipv4), h.mac) for h in cfg.hosts]
        v6 = [h.mac for h in cfg.hosts]
        return v4, v6
    if cfg.forwarding.policy == "active_leases":
        valid_pairs = {(str(h.ipv4), h.mac) for h in cfg.hosts}
        valid_macs = {h.mac for h in cfg.hosts}
        has_pool = bool(cfg.dhcp.dynamic_pool_start and cfg.dhcp.dynamic_pool_end)
        leases = parse_dnsmasq_leases(cfg.dhcp.runtime_dir / "dnsmasq.leases")
        v4: list[tuple[str, str]] = []
        v6: list[str] = []
        for lease in leases:
            if not lease.is_v6:
                if (lease.ip, lease.mac) in valid_pairs or _ip_in_dynamic_pool(cfg, lease.ip):
                    v4.append((lease.ip, lease.mac))
                    v6.append(lease.mac)
            else:
                if lease.mac in valid_macs or has_pool:
                    v6.append(lease.mac)
        return v4, v6
    return [], []


class FirewallManager:
    """Applies atomic `nftables` rulesets and optional `ufw` coexistence rules."""

    def __init__(self) -> None:
        self._ufw_installed_rules: list[list[str]] = []

    @staticmethod
    def _apply_nft_script(script: str) -> None:
        nft_bin = shutil.which("nft") or "/usr/sbin/nft"
        res = run_cmd_sync([nft_bin, "-f", "-"], input_text=script)
        if res.returncode != 0:
            raise RuntimeError(f"nft apply failed: {res.stderr.strip()}")

    @staticmethod
    def _is_ufw_active() -> bool:
        ufw_bin = shutil.which("ufw")
        if not ufw_bin:
            return False
        res = run_cmd_sync([ufw_bin, "status"])
        return res.returncode == 0 and "Status: active" in res.stdout

    def _sync_ufw_primary(
        self, cfg: LifelineConfig, eth_if: str, uplink_ifs: Sequence[str]
    ) -> None:
        if not cfg.forwarding.manage_ufw or not self._is_ufw_active():
            return
        self.clear_ufw_rules()
        ufw_bin = shutil.which("ufw") or "ufw"
        rules = [
            ["allow", "in", "on", eth_if, "proto", "udp", "to", "any", "port", "67", "comment", "lifeline-dhcp4"],
            ["allow", "in", "on", eth_if, "proto", "udp", "to", "any", "port", "547", "comment", "lifeline-dhcp6"],
            ["allow", "in", "on", eth_if, "to", "any", "port", "53", "comment", "lifeline-dns"],
            [
                "allow",
                "in",
                "on",
                eth_if,
                "proto",
                "udp",
                "to",
                "any",
                "port",
                str(cfg.election.beacon_port),
                "comment",
                "lifeline-beacon",
            ],
        ]
        for up_if in uplink_ifs:
            rules.append(
                ["route", "allow", "in", "on", eth_if, "out", "on", up_if, "comment", "lifeline-fwd"]
            )
        for rule in rules:
            res = run_cmd_sync([ufw_bin, *rule])
            if res.returncode == 0:
                self._ufw_installed_rules.append(rule)
            else:
                LOG.warning("Failed adding ufw rule %s: %s", rule, res.stderr.strip())

    def clear_ufw_rules(self) -> None:
        if not self._ufw_installed_rules:
            return
        ufw_bin = shutil.which("ufw")
        if not ufw_bin:
            self._ufw_installed_rules.clear()
            return
        for rule in reversed(self._ufw_installed_rules):
            run_cmd_sync([ufw_bin, "delete", *rule])
        self._ufw_installed_rules.clear()

    def apply_primary(
        self, cfg: LifelineConfig, eth_if: str, uplink_ifs: Union[str, Sequence[str]]
    ) -> None:
        uplinks = [uplink_ifs] if isinstance(uplink_ifs, str) else list(uplink_ifs)
        v4_pairs, v6_macs = compute_initial_allowlists(cfg)
        script = render_primary_ruleset(cfg, eth_if, uplinks, v4_pairs, v6_macs)
        self._apply_nft_script(script)
        self._sync_ufw_primary(cfg, eth_if, uplinks)
        LOG.info(
            "Applied PRIMARY nftables ruleset on %s -> %s (policy=%s, seeded v4=%d v6=%d)",
            eth_if,
            ",".join(uplinks),
            cfg.forwarding.policy,
            len(v4_pairs),
            len(v6_macs),
        )

    def apply_block(self, table: str, eth_if: str) -> None:
        self.clear_ufw_rules()
        script = render_block_ruleset(table, eth_if)
        self._apply_nft_script(script)
        LOG.info("Applied BLOCK nftables ruleset on %s", eth_if)

    @staticmethod
    def cleanup_table(table: str) -> None:
        nft_bin = shutil.which("nft") or "/usr/sbin/nft"
        run_cmd_sync([nft_bin, "destroy", "table", "inet", table])
