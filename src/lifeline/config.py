# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Configuration loading, RFC 4193 ULA derivation, and strict validation.

This module parses:
1. `/etc/lifeline/config.toml` (using Python's stdlib `tomllib`),
2. Optional `/etc/lifeline/config.env` overrides (`ETH_IP`, `ETH_IF`, etc.),
3. `/etc/lifeline/dhcp_hosts.csv` plus optional drop-ins under `hosts_dir`.

All validation happens eagerly so operators can run `lifelinectl validate`
offline before deploying or reloading configuration on a live laptop.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import tomllib
from typing import Iterable, Optional

DEFAULT_CONFIG_PATH = Path("/etc/lifeline/config.toml")
DEFAULT_ENV_PATH = Path("/etc/lifeline/config.env")
DEFAULT_MACHINE_ID_PATH = Path("/etc/machine-id")

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


class ConfigError(ValueError):
    """Raised when configuration or the MAC-to-IP host table is invalid."""


@dataclass(frozen=True)
class HostEntry:
    """One static Ethernet hardware-to-IP mapping from `dhcp_hosts.csv`."""

    mac: str
    ipv4: ipaddress.IPv4Address
    hostname: str
    ipv6: ipaddress.IPv6Address


@dataclass(frozen=True)
class InterfacesConfig:
    """Interface selection and network backend configuration."""

    eth: str = "auto"
    wifi: str = "auto"
    backend: str = "auto"


@dataclass(frozen=True)
class LanConfig:
    """Static LAN addressing used when this laptop is in PRIMARY mode."""

    eth_ip: ipaddress.IPv4Interface
    eth_ipv6_prefix: ipaddress.IPv6Network
    eth_ipv6_addr: ipaddress.IPv6Interface


@dataclass(frozen=True)
class DhcpConfig:
    """Managed dnsmasq DHCP/RA server configuration."""

    hosts_file: Path
    hosts_dir: Optional[Path]
    lease_time: str = "10m"
    authoritative: bool = False
    dynamic_pool_start: Optional[ipaddress.IPv4Address] = None
    dynamic_pool_end: Optional[ipaddress.IPv4Address] = None
    runtime_dir: Path = Path("/run/lifeline")
    lease_hook: Path = Path("/usr/local/libexec/lifeline-lease-hook")


@dataclass(frozen=True)
class ForwardingConfig:
    """Packet forwarding allowlist, tunnel uplinks, and NAT66/firewall settings."""

    policy: str = "active_leases"
    ipv6_mode: str = "ula_nat66"
    uplink_mode: str = "auto_tunnel"  # "auto_tunnel" | "wifi_only" | "explicit"
    uplink_interfaces: tuple[str, ...] = ()
    tunnel_prefixes: tuple[str, ...] = (
        "tailscale",
        "tun",
        "tap",
        "wg",
        "ppp",
        "vpn",
        "cscotun",
        "vmnet",
    )
    nft_table: str = "lifeline"
    manage_ufw: bool = True


@dataclass(frozen=True)
class HealthConfig:
    """Wi-Fi connectivity probing, hysteresis, and policy-routing settings."""

    mode: str = "internet"
    ipv4_targets: tuple[str, ...] = ("1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443")
    ipv6_targets: tuple[str, ...] = (
        "[2606:4700:4700::1111]:443",
        "[2001:4860:4860::8888]:443",
    )
    probe_interval_sec: float = 3.0
    probe_timeout_sec: float = 2.0
    fail_threshold: int = 3
    recover_threshold: int = 4
    min_dwell_sec: float = 15.0
    resume_grace_sec: float = 10.0
    probe_table_id: int = 200
    probe_rule_priority: int = 4000


@dataclass(frozen=True)
class ElectionConfig:
    """Shared-Ethernet multi-laptop standby and leader election settings."""

    beacon_interval_sec: float = 1.0
    beacon_port: int = 41924
    peer_timeout_sec: float = 4.0
    dhcp_probe_interval_sec: float = 5.0
    dhcp_probe_timeout_sec: float = 1.5
    primary_miss_threshold: int = 2
    priority: int = 100
    latency_bucket_ms: float = 20.0
    rank_backoff_sec: float = 2.0
    yield_to_external_dhcp: bool = True
    external_dhcp_check_interval_sec: float = 15.0
    arp_conflict_check: bool = True


@dataclass(frozen=True)
class RoutingConfig:
    """Interface route metrics used in FAILOVER vs SECONDARY modes."""

    failover_eth_metric: int = 100
    standby_eth_metric: int = 800


@dataclass(frozen=True)
class LifelineConfig:
    """Complete, validated configuration for `lifelined`."""

    config_path: Path
    interfaces: InterfacesConfig
    lan: LanConfig
    dhcp: DhcpConfig
    forwarding: ForwardingConfig
    health: HealthConfig
    election: ElectionConfig
    routing: RoutingConfig
    hosts: tuple[HostEntry, ...] = field(default_factory=tuple)


def normalize_mac(raw: str) -> str:
    """Validate and normalize an Ethernet MAC address to `aa:bb:cc:dd:ee:ff`.

    Rejects malformed strings, broadcast (`ff:ff:ff:ff:ff:ff`), all-zero, and
    multicast MACs (where the least-significant bit of the first octet is 1).
    """
    cleaned = raw.strip().replace("-", ":").lower()
    if not MAC_RE.match(cleaned):
        raise ConfigError(f"Invalid MAC address: {raw!r}")
    first_octet = int(cleaned[:2], 16)
    if first_octet & 0x01:
        raise ConfigError(f"Multicast/broadcast MAC is not valid for a host: {raw!r}")
    if cleaned == "00:00:00:00:00:00":
        raise ConfigError("All-zero MAC address is invalid")
    return cleaned


def derive_ula_prefix(machine_id_path: Path = DEFAULT_MACHINE_ID_PATH) -> ipaddress.IPv6Network:
    """Derive a deterministic RFC 4193 /64 ULA prefix from `/etc/machine-id`.

    Uses `fd` (L=1 locally assigned) + the first 40 bits of SHA-256 over
    `lifeline:<machine-id>` as the Global ID, and `0000` as the Subnet ID.
    Falls back to a hostname-based hash if `/etc/machine-id` is absent.
    """
    if machine_id_path.exists():
        seed = machine_id_path.read_text(encoding="utf-8").strip()
    else:
        seed = os.uname().nodename
    if not seed:
        seed = "lifeline-default-seed"
    digest = hashlib.sha256(f"lifeline:{seed}".encode("utf-8")).digest()
    # Build fdXX:XXXX:XXXX::/64 (48-bit prefix + 16-bit zero subnet ID).
    b0 = 0xFD
    b1, b2, b3, b4, b5 = digest[0], digest[1], digest[2], digest[3], digest[4]
    raw_bytes = bytes([b0, b1, b2, b3, b4, b5, 0, 0]) + b"\x00" * 8
    addr = ipaddress.IPv6Address(raw_bytes)
    return ipaddress.IPv6Network((addr, 64), strict=True)


def parse_eth_ip(raw: str) -> ipaddress.IPv4Interface:
    """Parse `eth_ip` (CIDR or bare IPv4 -> `/24`) and validate host rules."""
    text = raw.strip()
    if not text:
        raise ConfigError("eth_ip cannot be empty")
    if "/" not in text:
        text = f"{text}/24"
    try:
        iface = ipaddress.IPv4Interface(text)
    except ValueError as exc:
        raise ConfigError(f"Invalid eth_ip {raw!r}: {exc}") from exc

    prefix = iface.network.prefixlen
    if prefix < 8 or prefix > 30:
        raise ConfigError(
            f"eth_ip prefix /{prefix} is out of allowed range (/8 to /30)"
        )
    if iface.ip == iface.network.network_address:
        raise ConfigError(f"eth_ip {iface.ip} cannot be the subnet network address")
    if iface.ip == iface.network.broadcast_address:
        raise ConfigError(f"eth_ip {iface.ip} cannot be the subnet broadcast address")
    return iface


def combine_ipv6_prefix_and_host(
    prefix: ipaddress.IPv6Network, host_suffix: str
) -> ipaddress.IPv6Address:
    """Combine a `/64` ULA prefix with a host suffix such as `::24`."""
    suffix = host_suffix.strip()
    if not suffix.startswith("::"):
        raise ConfigError(
            f"IPv6 host identifier {host_suffix!r} must start with '::' (e.g. '::24')"
        )
    try:
        host_int = int(ipaddress.IPv6Address(suffix))
    except ValueError as exc:
        raise ConfigError(f"Invalid IPv6 host identifier {host_suffix!r}: {exc}") from exc

    if host_int == 0 or host_int >= (1 << 64):
        raise ConfigError(
            f"IPv6 host identifier {host_suffix!r} must be non-zero within the /64 host part"
        )
    combined = ipaddress.IPv6Address(int(prefix.network_address) | host_int)
    if combined not in prefix:
        raise ConfigError(f"Combined IPv6 {combined} does not belong to {prefix}")
    return combined


def parse_env_file(env_path: Path) -> dict[str, str]:
    """Parse simple `KEY=VALUE` lines from an optional `config.env` override file."""
    overrides: dict[str, str] = {}
    if not env_path.exists():
        return overrides
    for lineno, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise ConfigError(f"{env_path}:{lineno}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        overrides[key] = value
    return overrides


def parse_target_endpoint(target: str, default_port: int = 443) -> tuple[str, int]:
    """Parse `host[:port]` or `[ipv6]:port` into `(ip_str, port)`."""
    text = target.strip()
    if not text:
        raise ConfigError("Empty probe target")
    if text.startswith("["):
        if "]" not in text:
            raise ConfigError(f"Malformed IPv6 target: {target!r}")
        host, rest = text[1:].split("]", 1)
        port = default_port
        if rest:
            if not rest.startswith(":"):
                raise ConfigError(f"Malformed IPv6 target port: {target!r}")
            port = int(rest[1:])
    elif text.count(":") == 1:
        host, port_str = text.split(":", 1)
        port = int(port_str)
    else:
        host = text
        port = default_port

    ipaddress.ip_address(host)
    if not (1 <= port <= 65535):
        raise ConfigError(f"Target port out of range in {target!r}")
    return host, port


def load_hosts_tables(
    paths: Iterable[Path],
    lan_network: ipaddress.IPv4Network,
    router_ip: ipaddress.IPv4Address,
    ipv6_prefix: ipaddress.IPv6Network,
    router_ipv6: ipaddress.IPv6Address,
) -> tuple[HostEntry, ...]:
    """Load and validate one or more `dhcp_hosts.csv` files."""
    entries: list[HostEntry] = []
    seen_macs: set[str] = set()
    seen_v4: set[ipaddress.IPv4Address] = set()
    seen_v6: set[ipaddress.IPv6Address] = set()

    for path in paths:
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        cleaned_rows: list[tuple[int, str]] = []
        for idx, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            cleaned_rows.append((idx, stripped))

        for idx, row_text in cleaned_rows:
            row = next(csv.reader([row_text]))
            if len(row) < 2 or len(row) > 4:
                raise ConfigError(
                    f"{path}:{idx}: expected 2 to 4 columns (mac,ipv4[,hostname[,ipv6_host]])"
                )
            mac = normalize_mac(row[0])
            try:
                ipv4 = ipaddress.IPv4Address(row[1].strip())
            except ValueError as exc:
                raise ConfigError(f"{path}:{idx}: invalid IPv4 {row[1]!r}") from exc

            hostname = row[2].strip() if len(row) >= 3 else ""
            if hostname and not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", hostname):
                raise ConfigError(f"{path}:{idx}: invalid hostname {hostname!r}")

            raw_v6_host = row[3].strip() if len(row) == 4 else ""
            if not raw_v6_host:
                last_octet = int(ipv4) & 0xFF
                if last_octet == 0:
                    raise ConfigError(
                        f"{path}:{idx}: IPv4 {ipv4} ends in .0; specify explicit ipv6_host"
                    )
                raw_v6_host = f"::{last_octet}"
            ipv6 = combine_ipv6_prefix_and_host(ipv6_prefix, raw_v6_host)

            if ipv4 not in lan_network:
                raise ConfigError(
                    f"{path}:{idx}: IPv4 {ipv4} is outside LAN subnet {lan_network}"
                )
            if ipv4 == lan_network.network_address or ipv4 == lan_network.broadcast_address:
                raise ConfigError(
                    f"{path}:{idx}: IPv4 {ipv4} cannot be network or broadcast address"
                )
            if ipv4 == router_ip:
                raise ConfigError(
                    f"{path}:{idx}: IPv4 {ipv4} conflicts with router eth_ip {router_ip}"
                )
            if ipv6 == router_ipv6:
                raise ConfigError(
                    f"{path}:{idx}: IPv6 {ipv6} conflicts with router IPv6 {router_ipv6}"
                )
            if mac in seen_macs:
                raise ConfigError(f"{path}:{idx}: duplicate MAC address {mac}")
            if ipv4 in seen_v4:
                raise ConfigError(f"{path}:{idx}: duplicate IPv4 address {ipv4}")
            if ipv6 in seen_v6:
                raise ConfigError(f"{path}:{idx}: duplicate IPv6 address {ipv6}")

            seen_macs.add(mac)
            seen_v4.add(ipv4)
            seen_v6.add(ipv6)
            entries.append(HostEntry(mac=mac, ipv4=ipv4, hostname=hostname, ipv6=ipv6))

    return tuple(entries)


def load_config(
    config_path: Path = DEFAULT_CONFIG_PATH,
    env_path: Optional[Path] = DEFAULT_ENV_PATH,
    machine_id_path: Path = DEFAULT_MACHINE_ID_PATH,
) -> LifelineConfig:
    """Load, merge (`config.env` overrides), and validate full `LifelineConfig`."""
    if not config_path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")

    raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    env_overrides = parse_env_file(env_path) if env_path else {}

    iface_sec = raw.get("interfaces", {})
    eth_sel = env_overrides.get("ETH_IF", str(iface_sec.get("eth", "auto"))).strip()
    wifi_sel = env_overrides.get("WIFI_IF", str(iface_sec.get("wifi", "auto"))).strip()
    backend = str(iface_sec.get("backend", "auto")).strip().lower()
    if backend not in ("auto", "networkmanager", "networkd"):
        raise ConfigError(
            f"Unsupported backend {backend!r} (expected auto, networkmanager, or networkd)"
        )
    interfaces = InterfacesConfig(eth=eth_sel, wifi=wifi_sel, backend=backend)

    lan_sec = raw.get("lan", {})
    eth_ip_raw = env_overrides.get("ETH_IP", str(lan_sec.get("eth_ip", "192.168.9.24/24")))
    eth_ip = parse_eth_ip(eth_ip_raw)

    v6_prefix_raw = env_overrides.get(
        "ETH_IPV6_PREFIX", str(lan_sec.get("eth_ipv6_prefix", ""))
    ).strip()
    if v6_prefix_raw:
        try:
            v6_prefix = ipaddress.IPv6Network(v6_prefix_raw, strict=True)
        except ValueError as exc:
            raise ConfigError(f"Invalid eth_ipv6_prefix {v6_prefix_raw!r}: {exc}") from exc
        if v6_prefix.prefixlen != 64:
            raise ConfigError(f"eth_ipv6_prefix must be a /64, got /{v6_prefix.prefixlen}")
    else:
        v6_prefix = derive_ula_prefix(machine_id_path)

    v6_host_raw = env_overrides.get(
        "ETH_IPV6_HOST", str(lan_sec.get("eth_ipv6_host", ""))
    ).strip()
    if not v6_host_raw:
        last_octet = int(eth_ip.ip) & 0xFF
        v6_host_raw = f"::{last_octet if last_octet != 0 else 1}"
    v6_addr_only = combine_ipv6_prefix_and_host(v6_prefix, v6_host_raw)
    v6_iface = ipaddress.IPv6Interface(f"{v6_addr_only}/64")
    lan = LanConfig(eth_ip=eth_ip, eth_ipv6_prefix=v6_prefix, eth_ipv6_addr=v6_iface)

    dhcp_sec = raw.get("dhcp", {})
    hosts_file = Path(str(dhcp_sec.get("hosts_file", "/etc/lifeline/dhcp_hosts.csv")))
    hosts_dir_raw = str(dhcp_sec.get("hosts_dir", "")).strip()
    hosts_dir = Path(hosts_dir_raw) if hosts_dir_raw else None
    lease_time = str(dhcp_sec.get("lease_time", "10m")).strip()
    if not re.match(r"^\d+[smhdw]?$", lease_time):
        raise ConfigError(f"Invalid dhcp.lease_time {lease_time!r}")
    lease_hook_raw = str(dhcp_sec.get("lease_hook", "")).strip()
    if lease_hook_raw:
        lease_hook = Path(lease_hook_raw)
    elif Path("/usr/libexec/lifeline/lease-hook").exists():
        lease_hook = Path("/usr/libexec/lifeline/lease-hook")
    else:
        lease_hook = Path("/usr/local/libexec/lifeline-lease-hook")

    pool_start_raw = str(dhcp_sec.get("dynamic_pool_start", "")).strip()
    pool_end_raw = str(dhcp_sec.get("dynamic_pool_end", "")).strip()
    if bool(pool_start_raw) != bool(pool_end_raw):
        raise ConfigError(
            "Both dhcp.dynamic_pool_start and dhcp.dynamic_pool_end must be set together (or both empty)"
        )
    pool_start: Optional[ipaddress.IPv4Address] = None
    pool_end: Optional[ipaddress.IPv4Address] = None
    if pool_start_raw and pool_end_raw:
        try:
            pool_start = ipaddress.IPv4Address(pool_start_raw)
            pool_end = ipaddress.IPv4Address(pool_end_raw)
        except ValueError as exc:
            raise ConfigError(f"Invalid dhcp dynamic_pool IP: {exc}") from exc
        if pool_start > pool_end:
            raise ConfigError(f"dhcp.dynamic_pool_start ({pool_start}) > dynamic_pool_end ({pool_end})")
        for edge_name, edge_ip in (("dynamic_pool_start", pool_start), ("dynamic_pool_end", pool_end)):
            if edge_ip not in lan.eth_ip.network:
                raise ConfigError(f"dhcp.{edge_name} ({edge_ip}) is outside LAN subnet {lan.eth_ip.network}")
            if edge_ip == lan.eth_ip.network.network_address or edge_ip == lan.eth_ip.network.broadcast_address:
                raise ConfigError(f"dhcp.{edge_name} ({edge_ip}) cannot be network or broadcast address")
        if int(pool_start) <= int(lan.eth_ip.ip) <= int(pool_end):
            raise ConfigError(f"dhcp dynamic_pool [{pool_start}, {pool_end}] overlaps router eth_ip {lan.eth_ip.ip}")

    dhcp = DhcpConfig(
        hosts_file=hosts_file,
        hosts_dir=hosts_dir,
        lease_time=lease_time,
        authoritative=bool(dhcp_sec.get("authoritative", False)),
        dynamic_pool_start=pool_start,
        dynamic_pool_end=pool_end,
        runtime_dir=Path(str(dhcp_sec.get("runtime_dir", "/run/lifeline"))),
        lease_hook=lease_hook,
    )

    fwd_sec = raw.get("forwarding", {})
    policy = str(fwd_sec.get("policy", "active_leases")).strip()
    if policy not in ("active_leases", "static_table", "subnet"):
        raise ConfigError(f"Invalid forwarding.policy {policy!r}")
    ipv6_mode = str(fwd_sec.get("ipv6_mode", "ula_nat66")).strip()
    if ipv6_mode not in ("ula_nat66", "off"):
        raise ConfigError(f"Invalid forwarding.ipv6_mode {ipv6_mode!r}")
    uplink_mode = str(fwd_sec.get("uplink_mode", "auto_tunnel")).strip()
    if uplink_mode not in ("auto_tunnel", "wifi_only", "explicit"):
        raise ConfigError(f"Invalid forwarding.uplink_mode {uplink_mode!r}")
    uplink_interfaces = tuple(
        str(x).strip() for x in fwd_sec.get("uplink_interfaces", []) if str(x).strip()
    )
    tunnel_prefixes = tuple(
        str(x).strip()
        for x in fwd_sec.get(
            "tunnel_prefixes",
            ["tailscale", "tun", "tap", "wg", "ppp", "vpn", "cscotun", "vmnet"],
        )
        if str(x).strip()
    )
    nft_table = str(fwd_sec.get("nft_table", "lifeline")).strip()
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", nft_table):
        raise ConfigError(f"Invalid forwarding.nft_table {nft_table!r}")
    forwarding = ForwardingConfig(
        policy=policy,
        ipv6_mode=ipv6_mode,
        uplink_mode=uplink_mode,
        uplink_interfaces=uplink_interfaces,
        tunnel_prefixes=tunnel_prefixes,
        nft_table=nft_table,
        manage_ufw=bool(fwd_sec.get("manage_ufw", True)),
    )

    health_sec = raw.get("health", {})
    health_mode = str(health_sec.get("mode", "internet")).strip()
    if health_mode not in ("internet", "gateway"):
        raise ConfigError(f"Invalid health.mode {health_mode!r}")
    v4_targets = tuple(str(t) for t in health_sec.get("ipv4_targets", ["1.1.1.1:443", "8.8.8.8:443"]))
    v6_targets = tuple(
        str(t)
        for t in health_sec.get(
            "ipv6_targets", ["[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"]
        )
    )
    for t in v4_targets + v6_targets:
        parse_target_endpoint(t)

    health = HealthConfig(
        mode=health_mode,
        ipv4_targets=v4_targets,
        ipv6_targets=v6_targets,
        probe_interval_sec=float(health_sec.get("probe_interval_sec", 3.0)),
        probe_timeout_sec=float(health_sec.get("probe_timeout_sec", 2.0)),
        fail_threshold=int(health_sec.get("fail_threshold", 3)),
        recover_threshold=int(health_sec.get("recover_threshold", 4)),
        min_dwell_sec=float(health_sec.get("min_dwell_sec", 15.0)),
        resume_grace_sec=float(health_sec.get("resume_grace_sec", 10.0)),
        probe_table_id=int(health_sec.get("probe_table_id", 200)),
        probe_rule_priority=int(health_sec.get("probe_rule_priority", 4000)),
    )
    if health.fail_threshold < 1 or health.recover_threshold < 1:
        raise ConfigError("fail_threshold and recover_threshold must be >= 1")
    if health.probe_interval_sec <= 0 or health.probe_timeout_sec <= 0:
        raise ConfigError("probe_interval_sec and probe_timeout_sec must be > 0")

    elec_sec = raw.get("election", {})
    prio_raw = env_overrides.get("ELECTION_PRIORITY", str(elec_sec.get("priority", 100)))
    latency_bucket_ms = float(elec_sec.get("latency_bucket_ms", 20.0))
    if latency_bucket_ms <= 0:
        raise ConfigError("election.latency_bucket_ms must be > 0")
    election = ElectionConfig(
        beacon_interval_sec=float(elec_sec.get("beacon_interval_sec", 1.0)),
        beacon_port=int(elec_sec.get("beacon_port", 41924)),
        peer_timeout_sec=float(elec_sec.get("peer_timeout_sec", 4.0)),
        dhcp_probe_interval_sec=float(elec_sec.get("dhcp_probe_interval_sec", 5.0)),
        dhcp_probe_timeout_sec=float(elec_sec.get("dhcp_probe_timeout_sec", 1.5)),
        primary_miss_threshold=int(elec_sec.get("primary_miss_threshold", 2)),
        priority=int(prio_raw),
        latency_bucket_ms=latency_bucket_ms,
        rank_backoff_sec=float(elec_sec.get("rank_backoff_sec", 2.0)),
        yield_to_external_dhcp=bool(elec_sec.get("yield_to_external_dhcp", True)),
        external_dhcp_check_interval_sec=float(
            elec_sec.get("external_dhcp_check_interval_sec", 15.0)
        ),
        arp_conflict_check=bool(elec_sec.get("arp_conflict_check", True)),
    )
    if not (1 <= election.beacon_port <= 65535):
        raise ConfigError("election.beacon_port must be 1..65535")

    routing_sec = raw.get("routing", {})
    routing = RoutingConfig(
        failover_eth_metric=int(routing_sec.get("failover_eth_metric", 100)),
        standby_eth_metric=int(routing_sec.get("standby_eth_metric", 800)),
    )

    host_paths = [dhcp.hosts_file]
    if dhcp.hosts_dir and dhcp.hosts_dir.is_dir():
        host_paths.extend(sorted(dhcp.hosts_dir.glob("*.csv")))
    if not dhcp.hosts_file.exists():
        raise ConfigError(f"DHCP hosts table not found: {dhcp.hosts_file}")

    hosts = load_hosts_tables(
        host_paths,
        lan_network=lan.eth_ip.network,
        router_ip=lan.eth_ip.ip,
        ipv6_prefix=lan.eth_ipv6_prefix,
        router_ipv6=lan.eth_ipv6_addr.ip,
    )
    if dhcp.dynamic_pool_start and dhcp.dynamic_pool_end:
        for entry in hosts:
            if int(dhcp.dynamic_pool_start) <= int(entry.ipv4) <= int(dhcp.dynamic_pool_end):
                raise ConfigError(
                    f"Static host {entry.mac} ({entry.ipv4}) overlaps dynamic_pool "
                    f"[{dhcp.dynamic_pool_start}, {dhcp.dynamic_pool_end}]"
                )

    return LifelineConfig(
        config_path=config_path,
        interfaces=interfaces,
        lan=lan,
        dhcp=dhcp,
        forwarding=forwarding,
        health=health,
        election=election,
        routing=routing,
        hosts=hosts,
    )
