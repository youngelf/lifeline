# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Operator CLI (`lifelinectl`) for validating, inspecting, and controlling Lifeline."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import time
from typing import Optional

from lifeline.config import ConfigError, DEFAULT_CONFIG_PATH, load_config
from lifeline.daemon import build_backend
from lifeline.dhcp import DnsmasqSupervisor, render_dnsmasq_config
from lifeline.firewall import FirewallManager
from lifeline.net_utils import run_cmd_sync
from lifeline.probe import PolicyRouteManager
from lifeline.sysctl import SysctlManager


def _send_ctl(socket_path: Path, payload: dict) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(5.0)
        sock.connect(str(socket_path))
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8"))
    finally:
        sock.close()


def cmd_validate(config_path: Path) -> int:
    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    print(f"VALID: {config_path}")
    print(f"  backend       : {cfg.interfaces.backend}")
    print(f"  eth / wifi    : {cfg.interfaces.eth} / {cfg.interfaces.wifi}")
    print(f"  lan ipv4      : {cfg.lan.eth_ip}")
    print(f"  lan ipv6      : {cfg.lan.eth_ipv6_addr} (prefix {cfg.lan.eth_ipv6_prefix}, mode={cfg.forwarding.ipv6_mode})")
    print(f"  fwd policy    : {cfg.forwarding.policy} (uplink_mode={cfg.forwarding.uplink_mode})")
    if cfg.dhcp.dynamic_pool_start and cfg.dhcp.dynamic_pool_end:
        print(f"  dynamic pool  : {cfg.dhcp.dynamic_pool_start}-{cfg.dhcp.dynamic_pool_end}")
    print(f"  host entries  : {len(cfg.hosts)}")
    return 0


def cmd_status(config_path: Path, as_json: bool) -> int:
    cfg = load_config(config_path)
    sock_path = cfg.dhcp.runtime_dir / "control.sock"
    status_path = cfg.dhcp.runtime_dir / "status.json"
    data = None
    if sock_path.exists():
        try:
            resp = _send_ctl(sock_path, {"cmd": "status"})
            if resp.get("ok"):
                data = resp["status"]
        except OSError:
            pass
    if data is None and status_path.exists():
        data = json.loads(status_path.read_text(encoding="utf-8"))
    if data is None:
        print("lifelined is not running (no status found).", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(data, indent=2))
        return 0

    ifaces = data["interfaces"]
    health = data["health"]
    elec = data["election"]
    print(f"Node: {data['node_id']}   Mode: {data['mode']}   Reason: {data['reason']}")
    if data.get("force_mode"):
        print(f"Manual override active: {data['force_mode']}")
    print(
        f"Interfaces: eth={ifaces['eth']} (carrier={ifaces['eth_carrier']}, mac={ifaces['eth_mac']})  "
        f"wifi={ifaces['wifi']} (mac={ifaces['wifi_mac']})  "
        f"uplinks={','.join(ifaces.get('uplinks') or []) or '-'}"
    )
    pool_str = f"  pool={data['lan']['dynamic_pool']}" if data["lan"].get("dynamic_pool") else ""
    print(
        f"LAN: ipv4={data['lan']['eth_ip']}  ipv6={data['lan']['eth_ipv6']} ({data['lan']['ipv6_mode']}){pool_str}"
    )
    lat = health.get("wifi_latency_ms")
    lat_str = f"{lat}ms" if lat is not None else "-"
    print(
        f"Wi-Fi Health: ok={health['wifi_probe_ok']} ({health['wifi_detail']})  "
        f"ewma_rtt={lat_str}  ok_streak={health['wifi_ok_streak']}  fail_streak={health['wifi_fail_streak']}"
    )
    print(
        f"Election: priority={elec['priority']}  ext_dhcp={elec['external_dhcp_seen']} "
        f"({elec['external_dhcp_server']})  peers={len(elec['peers'])}"
    )
    for p in elec["peers"]:
        p_lat = f"{p['latency_ms']}ms" if p.get("latency_ms") is not None else "-"
        print(
            f"  peer {p['node_id']} ({p['mac']}): state={p['state']} prio={p['priority']} rtt={p_lat} wifi_ok={p['wifi_ok']}"
        )
    print(f"Active Leases ({len(data['leases'])}):")
    for l in data["leases"]:
        print(f"  {l['mac']} -> {l['ip']} ({l['hostname'] or '-'})")
    return 0


def format_prompt_status(
    status_path: Path = Path("/run/lifeline/status.json"),
    *,
    shell: str = "plain",
    color: bool = False,
    show_stopped: bool = False,
    max_age_sec: float = 15.0,
    now_epoch: Optional[float] = None,
) -> str:
    """Return a compact, non-blocking status badge suitable for bash/zsh PS1."""
    if not status_path.exists():
        return "[LL:OFF]" if show_stopped else ""
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "[LL:ERR]" if show_stopped else ""

    now_ts = time.time() if now_epoch is None else now_epoch
    updated = float(data.get("updated_at_epoch", 0))
    if max_age_sec > 0 and (now_ts - updated) > max_age_sec:
        return "[LL:STALE]" if show_stopped else ""

    mode = str(data.get("mode", "UNKNOWN")).upper()
    leases = data.get("leases", [])
    n_leases = len(leases)

    short_map = {
        "PRIMARY": f"PRI({n_leases})",
        "SECONDARY": "SEC",
        "FAILOVER": "FAIL",
        "ELECTION": "ELEC",
        "IDLE": "IDLE",
    }
    label = f"[LL:{short_map.get(mode, mode)}]"
    if not color:
        return label

    ansi_map = {
        "PRIMARY": "\033[32m",    # green
        "SECONDARY": "\033[36m",  # cyan
        "FAILOVER": "\033[31m",   # red
        "ELECTION": "\033[33m",   # yellow
        "IDLE": "\033[90m",       # gray
    }
    ansi = ansi_map.get(mode, "")
    reset = "\033[0m"
    if not ansi:
        return label
    if shell == "bash":
        return f"\\[{ansi}\\]{label}\\[{reset}\\]"
    if shell == "zsh":
        return f"%{{{ansi}%}}{label}%{{{reset}%}}"
    return f"{ansi}{label}{reset}"


def cmd_prompt(
    status_file: Path,
    shell: str,
    color: bool,
    show_stopped: bool,
) -> int:
    text = format_prompt_status(
        status_file,
        shell=shell,
        color=color,
        show_stopped=show_stopped,
    )
    if text:
        sys.stdout.write(text)
    return 0


def cmd_cleanup(config_path: Path) -> int:
    """Idempotent emergency cleanup invoked by systemd ExecStopPost or operators."""
    try:
        cfg = load_config(config_path)
        runtime_dir = cfg.dhcp.runtime_dir
        nft_table = cfg.forwarding.nft_table
        table_id = cfg.health.probe_table_id
        rule_prio = cfg.health.probe_rule_priority
        backend_name = cfg.interfaces.backend
        eth_sel, wifi_sel = cfg.interfaces.eth, cfg.interfaces.wifi
    except ConfigError:
        runtime_dir = Path("/run/lifeline")
        nft_table = "lifeline"
        table_id = 200
        rule_prio = 4000
        backend_name = "auto"
        eth_sel, wifi_sel = "auto", "auto"

    DnsmasqSupervisor.cleanup_stale_pid(runtime_dir)
    FirewallManager.cleanup_table(nft_table)
    PolicyRouteManager(table_id=table_id, rule_priority=rule_prio).cleanup()

    backend = build_backend(backend_name, eth_sel)

    async def _clean() -> None:
        ifaces = await backend.discover_interfaces(eth_sel, wifi_sel)
        SysctlManager().disable_and_restore(ifaces.eth_if)
        await backend.cleanup(ifaces.eth_if, ifaces.wifi_if)

    asyncio.run(_clean())
    print("Lifeline cleanup complete.")
    return 0


def cmd_doctor(config_path: Path) -> int:
    """Print an installation & runtime diagnostic report for troubleshooting startup."""
    print(f"=== Lifeline Doctor (uid={os.geteuid()}) ===")
    cfg = None
    try:
        cfg = load_config(config_path)
        print(
            f"[OK] Config valid: {config_path} (backend={cfg.interfaces.backend}, "
            f"eth_ip={cfg.lan.eth_ip}, hosts={len(cfg.hosts)})"
        )
    except ConfigError as exc:
        print(f"[FAIL] Config error ({config_path}): {exc}")

    print("\n--- Required Binaries ---")
    for binary in ("python3", "dnsmasq", "nft", "ip", "nmcli", "networkctl", "resolvectl"):
        print(f"  {binary:12s}: {shutil.which(binary) or 'MISSING'}")

    print("\n--- Systemd Services ---")
    if shutil.which("systemctl"):
        for unit in ("lifeline", "NetworkManager", "systemd-networkd", "systemd-resolved"):
            r = run_cmd_sync(["systemctl", "is-active", unit], timeout=3.0)
            state = (r.stdout or r.stderr).strip() or f"rc={r.returncode}"
            print(f"  {unit:18s}: {state}")

    print("\n--- Kernel Links & Addresses ---")
    ip_link = run_cmd_sync(["ip", "-br", "link"], timeout=5.0)
    print(ip_link.stdout.strip() or ip_link.stderr.strip())
    ip_addr = run_cmd_sync(["ip", "-br", "addr"], timeout=5.0)
    print(ip_addr.stdout.strip() or ip_addr.stderr.strip())

    if shutil.which("nmcli"):
        print("\n--- NetworkManager Devices ---")
        nm_res = run_cmd_sync(["nmcli", "device", "status"], timeout=5.0)
        print(nm_res.stdout.strip() or nm_res.stderr.strip())
        if "unmanaged" in nm_res.stdout:
            print(
                "[WARN] One or more devices are 'unmanaged' in NetworkManager. "
                "If Ethernet is unmanaged, configure Netplan to use NetworkManager or set "
                "backend = \"networkd\" in /etc/lifeline/config.toml."
            )

    if cfg is not None:
        backend = build_backend(cfg.interfaces.backend, cfg.interfaces.eth)
        ifaces = asyncio.run(backend.discover_interfaces(cfg.interfaces.eth, cfg.interfaces.wifi))
        print(
            f"\n--- Resolved Backend & Interfaces ---\n"
            f"  backend={type(backend).__name__}  eth={ifaces.eth_if} ({ifaces.eth_mac})  "
            f"wifi={ifaces.wifi_if} ({ifaces.wifi_mac})"
        )
        if ifaces.eth_if and shutil.which("dnsmasq"):
            dm_conf = render_dnsmasq_config(cfg, ifaces.eth_if, wifi_has_ipv6_default=False)
            dm_test = run_cmd_sync(
                [shutil.which("dnsmasq") or "dnsmasq", "--test", "--conf-file=/dev/stdin"],
                input_text=dm_conf,
            )
            status = "OK" if dm_test.returncode == 0 else f"FAIL: {dm_test.stderr.strip()}"
            print(f"  dnsmasq --test: {status}")

    if shutil.which("nft"):
        nft_res = run_cmd_sync(["nft", "list", "tables"], timeout=3.0)
        print(f"\n--- nftables Tables ---\n{nft_res.stdout.strip() or nft_res.stderr.strip()}")

    if shutil.which("journalctl"):
        print("\n--- Recent lifeline Journal (last 20 lines) ---")
        j_res = run_cmd_sync(["journalctl", "-u", "lifeline", "-n", "20", "--no-pager"], timeout=5.0)
        print(j_res.stdout.strip() or j_res.stderr.strip())

    return 0 if cfg is not None else 2


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="lifelinectl", description="Control utility for Lifeline")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to config.toml (default: {DEFAULT_CONFIG_PATH})",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    p_status = sub.add_parser("status", help="Show live daemon state, peers, and leases")
    p_status.add_argument("--json", action="store_true", help="Output raw JSON")

    sub.add_parser("validate", help="Validate config.toml, config.env, and dhcp_hosts.csv")
    sub.add_parser("reload", help="Hot-reload config and MAC-to-IP table")

    p_force = sub.add_parser("force-mode", help="Force a specific mode or return to auto")
    p_force.add_argument("mode", choices=["primary", "secondary", "failover", "auto"])

    p_prompt = sub.add_parser(
        "prompt",
        help="Print a fast, compact status badge for bash/zsh PS1 prompts",
    )
    p_prompt.add_argument("--shell", choices=["plain", "bash", "zsh"], default="plain")
    p_prompt.add_argument("--color", action="store_true", help="Emit ANSI color codes")
    p_prompt.add_argument(
        "--show-stopped",
        action="store_true",
        help="Show [LL:OFF] / [LL:STALE] when lifelined is not running",
    )
    p_prompt.add_argument(
        "--status-file",
        type=Path,
        default=Path("/run/lifeline/status.json"),
        help="Path to status.json (default: /run/lifeline/status.json)",
    )

    sub.add_parser("doctor", help="Run startup and network environment diagnostics")
    sub.add_parser("cleanup", help="Clean up nftables, policy routes, dnsmasq, and NM profiles")

    args = parser.parse_args(argv)
    if args.subcmd == "doctor":
        return cmd_doctor(args.config)
    if args.subcmd == "prompt":
        return cmd_prompt(args.status_file, args.shell, args.color, args.show_stopped)
    if args.subcmd == "validate":
        return cmd_validate(args.config)
    if args.subcmd == "status":
        return cmd_status(args.config, args.json)
    if args.subcmd == "cleanup":
        return cmd_cleanup(args.config)

    cfg = load_config(args.config)
    sock_path = cfg.dhcp.runtime_dir / "control.sock"
    if args.subcmd == "reload":
        resp = _send_ctl(sock_path, {"cmd": "reload"})
        print(resp)
        return 0 if resp.get("ok") else 1
    if args.subcmd == "force-mode":
        resp = _send_ctl(sock_path, {"cmd": "force-mode", "mode": args.mode})
        print(resp)
        return 0 if resp.get("ok") else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
