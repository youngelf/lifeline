#!/usr/bin/env python3
"""Self-contained Linux namespace integration tests for Lifeline.

Runs inside `unshare -Urn` (rootless user + network namespace) so it can safely
create real bridges, veth pairs, nftables tables, ip rules, and dnsmasq
processes without touching the host's network.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))


def _in_child_namespace() -> bool:
    return os.environ.get("LIFELINE_NETNS_INNER") == "1"


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


async def run_all_tests() -> None:
    from lifeline.config import load_config
    from lifeline.dhcp import render_dnsmasq_config
    from lifeline.election import BeaconBus
    from lifeline.firewall import FirewallManager
    from lifeline.lease_hook import handle_lease_event
    from lifeline.net_utils import get_iface_mac, resolve_uplink_interfaces
    from lifeline.probe import (
        PolicyRouteManager,
        probe_arp_conflict_sync,
        probe_dhcp_server_sync,
        probe_wifi_connectivity,
    )

    print("[1/4] Setting up virtual switch, eth pair, and wifi pair inside namespace...")
    _run(["ip", "link", "set", "lo", "up"])
    _run(["ip", "link", "add", "br_lan", "type", "bridge"])
    _run(["ip", "link", "set", "br_lan", "up"])

    # Ethernet side: eth_srv <-> br_lan <-> eth_cli
    _run(["ip", "link", "add", "eth_srv", "type", "veth", "peer", "name", "eth_srv_p"])
    _run(["ip", "link", "add", "eth_cli", "type", "veth", "peer", "name", "eth_cli_p"])
    _run(["ip", "link", "set", "eth_srv_p", "master", "br_lan"])
    _run(["ip", "link", "set", "eth_cli_p", "master", "br_lan"])
    # Give eth_srv and eth_cli deterministic MACs for election rank testing
    _run(["ip", "link", "set", "eth_srv", "address", "02:00:00:00:00:01"])
    _run(["ip", "link", "set", "eth_cli", "address", "aa:bb:cc:dd:ee:01"])
    for dev in ("eth_srv", "eth_srv_p", "eth_cli", "eth_cli_p"):
        _run(["ip", "link", "set", dev, "up"])

    # Wi-Fi simulation pair: wifi0 <-> isp0 (tests policy table 200 under rp_filter=1)
    _run(["ip", "link", "add", "wifi0", "type", "veth", "peer", "name", "isp0"])
    _run(["ip", "addr", "add", "172.20.1.2/24", "dev", "wifi0"])
    _run(["ip", "addr", "add", "172.20.1.1/24", "dev", "isp0"])
    _run(["ip", "link", "set", "wifi0", "up"])
    _run(["ip", "link", "set", "isp0", "up"])

    # Assign server IP + ULA IPv6 on eth_srv
    _run(["ip", "addr", "add", "192.168.9.24/24", "dev", "eth_srv"])
    _run(["ip", "-6", "addr", "add", "fd09:1234:5678::24/64", "dev", "eth_srv"])
    # Wait briefly for IPv6 DAD on link-local & ULA
    await asyncio.sleep(2.0)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_dir = root / "run"
        run_dir.mkdir()
        hosts_csv = root / "dhcp_hosts.csv"
        hosts_csv.write_text("aa:bb:cc:dd:ee:01,192.168.9.101,known-client,\n", encoding="utf-8")
        cfg_path = root / "config.toml"
        cfg_path.write_text(
            f"""
[lan]
eth_ip = "192.168.9.24/24"
eth_ipv6_prefix = "fd09:1234:5678::/64"

[dhcp]
hosts_file = "{hosts_csv}"
runtime_dir = "{run_dir}"
lease_hook = "{REPO_ROOT / 'scripts' / 'lifeline-lease-hook'}"
""",
            encoding="utf-8",
        )
        cfg = load_config(cfg_path, env_path=None)

        # --- Test 1: Real dnsmasq (when real root) or synthetic DHCP responder (in userns) + AF_PACKET probes ---
        dnsmasq_conf = render_dnsmasq_config(
            cfg, "eth_srv", wifi_has_ipv6_default=True, upstream_dns="127.0.0.53"
        )
        conf_file = run_dir / "dnsmasq.conf"
        conf_file.write_text(dnsmasq_conf, encoding="utf-8")
        dnsmasq_bin = shutil.which("dnsmasq") or "/usr/sbin/dnsmasq"
        _run([dnsmasq_bin, "--test", f"--conf-file={conf_file}"])

        setgroups_path = Path("/proc/self/setgroups")
        in_unpriv_userns = (
            setgroups_path.exists() and setgroups_path.read_text(encoding="utf-8").strip() == "deny"
        )

        if not in_unpriv_userns:
            print("[2/4] Testing real dnsmasq + AF_PACKET DHCPDISCOVER + ARP probe...")
            dm_proc = await asyncio.create_subprocess_exec(
                dnsmasq_bin,
                "--keep-in-foreground",
                "--log-facility=-",
                "--user=root",
                f"--conf-file={conf_file}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            cleanup_proc = dm_proc
        else:
            print(
                "[2/4] Testing AF_PACKET DHCPDISCOVER + ARP probe over Linux bridge "
                "(dnsmasq --test passed; live dnsmasq spawn requires real root because userns setgroups=deny)..."
            )
            cleanup_proc = None

        # When inside unprivileged userns, run a minimal RFC 2131 DHCPOFFER responder on eth_srv:67
        responder_sock = None
        responder_task = None
        if in_unpriv_userns:
            import struct
            from lifeline.probe import DHCP_MAGIC_COOKIE, mac_str_to_bytes

            responder_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            responder_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            responder_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            responder_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth_srv\x00")
            responder_sock.bind(("0.0.0.0", 67))
            responder_sock.setblocking(False)

            async def _serve_static_offer() -> None:
                loop = asyncio.get_running_loop()
                known_mac = mac_str_to_bytes("aa:bb:cc:dd:ee:01")
                while True:
                    try:
                        data, _ = await loop.sock_recvfrom(responder_sock, 4096)
                    except asyncio.CancelledError:
                        return
                    if len(data) < 240 or data[0] != 1:
                        continue
                    chaddr = data[28:34]
                    if chaddr != known_mac:
                        continue  # static table-only: ignore unknown MACs
                    xid = data[4:8]
                    bootp = struct.pack(
                        "!BBBB4sHH4s4s4s4s16s64s128s",
                        2, 1, 6, 0, xid, 0, 0x8000,
                        b"\x00\x00\x00\x00",
                        socket.inet_aton("192.168.9.101"),
                        socket.inet_aton("192.168.9.24"),
                        b"\x00\x00\x00\x00",
                        data[28:44],
                        b"\x00" * 64,
                        b"\x00" * 128,
                    )
                    opts = bytes([53, 1, 2, 54, 4]) + socket.inet_aton("192.168.9.24") + bytes([255])
                    responder_sock.sendto(bootp + DHCP_MAGIC_COOKIE + opts, ("255.255.255.255", 68))

            responder_task = asyncio.create_task(_serve_static_offer())

        try:
            await asyncio.sleep(0.3)
            if cleanup_proc is not None:
                assert cleanup_proc.returncode is None, (
                    f"dnsmasq failed: {await cleanup_proc.stderr.read()}"
                )

            cli_mac = get_iface_mac("eth_cli")
            assert cli_mac == "aa:bb:cc:dd:ee:01"
            offer = await asyncio.to_thread(probe_dhcp_server_sync, "eth_cli", cli_mac, 2.0)
            assert offer is not None, "Expected DHCPOFFER for known MAC"
            assert offer.offered_ip == "192.168.9.101", f"Unexpected offered IP: {offer}"
            assert offer.server_ip == "192.168.9.24", f"Unexpected server_ip: {offer}"

            # Unknown MAC must NOT receive a DHCPOFFER (static table-only)
            unknown_offer = await asyncio.to_thread(
                probe_dhcp_server_sync, "eth_cli", "aa:bb:cc:dd:ee:fe", 0.8
            )
            assert unknown_offer is None, f"Unexpected offer to unknown MAC: {unknown_offer}"

            # ARP conflict probe must detect 192.168.9.24 on the bridge
            conflict = await asyncio.to_thread(
                probe_arp_conflict_sync, "eth_cli", cli_mac, "192.168.9.24", 1.0
            )
            assert conflict is not None, "Expected ARP conflict for 192.168.9.24"
            # Probing an unused IP must report no conflict
            no_conflict = await asyncio.to_thread(
                probe_arp_conflict_sync, "eth_cli", cli_mac, "192.168.9.25", 0.4
            )
            assert no_conflict is None, f"Unexpected ARP conflict for unused IP: {no_conflict}"
        finally:
            if responder_task is not None:
                responder_task.cancel()
            if responder_sock is not None:
                responder_sock.close()
            if cleanup_proc is not None:
                if cleanup_proc.returncode is None:
                    cleanup_proc.terminate()
                await cleanup_proc.wait()

        # --- Test 2: Real nftables PRIMARY (with simulated tunnel interface) + lease_hook + BLOCK ---
        print("[3/4] Testing real nftables PRIMARY ruleset (multi-uplink), lease_hook, and BLOCK...")
        _run(["ip", "link", "add", "tailscale0", "type", "dummy"])
        _run(["ip", "link", "set", "tailscale0", "up"])
        uplinks = resolve_uplink_interfaces(
            eth_if="eth_srv",
            wifi_if="wifi0",
            uplink_mode="auto_tunnel",
            explicit_interfaces=(),
            tunnel_prefixes=("tailscale", "tun"),
        )
        assert uplinks == ("wifi0", "tailscale0"), f"Unexpected uplinks: {uplinks}"
        fw = FirewallManager()
        fw.apply_primary(cfg, "eth_srv", uplinks)
        lease_file = run_dir / "dnsmasq.leases"
        lease_file.write_text(
            f"{int(time.time()) + 600} aa:bb:cc:dd:ee:01 192.168.9.101 known-client *\n",
            encoding="utf-8",
        )
        hook_env = {
            "LIFELINE_FWD_POLICY": "active_leases",
            "LIFELINE_NFT_TABLE": "lifeline",
            "LIFELINE_LEASE_FILE": str(lease_file),
        }
        handle_lease_event("add", "aa:bb:cc:dd:ee:01", "192.168.9.101", env=hook_env)
        nft_out = _run(["nft", "list", "table", "inet", "lifeline"]).stdout
        assert "192.168.9.101 . aa:bb:cc:dd:ee:01" in nft_out, nft_out
        assert "tailscale0" in nft_out, nft_out
        assert "aa:bb:cc:dd:ee:01" in nft_out, nft_out

        fw.apply_block("lifeline", "eth_srv")
        nft_block = _run(["nft", "list", "table", "inet", "lifeline"]).stdout
        assert 'iifname "eth_srv" drop' in nft_block, nft_block

        # --- Test 3: Policy routing table 200 verification under rp_filter=1 ---
        print("[4/4] Testing policy-routed Wi-Fi probe routing under rp_filter=1 + BeaconBus...")
        Path("/proc/sys/net/ipv4/conf/all/rp_filter").write_text("1\n", encoding="utf-8")
        Path("/proc/sys/net/ipv4/conf/wifi0/rp_filter").write_text("1\n", encoding="utf-8")
        # Give eth_srv a lower-metric default route (FAILOVER scenario!)
        _run(["ip", "route", "replace", "default", "via", "192.168.9.1", "dev", "eth_srv", "metric", "100", "onlink"])

        prm = PolicyRouteManager(table_id=200, rule_priority=10200)
        try:
            import ipaddress

            prm.sync(
                "wifi0",
                ipaddress.IPv4Address("172.20.1.2"),
                ipaddress.IPv4Address("172.20.1.1"),
                None,
                None,
            )
            # Normal host traffic uses Ethernet (main table, metric 100)
            main_route = _run(["ip", "route", "get", "1.1.1.1"]).stdout
            assert "dev eth_srv" in main_route, f"Expected main route via eth_srv, got: {main_route}"

            # Wi-Fi probe bound to 172.20.1.2 uses table 200 via wifi0
            probe_route = _run(["ip", "route", "get", "1.1.1.1", "from", "172.20.1.2"]).stdout
            assert "dev wifi0" in probe_route and "table 200" in probe_route, (
                f"Expected probe route via wifi0 table 200, got: {probe_route}"
            )
        finally:
            prm.cleanup()

        # --- Test 4: Link-local IPv6 BeaconBus across veth/bridge ---
        bus_srv = BeaconBus(port=41924, peer_timeout_sec=4.0)
        bus_cli = BeaconBus(port=41924, peer_timeout_sec=4.0)
        try:
            bus_srv.bind("eth_srv")
            bus_cli.bind("eth_cli")
            bus_srv.send_beacon(
                "laptop-1",
                get_iface_mac("eth_srv") or "02:00:00:00:00:01",
                "PRIMARY",
                100,
                True,
            )
            await asyncio.sleep(0.3)
            rank, primary_seen, _ = bus_cli.get_election_view(100, "aa:bb:cc:dd:ee:01")
            assert primary_seen, "BeaconBus client did not receive PRIMARY peer beacon"
            assert rank == 1, f"Expected rank 1 when 1 PRIMARY peer exists, got {rank}"
        finally:
            bus_srv.close()
            bus_cli.close()

    print("ALL INTEGRATION TESTS PASSED!")


def main() -> int:
    if os.geteuid() != 0 and not _in_child_namespace():
        env = os.environ.copy()
        env["LIFELINE_NETNS_INNER"] = "1"
        res = subprocess.run(
            ["unshare", "-Urn", sys.executable, str(Path(__file__).resolve())],
            env=env,
        )
        return res.returncode
    if os.geteuid() == 0 and not _in_child_namespace():
        env = os.environ.copy()
        env["LIFELINE_NETNS_INNER"] = "1"
        res = subprocess.run(
            ["unshare", "-n", sys.executable, str(Path(__file__).resolve())],
            env=env,
        )
        return res.returncode

    asyncio.run(run_all_tests())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
