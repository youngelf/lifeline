# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Vikram Aggarwal
# Author: Vikram Aggarwal
# Bug fixes, hardening, and feature improvements are warmly encouraged.

"""Main asyncio daemon (`lifelined`) coordinating probes, election, and mode switches."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import shutil
import signal
import socket
import sys
import time
from typing import Optional

from lifeline import __version__
from lifeline.backends import (
    InterfacePair,
    NetworkBackend,
    NetworkManagerBackend,
    NetworkdBackend,
)
from lifeline.config import ConfigError, DEFAULT_CONFIG_PATH, LifelineConfig, load_config
from lifeline.dhcp import DnsmasqSupervisor, parse_dnsmasq_leases
from lifeline.election import BeaconBus
from lifeline.firewall import FirewallManager
from lifeline.net_utils import (
    get_iface_carrier,
    get_interface_addrs,
    get_interface_gateways,
    resolve_uplink_interfaces,
    run_cmd_sync,
)
from lifeline.probe import (
    PolicyRouteManager,
    WifiProbeResult,
    probe_arp_conflict_sync,
    probe_dhcp_server_sync,
    probe_wifi_connectivity,
)
from lifeline.state import Mode, StateMachine, StateMachineParams, TickObservation
from lifeline.sysctl import SysctlManager

LOG = logging.getLogger("lifeline.daemon")


def _sd_notify(message: str) -> None:
    """Send systemd sd_notify datagram if `$NOTIFY_SOCKET` is set (stdlib only)."""
    sock_path = os.environ.get("NOTIFY_SOCKET")
    if not sock_path:
        return
    if sock_path.startswith("@"):
        sock_path = "\0" + sock_path[1:]
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode("utf-8"), sock_path)
        finally:
            sock.close()
    except OSError:
        pass


def _is_systemd_unit_active(unit: str) -> str:
    sc = shutil.which("systemctl")
    if not sc:
        return "no-systemctl"
    res = run_cmd_sync([sc, "is-active", unit], timeout=3.0)
    return (res.stdout or res.stderr).strip() or f"rc={res.returncode}"


def _nm_device_table() -> list[tuple[str, str, str, str]]:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return []
    res = run_cmd_sync(
        [nmcli, "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
        timeout=5.0,
    )
    if res.returncode != 0:
        return []
    rows: list[tuple[str, str, str, str]] = []
    for line in res.stdout.splitlines():
        parts = line.split(":", 3)
        if len(parts) == 4:
            rows.append((parts[0], parts[1], parts[2], parts[3]))
    return rows


def build_backend(name: str, eth_sel: str = "auto") -> NetworkBackend:
    if name == "networkd":
        LOG.info("Selected systemd-networkd backend (configured explicitly)")
        return NetworkdBackend()
    if name == "networkmanager":
        LOG.info("Selected NetworkManager backend (configured explicitly)")
        return NetworkManagerBackend()

    # backend == "auto": inspect running managers and device management state
    nm_active = _is_systemd_unit_active("NetworkManager") == "active"
    nd_active = _is_systemd_unit_active("systemd-networkd") == "active"
    if nm_active:
        nm_rows = _nm_device_table()
        eth_rows = [r for r in nm_rows if r[1] == "ethernet"]
        if eth_sel != "auto" and not eth_sel.lower().startswith("mac:"):
            eth_rows = [r for r in eth_rows if r[0] == eth_sel] or eth_rows
        if eth_rows and all(r[2] == "unmanaged" for r in eth_rows) and nd_active:
            LOG.warning(
                "NetworkManager is active, but Ethernet device(s) %s are 'unmanaged' and "
                "systemd-networkd is active; auto-selecting systemd-networkd backend",
                [r[0] for r in eth_rows],
            )
            return NetworkdBackend()
        LOG.info("Auto-selected NetworkManager backend (NetworkManager=active, networkd=%s)", nd_active)
        return NetworkManagerBackend()
    if nd_active:
        LOG.info("Auto-selected systemd-networkd backend (NetworkManager inactive, systemd-networkd=active)")
        return NetworkdBackend()
    LOG.warning(
        "Neither NetworkManager nor systemd-networkd reported active; defaulting to NetworkManager backend"
    )
    return NetworkManagerBackend()


class LifelineDaemon:
    """Long-running coordinator managing Lifeline's state and subsystems."""

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH) -> None:
        self.config_path = config_path
        self.cfg: LifelineConfig = load_config(config_path)
        self.backend: NetworkBackend = build_backend(
            self.cfg.interfaces.backend, self.cfg.interfaces.eth
        )
        self.sysctls = SysctlManager()
        self.firewall = FirewallManager()
        self.dhcp = DnsmasqSupervisor()
        self.policy_routes = PolicyRouteManager(
            table_id=self.cfg.health.probe_table_id,
            rule_priority=self.cfg.health.probe_rule_priority,
        )
        self.beacons = BeaconBus(
            port=self.cfg.election.beacon_port,
            peer_timeout_sec=self.cfg.election.peer_timeout_sec,
            latency_bucket_ms=self.cfg.election.latency_bucket_ms,
        )
        self.sm = StateMachine(self._sm_params(self.cfg), initial_now=time.monotonic())

        self.node_id = socket.gethostname()
        self.ifaces = InterfacePair(None, None, None, None)
        self.active_uplinks: tuple[str, ...] = ()
        self.force_mode: Optional[str] = None
        self.last_wifi_probe: Optional[WifiProbeResult] = None
        self.ewma_latency_ms: Optional[float] = None
        self.last_wifi_probe_at: float = 0.0
        self.last_dhcp_probe_at: float = 0.0
        self.last_dhcp_seen: Optional[bool] = None
        self.last_dhcp_server_info: Optional[str] = None
        self.last_beacon_at: float = 0.0
        self.resume_grace_until: float = 0.0
        self._last_wall_mono_offset: float = time.time() - time.monotonic()

        self._stop_event = asyncio.Event()
        self._reload_requested = False
        self._ctl_server: Optional[asyncio.AbstractServer] = None
        self._applied_mode: Optional[Mode] = None

    @staticmethod
    def _sm_params(cfg: LifelineConfig) -> StateMachineParams:
        return StateMachineParams(
            fail_threshold=cfg.health.fail_threshold,
            recover_threshold=cfg.health.recover_threshold,
            min_dwell_sec=cfg.health.min_dwell_sec,
            primary_miss_threshold=cfg.election.primary_miss_threshold,
            rank_backoff_sec=cfg.election.rank_backoff_sec,
            yield_to_external_dhcp=cfg.election.yield_to_external_dhcp,
        )

    @property
    def status_file(self) -> Path:
        return self.cfg.dhcp.runtime_dir / "status.json"

    @property
    def control_socket_path(self) -> Path:
        return self.cfg.dhcp.runtime_dir / "control.sock"

    def _detect_suspend_resume(self, now_mono: float) -> bool:
        """Detect laptop suspend/hibernate via monotonic-vs-wall-clock jump."""
        offset = time.time() - now_mono
        drift = offset - self._last_wall_mono_offset
        self._last_wall_mono_offset = offset
        if drift > 5.0:
            self.resume_grace_until = now_mono + self.cfg.health.resume_grace_sec
            LOG.info(
                "System resume detected (clock jump %.1fs); pausing fail transitions for %.1fs",
                drift,
                self.cfg.health.resume_grace_sec,
            )
            return True
        return now_mono < self.resume_grace_until

    async def _run_dhcp_server_probe(self, eth_if: str, eth_mac: str) -> Optional[bool]:
        """Run a raw DHCPDISCOVER probe on `eth_if` off the event loop."""
        ignore_ips = {str(self.cfg.lan.eth_ip.ip)} if self.sm.mode == Mode.PRIMARY else set()
        offer = await asyncio.to_thread(
            probe_dhcp_server_sync,
            eth_if,
            eth_mac,
            self.cfg.election.dhcp_probe_timeout_sec,
            ignore_ips,
        )
        if offer is not None:
            self.last_dhcp_server_info = f"{offer.server_ip} ({offer.server_mac})"
            return True
        self.last_dhcp_server_info = None
        return False

    async def _apply_mode(self, new_mode: Mode, reason: str) -> None:
        """Apply side effects of entering `new_mode` in strict race-free order."""
        eth_if = self.ifaces.eth_if
        eth_mac = self.ifaces.eth_mac
        wifi_if = self.ifaces.wifi_if
        LOG.info("Transitioning %s -> %s (%s)", self._applied_mode, new_mode.value, reason)

        if new_mode == Mode.PRIMARY:
            if not eth_if or not eth_mac or not wifi_if:
                LOG.error("Cannot enter PRIMARY: missing interface(s) %s", self.ifaces)
                self.sm.mode = Mode.FAILOVER
                return

            # Pre-flight L2 safety checks before claiming ETH_IP / starting dnsmasq.
            external_offer = await self._run_dhcp_server_probe(eth_if, eth_mac)
            if external_offer:
                LOG.warning(
                    "Aborting PRIMARY promotion: DHCP server %s responded on %s -> entering SECONDARY",
                    self.last_dhcp_server_info,
                    eth_if,
                )
                self.sm.mode = Mode.SECONDARY
                self.sm.mode_entered_at = time.monotonic()
                await self._apply_mode(Mode.SECONDARY, "external DHCP detected during promotion")
                return

            if self.cfg.election.arp_conflict_check:
                conflict_mac = await asyncio.to_thread(
                    probe_arp_conflict_sync,
                    eth_if,
                    eth_mac,
                    str(self.cfg.lan.eth_ip.ip),
                    1.0,
                )
                if conflict_mac:
                    LOG.error(
                        "Aborting PRIMARY promotion: ARP conflict for %s from MAC %s",
                        self.cfg.lan.eth_ip.ip,
                        conflict_mac,
                    )
                    self.sm.mode = Mode.SECONDARY
                    self.sm.mode_entered_at = time.monotonic()
                    await self._apply_mode(Mode.SECONDARY, "ARP IP conflict")
                    return

            await self.backend.set_wifi_dns_default_route(wifi_if, True)
            v6_cidr = (
                str(self.cfg.lan.eth_ipv6_addr)
                if self.cfg.forwarding.ipv6_mode == "ula_nat66"
                else None
            )
            await self.backend.apply_eth_static(eth_if, str(self.cfg.lan.eth_ip), v6_cidr)

            enable_v6 = self.cfg.forwarding.ipv6_mode == "ula_nat66"
            self.active_uplinks = resolve_uplink_interfaces(
                eth_if=eth_if,
                wifi_if=wifi_if,
                uplink_mode=self.cfg.forwarding.uplink_mode,
                explicit_interfaces=self.cfg.forwarding.uplink_interfaces,
                tunnel_prefixes=self.cfg.forwarding.tunnel_prefixes,
            )
            self.sysctls.enable_forwarding(
                eth_if,
                wifi_if,
                uplink_ifs=self.active_uplinks,
                enable_ipv6=enable_v6,
                set_wifi_accept_ra_2=self.backend.uses_kernel_ra,
            )
            self.firewall.apply_primary(self.cfg, eth_if, self.active_uplinks)

            _, wifi_gw6 = get_interface_gateways(wifi_if)
            await self.dhcp.start_or_reload(
                self.cfg,
                eth_if,
                wifi_has_ipv6_default=(wifi_gw6 is not None),
            )

        elif new_mode == Mode.SECONDARY:
            self.active_uplinks = ()
            await self.dhcp.stop(deprecate_ra=(self._applied_mode == Mode.PRIMARY))
            if eth_if:
                self.firewall.apply_block(self.cfg.forwarding.nft_table, eth_if)
            self.sysctls.disable_and_restore(eth_if)
            if wifi_if:
                await self.backend.set_wifi_dns_default_route(wifi_if, True)
            if eth_if:
                await self.backend.apply_eth_dhcp_standby(eth_if, self.cfg.routing.standby_eth_metric)

        elif new_mode == Mode.FAILOVER:
            self.active_uplinks = ()
            await self.dhcp.stop(deprecate_ra=(self._applied_mode == Mode.PRIMARY))
            if eth_if:
                self.firewall.apply_block(self.cfg.forwarding.nft_table, eth_if)
            self.sysctls.disable_and_restore(eth_if)
            if wifi_if:
                await self.backend.set_wifi_dns_default_route(wifi_if, False)
            if eth_if:
                await self.backend.apply_eth_dhcp_failover(eth_if, self.cfg.routing.failover_eth_metric)

        elif new_mode == Mode.IDLE:
            self.active_uplinks = ()
            await self.dhcp.stop(deprecate_ra=False)
            if eth_if:
                self.firewall.apply_block(self.cfg.forwarding.nft_table, eth_if)
            self.sysctls.disable_and_restore(eth_if)

        elif new_mode == Mode.ELECTION:
            # Ensure we are not serving DHCP during election wait.
            await self.dhcp.stop(deprecate_ra=False)
            if eth_if:
                self.firewall.apply_block(self.cfg.forwarding.nft_table, eth_if)

        self._applied_mode = new_mode
        _sd_notify(f"STATUS=Mode: {new_mode.value} ({reason})")

    def _write_status(self) -> None:
        self.cfg.dhcp.runtime_dir.mkdir(parents=True, exist_ok=True)
        leases = parse_dnsmasq_leases(self.cfg.dhcp.runtime_dir / "dnsmasq.leases")
        payload = {
            "version": __version__,
            "node_id": self.node_id,
            "mode": self.sm.mode.value,
            "reason": self.sm.last_reason,
            "force_mode": self.force_mode,
            "interfaces": {
                "eth": self.ifaces.eth_if,
                "eth_mac": self.ifaces.eth_mac,
                "eth_carrier": get_iface_carrier(self.ifaces.eth_if) if self.ifaces.eth_if else False,
                "wifi": self.ifaces.wifi_if,
                "wifi_mac": self.ifaces.wifi_mac,
                "uplinks": list(self.active_uplinks),
            },
            "lan": {
                "eth_ip": str(self.cfg.lan.eth_ip),
                "eth_ipv6": str(self.cfg.lan.eth_ipv6_addr),
                "ipv6_mode": self.cfg.forwarding.ipv6_mode,
                "dynamic_pool": (
                    f"{self.cfg.dhcp.dynamic_pool_start}-{self.cfg.dhcp.dynamic_pool_end}"
                    if (self.cfg.dhcp.dynamic_pool_start and self.cfg.dhcp.dynamic_pool_end)
                    else None
                ),
            },
            "health": {
                "wifi_probe_ok": self.last_wifi_probe.healthy if self.last_wifi_probe else None,
                "wifi_detail": self.last_wifi_probe.detail if self.last_wifi_probe else "pending",
                "wifi_latency_ms": round(self.ewma_latency_ms, 1) if self.ewma_latency_ms is not None else None,
                "wifi_ok_streak": self.sm.wifi_ok_streak,
                "wifi_fail_streak": self.sm.wifi_fail_streak,
            },
            "election": {
                "priority": self.cfg.election.priority,
                "latency_bucket_ms": self.cfg.election.latency_bucket_ms,
                "external_dhcp_seen": self.last_dhcp_seen,
                "external_dhcp_server": self.last_dhcp_server_info,
                "peers": [
                    {
                        "node_id": p.node_id,
                        "mac": p.mac,
                        "state": p.state,
                        "priority": p.priority,
                        "latency_ms": p.latency_ms,
                        "wifi_ok": p.wifi_ok,
                    }
                    for p in self.beacons.peers.values()
                ],
            },
            "leases": [
                {
                    "mac": l.mac,
                    "ip": l.ip,
                    "hostname": l.hostname,
                    "expires_at": l.expires_at,
                }
                for l in leases
            ],
            "updated_at_epoch": int(time.time()),
        }
        tmp = self.status_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o644)
        tmp.replace(self.status_file)

    async def _handle_reload(self) -> None:
        self._reload_requested = False
        LOG.info("Reloading configuration from %s", self.config_path)
        try:
            new_cfg = load_config(self.config_path)
        except ConfigError as exc:
            LOG.error("Reload aborted; invalid config: %s", exc)
            return

        self.cfg = new_cfg
        self.sm.params = self._sm_params(new_cfg)
        self.beacons.latency_bucket_ms = new_cfg.election.latency_bucket_ms
        if self.sm.mode == Mode.PRIMARY and self.ifaces.eth_if and self.ifaces.wifi_if:
            _, wifi_gw6 = get_interface_gateways(self.ifaces.wifi_if)
            self.active_uplinks = resolve_uplink_interfaces(
                eth_if=self.ifaces.eth_if,
                wifi_if=self.ifaces.wifi_if,
                uplink_mode=self.cfg.forwarding.uplink_mode,
                explicit_interfaces=self.cfg.forwarding.uplink_interfaces,
                tunnel_prefixes=self.cfg.forwarding.tunnel_prefixes,
            )
            await self.dhcp.start_or_reload(
                self.cfg,
                self.ifaces.eth_if,
                wifi_has_ipv6_default=(wifi_gw6 is not None),
            )
            self.sysctls.enable_forwarding(
                self.ifaces.eth_if,
                self.ifaces.wifi_if,
                uplink_ifs=self.active_uplinks,
                enable_ipv6=(self.cfg.forwarding.ipv6_mode == "ula_nat66"),
                set_wifi_accept_ra_2=self.backend.uses_kernel_ra,
            )
            self.firewall.apply_primary(self.cfg, self.ifaces.eth_if, self.active_uplinks)
        LOG.info("Configuration reload complete (%d host table entries)", len(self.cfg.hosts))

    async def _handle_control_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=2.0)
            req = json.loads(raw.decode("utf-8"))
            cmd = req.get("cmd")
            if cmd == "status":
                self._write_status()
                resp = {"ok": True, "status": json.loads(self.status_file.read_text(encoding="utf-8"))}
            elif cmd == "reload":
                await self._handle_reload()
                resp = {"ok": True, "message": "reloaded"}
            elif cmd == "force-mode":
                mode_arg = req.get("mode")
                if mode_arg in ("primary", "secondary", "failover"):
                    self.force_mode = mode_arg
                elif mode_arg == "auto":
                    self.force_mode = None
                else:
                    resp = {"ok": False, "error": f"invalid mode {mode_arg!r}"}
                    writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                resp = {"ok": True, "force_mode": self.force_mode}
            else:
                resp = {"ok": False, "error": f"unknown command {cmd!r}"}
            writer.write((json.dumps(resp) + "\n").encode("utf-8"))
            await writer.drain()
        except Exception as exc:
            LOG.debug("Control socket error: %s", exc)
        finally:
            writer.close()

    async def _start_control_server(self) -> None:
        self.cfg.dhcp.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.control_socket_path.unlink(missing_ok=True)
        self._ctl_server = await asyncio.start_unix_server(
            self._handle_control_client, path=str(self.control_socket_path)
        )
        os.chmod(self.control_socket_path, 0o600)

    def _log_startup_diagnostics(self) -> None:
        """Emit rich environment diagnostics at startup so boot failures are easy to trace."""
        tools = {
            name: shutil.which(name) or "MISSING"
            for name in ("dnsmasq", "nft", "ip", "nmcli", "networkctl", "resolvectl")
        }
        services = {
            unit: _is_systemd_unit_active(unit)
            for unit in ("NetworkManager", "systemd-networkd", "systemd-resolved")
        }
        ip_link = run_cmd_sync(["ip", "-br", "link"], timeout=5.0)
        links_summary = " | ".join(
            line.strip() for line in ip_link.stdout.splitlines() if line.strip()
        ) or ip_link.stderr.strip()
        nm_rows = _nm_device_table()
        nm_summary = ", ".join(f"{d}({t}):{s}[{c or '-'}]" for d, t, s, c in nm_rows) or "unavailable"

        LOG.info(
            "Startup diagnostics: python=%s uid=%d pid=%d config=%s backend=%s(%s)",
            sys.version.split()[0],
            os.geteuid(),
            os.getpid(),
            self.config_path,
            self.cfg.interfaces.backend,
            type(self.backend).__name__,
        )
        LOG.info(
            "Config summary: eth_sel=%s wifi_sel=%s eth_ip=%s eth_ipv6=%s hosts=%d pool=%s-%s uplink_mode=%s",
            self.cfg.interfaces.eth,
            self.cfg.interfaces.wifi,
            self.cfg.lan.eth_ip,
            self.cfg.lan.eth_ipv6_addr,
            len(self.cfg.hosts),
            self.cfg.dhcp.dynamic_pool_start,
            self.cfg.dhcp.dynamic_pool_end,
            self.cfg.forwarding.uplink_mode,
        )
        LOG.info("System services: %s", services)
        LOG.info("System binaries: %s", tools)
        LOG.info("Kernel links: %s", links_summary)
        LOG.info("NetworkManager devices: %s", nm_summary)

        if self.ifaces.eth_if is None:
            LOG.warning(
                "No Ethernet interface resolved for selector %r; staying IDLE until plugged in",
                self.cfg.interfaces.eth,
            )
        elif isinstance(self.backend, NetworkManagerBackend):
            for dev, _t, state, _c in nm_rows:
                if dev == self.ifaces.eth_if and state == "unmanaged":
                    LOG.error(
                        "Ethernet interface %s is marked 'unmanaged' by NetworkManager! "
                        "Either let NM manage it or set backend = 'networkd' in %s",
                        dev,
                        self.config_path,
                    )
        if self.ifaces.wifi_if is None:
            LOG.warning(
                "No Wi-Fi interface resolved for selector %r; daemon will hold FAILOVER",
                self.cfg.interfaces.wifi,
            )

    async def run(self) -> None:
        """Main daemon lifecycle."""
        DnsmasqSupervisor.cleanup_stale_pid(self.cfg.dhcp.runtime_dir)
        await self._start_control_server()

        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, self._stop_event.set)
        loop.add_signal_handler(signal.SIGINT, self._stop_event.set)
        loop.add_signal_handler(signal.SIGHUP, lambda: setattr(self, "_reload_requested", True))

        self.ifaces = await self.backend.discover_interfaces(
            self.cfg.interfaces.eth, self.cfg.interfaces.wifi
        )
        self._log_startup_diagnostics()
        LOG.info(
            "Starting lifeline (node=%s, backend=%s, eth=%s, wifi=%s, eth_ip=%s)",
            self.node_id,
            type(self.backend).__name__,
            self.ifaces.eth_if,
            self.ifaces.wifi_if,
            self.cfg.lan.eth_ip,
        )

        # Apply baseline nftables safety block immediately and mark service READY so
        # systemd never stalls or aborts start on slow DHCP / unplugged cable.
        if self.ifaces.eth_if:
            try:
                self.firewall.apply_block(self.cfg.forwarding.nft_table, self.ifaces.eth_if)
            except Exception:
                LOG.exception("Initial nftables block apply failed on %s", self.ifaces.eth_if)
        _sd_notify("READY=1\nSTATUS=Initialized; applying safe startup mode")

        initial_mode = (
            Mode.FAILOVER
            if (self.ifaces.eth_if and get_iface_carrier(self.ifaces.eth_if))
            else Mode.IDLE
        )
        self.sm.mode = initial_mode
        self.sm.last_reason = (
            "startup safe default" if initial_mode == Mode.FAILOVER else "startup with no Ethernet carrier"
        )
        try:
            await self._apply_mode(initial_mode, self.sm.last_reason)
        except Exception:
            LOG.exception(
                "Initial mode setup (%s) encountered an error; daemon remains running and will retry",
                initial_mode.value,
            )

        try:
            while not self._stop_event.is_set():
                now = time.monotonic()
                if self._reload_requested:
                    await self._handle_reload()

                try:
                    await self._tick(now)
                except Exception:
                    LOG.exception("Unhandled error during daemon tick; continuing")
                self._write_status()

                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
        finally:
            await self.shutdown()

    async def _tick(self, now: float) -> None:
        self.ifaces = await self.backend.discover_interfaces(
            self.cfg.interfaces.eth, self.cfg.interfaces.wifi
        )
        eth_if = self.ifaces.eth_if
        eth_mac = self.ifaces.eth_mac
        wifi_if = self.ifaces.wifi_if

        eth_carrier = bool(eth_if and get_iface_carrier(eth_if))

        if eth_if and eth_carrier:
            self.beacons.bind(eth_if)
        else:
            self.beacons.close()

        # 1. Inspect Wi-Fi L3 + update policy routing table 200
        wifi_ip4 = wifi_gw4 = wifi_ip6 = wifi_gw6 = None
        if wifi_if:
            v4_list, v6_list = get_interface_addrs(wifi_if)
            wifi_ip4 = v4_list[0].ip if v4_list else None
            wifi_ip6 = v6_list[0].ip if v6_list else None
            wifi_gw4, wifi_gw6 = get_interface_gateways(wifi_if)
        self.policy_routes.sync(wifi_if, wifi_ip4, wifi_gw4, wifi_ip6, wifi_gw6)

        wifi_link_up = bool(wifi_if and ((wifi_ip4 and wifi_gw4) or (wifi_ip6 and wifi_gw6)))
        probe_ok: Optional[bool] = None
        if wifi_link_up and wifi_if:
            if (now - self.last_wifi_probe_at) >= self.cfg.health.probe_interval_sec:
                res = await probe_wifi_connectivity(
                    wifi_if,
                    wifi_ip4,
                    wifi_gw4,
                    wifi_ip6,
                    wifi_gw6,
                    mode=self.cfg.health.mode,
                    ipv4_targets=self.cfg.health.ipv4_targets,
                    ipv6_targets=self.cfg.health.ipv6_targets,
                    timeout_sec=self.cfg.health.probe_timeout_sec,
                )
                self.last_wifi_probe = res
                self.last_wifi_probe_at = now
                probe_ok = res.healthy
                if res.healthy and res.latency_ms is not None:
                    if self.ewma_latency_ms is None:
                        self.ewma_latency_ms = res.latency_ms
                    else:
                        self.ewma_latency_ms = 0.7 * self.ewma_latency_ms + 0.3 * res.latency_ms
                elif not res.healthy:
                    self.ewma_latency_ms = None
        else:
            self.last_wifi_probe = WifiProbeResult(False, False, False, "wifi L3 down")
            self.ewma_latency_ms = None
            probe_ok = False

        # 2. Periodic raw DHCPDISCOVER check on Ethernet (mode-aware intervals)
        dhcp_seen: Optional[bool] = None
        if eth_if and eth_mac and eth_carrier:
            if self.sm.mode == Mode.SECONDARY:
                interval = self.cfg.election.dhcp_probe_interval_sec
            elif self.sm.mode == Mode.PRIMARY and self.cfg.election.yield_to_external_dhcp:
                interval = self.cfg.election.external_dhcp_check_interval_sec
            elif self.sm.mode in (Mode.FAILOVER, Mode.IDLE, Mode.ELECTION):
                interval = self.cfg.election.dhcp_probe_interval_sec
            else:
                interval = 1e9

            if (now - self.last_dhcp_probe_at) >= interval:
                dhcp_seen = await self._run_dhcp_server_probe(eth_if, eth_mac)
                self.last_dhcp_seen = dhcp_seen
                self.last_dhcp_probe_at = now

        # 3. Election view + beacon broadcast
        rank = 0
        peer_primary_seen = False
        peer_outranks = False
        if eth_mac:
            rank, peer_primary_seen, peer_outranks = self.beacons.get_election_view(
                self.cfg.election.priority,
                eth_mac,
                our_latency_ms=self.ewma_latency_ms,
                now=now,
            )
            if eth_if and eth_carrier and (now - self.last_beacon_at) >= self.cfg.election.beacon_interval_sec:
                self.beacons.send_beacon(
                    self.node_id,
                    eth_mac,
                    self.sm.mode.value,
                    self.cfg.election.priority,
                    wifi_ok=(self.last_wifi_probe.healthy if self.last_wifi_probe else False),
                    latency_ms=self.ewma_latency_ms,
                )
                self.last_beacon_at = now

        # 4. Step pure state machine
        in_grace = self._detect_suspend_resume(now)
        obs = TickObservation(
            now=now,
            eth_carrier=eth_carrier,
            wifi_link_up=wifi_link_up,
            wifi_probe_ok=probe_ok,
            external_dhcp_seen=dhcp_seen if dhcp_seen is not None else self.last_dhcp_seen,
            peer_primary_seen=peer_primary_seen,
            peer_primary_outranks_us=peer_outranks,
            election_rank=rank,
            in_resume_grace=in_grace,
            force_mode=self.force_mode,
        )
        tr = self.sm.step(obs)
        if tr.changed:
            await self._apply_mode(tr.current, tr.reason)
        elif self.sm.mode == Mode.PRIMARY and eth_if and wifi_if:
            # Detect tunnel interfaces (Tailscale/WireGuard/VMware) appearing/disappearing.
            new_uplinks = resolve_uplink_interfaces(
                eth_if=eth_if,
                wifi_if=wifi_if,
                uplink_mode=self.cfg.forwarding.uplink_mode,
                explicit_interfaces=self.cfg.forwarding.uplink_interfaces,
                tunnel_prefixes=self.cfg.forwarding.tunnel_prefixes,
            )
            if new_uplinks != self.active_uplinks:
                LOG.info("Active uplinks changed %s -> %s; updating forwarding", self.active_uplinks, new_uplinks)
                self.active_uplinks = new_uplinks
                self.firewall.apply_primary(self.cfg, eth_if, self.active_uplinks)

            # Re-assert forwarding sysctls (in case NM roamed Wi-Fi or tunnel reset flags) & keep dnsmasq RA aligned.
            self.sysctls.reassert_forwarding(
                eth_if,
                wifi_if,
                uplink_ifs=self.active_uplinks,
                enable_ipv6=(self.cfg.forwarding.ipv6_mode == "ula_nat66"),
                set_wifi_accept_ra_2=self.backend.uses_kernel_ra,
            )
            if not self.dhcp.is_running:
                LOG.warning("Managed dnsmasq exited unexpectedly; restarting")
                await self.dhcp.start_or_reload(
                    self.cfg, eth_if, wifi_has_ipv6_default=(wifi_gw6 is not None)
                )
            else:
                # Re-sync dnsmasq RA router-lifetime if Wi-Fi gained/lost IPv6 default route.
                await self.dhcp.start_or_reload(
                    self.cfg, eth_if, wifi_has_ipv6_default=(wifi_gw6 is not None)
                )

    async def shutdown(self) -> None:
        LOG.info("Shutting down lifeline daemon cleanly")
        self.beacons.close()
        if self._ctl_server is not None:
            self._ctl_server.close()
            await self._ctl_server.wait_closed()
        self.control_socket_path.unlink(missing_ok=True)
        await self.dhcp.stop(deprecate_ra=(self.sm.mode == Mode.PRIMARY))
        self.firewall.clear_ufw_rules()
        self.firewall.cleanup_table(self.cfg.forwarding.nft_table)
        self.sysctls.disable_and_restore(self.ifaces.eth_if)
        self.policy_routes.cleanup()
        await self.backend.cleanup(self.ifaces.eth_if, self.ifaces.wifi_if)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Lifeline background daemon")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to config.toml (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LIFELINE_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        daemon = LifelineDaemon(args.config)
    except ConfigError as exc:
        LOG.error("Invalid configuration (%s): %s", args.config, exc)
        return 2
    except Exception:
        LOG.exception("Failed initializing LifelineDaemon")
        return 1

    try:
        asyncio.run(daemon.run())
    except Exception:
        LOG.exception("Fatal unhandled exception in lifelined")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
