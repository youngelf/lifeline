"""Unit tests for `lifeline.dhcp`, `lifeline.firewall`, and `lifeline.lease_hook`."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from lifeline.config import load_config
from lifeline.dhcp import (
    DnsmasqSupervisor,
    build_ra_deprecation_packet,
    parse_dnsmasq_leases,
    render_dnsmasq_config,
)
from lifeline.firewall import compute_initial_allowlists, render_block_ruleset, render_primary_ruleset
from lifeline.lease_hook import handle_lease_event


def _make_sample_config(root: Path):
    hosts_csv = root / "dhcp_hosts.csv"
    hosts_csv.write_text(
        "aa:bb:cc:dd:ee:01,192.168.9.101,alpha,\n"
        "aa:bb:cc:dd:ee:02,192.168.9.102,beta,::202\n",
        encoding="utf-8",
    )
    cfg_path = root / "config.toml"
    cfg_path.write_text(
        f"""
[lan]
eth_ip = "192.168.9.24/24"
eth_ipv6_prefix = "fd09:1234:5678::/64"
eth_ipv6_host = "::24"

[dhcp]
hosts_file = "{hosts_csv}"
runtime_dir = "{root / 'run'}"
lease_hook = "/usr/local/libexec/lifeline-lease-hook"
""",
        encoding="utf-8",
    )
    return load_config(cfg_path, env_path=None)


class TestDhcpFirewallAndHook(unittest.TestCase):
    def test_render_dnsmasq_config_and_ra_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _make_sample_config(Path(tmp))
            conf_v6 = render_dnsmasq_config(
                cfg, "eth0", wifi_has_ipv6_default=True, upstream_dns="127.0.0.53"
            )
            self.assertIn("dhcp-range=192.168.9.0,static,255.255.255.0,10m", conf_v6)
            self.assertIn("ra-param=eth0,10,60", conf_v6)
            self.assertIn("dhcp-host=aa:bb:cc:dd:ee:01,192.168.9.101,[fd09:1234:5678::101],alpha", conf_v6)
            self.assertNotIn("dhcp-authoritative", conf_v6)

            conf_v4_only = render_dnsmasq_config(
                cfg, "eth0", wifi_has_ipv6_default=False, upstream_dns="127.0.0.53"
            )
            self.assertIn("ra-param=eth0,10,0", conf_v4_only)

            if shutil.which("dnsmasq"):
                res = subprocess.run(
                    ["dnsmasq", "--test", "--conf-file=/dev/stdin"],
                    input=conf_v6,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(res.returncode, 0, res.stderr)

    def test_parse_dnsmasq_leases_filters_expired(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lease_file = Path(tmp) / "dnsmasq.leases"
            lease_file.write_text(
                "2000 11:22:33:44:55:66 192.168.9.101 host1 01:11\n"
                "500 11:22:33:44:55:77 192.168.9.102 host2 *\n"
                "duid 00:01:00:01:ab\n",
                encoding="utf-8",
            )
            leases = parse_dnsmasq_leases(lease_file, now_epoch=1000)
            self.assertEqual(len(leases), 1)
            self.assertEqual(leases[0].mac, "11:22:33:44:55:66")

    def test_ra_deprecation_packet(self) -> None:
        pkt = build_ra_deprecation_packet("aa:bb:cc:dd:ee:01")
        self.assertEqual(len(pkt), 24)
        self.assertEqual(pkt[0], 134)  # ICMPv6 RA
        self.assertEqual(pkt[6:8], b"\x00\x00")  # Router lifetime = 0

    def test_render_nftables_rulesets_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _make_sample_config(Path(tmp))
            v4_pairs, v6_macs = compute_initial_allowlists(cfg)
            self.assertEqual(v4_pairs, [])
            primary_nft = render_primary_ruleset(
                cfg,
                "eth0",
                ["wlan0", "tailscale0", "tun0"],
                [("192.168.9.101", "aa:bb:cc:dd:ee:01")],
                ["aa:bb:cc:dd:ee:01"],
            )
            block_nft = render_block_ruleset("lifeline", "eth0")
            self.assertIn('oifname { "wlan0", "tailscale0", "tun0" }', primary_nft)
            self.assertIn("ip saddr . ether saddr @allowed_v4", primary_nft)
            self.assertIn('iifname "eth0" drop', block_nft)

            if shutil.which("nft") and shutil.which("unshare"):
                for ruleset in (primary_nft, block_nft):
                    res = subprocess.run(
                        ["unshare", "-Urn", "nft", "-c", "-f", "-"],
                        input=ruleset,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(res.returncode, 0, res.stderr)

    def test_dynamic_pool_dnsmasq_and_lease_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_csv = root / "dhcp_hosts.csv"
            hosts_csv.write_text("aa:bb:cc:dd:ee:01,192.168.9.101,alpha,\n", encoding="utf-8")
            run_dir = root / "run"
            run_dir.mkdir()
            cfg_path = root / "config.toml"
            cfg_path.write_text(
                f"""
[lan]
eth_ip = "192.168.9.24/24"
eth_ipv6_prefix = "fd09:1234:5678::/64"
[dhcp]
hosts_file = "{hosts_csv}"
dynamic_pool_start = "192.168.9.200"
dynamic_pool_end = "192.168.9.240"
runtime_dir = "{run_dir}"
""",
                encoding="utf-8",
            )
            cfg = load_config(cfg_path, env_path=None)
            dm_conf = render_dnsmasq_config(
                cfg, "eth0", wifi_has_ipv6_default=True, upstream_dns="127.0.0.53"
            )
            self.assertIn("dhcp-range=192.168.9.200,192.168.9.240,255.255.255.0,10m", dm_conf)
            self.assertIn("dhcp-range=fd09:1234:5678::,slaac,ra-names,64,10m", dm_conf)
            if shutil.which("dnsmasq"):
                res = subprocess.run(
                    ["dnsmasq", "--test", "--conf-file=/dev/stdin"],
                    input=dm_conf,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(res.returncode, 0, res.stderr)

            # Dynamic guest lease + out-of-pool unauthorized lease
            exp = int(time.time()) + 600
            (run_dir / "dnsmasq.leases").write_text(
                f"{exp} aa:bb:cc:dd:ee:99 192.168.9.205 guest *\n"
                f"{exp} aa:bb:cc:dd:ee:fe 192.168.9.150 rogue *\n",
                encoding="utf-8",
            )
            v4_pairs, v6_macs = compute_initial_allowlists(cfg)
            self.assertEqual(v4_pairs, [("192.168.9.205", "aa:bb:cc:dd:ee:99")])
            self.assertEqual(v6_macs, ["aa:bb:cc:dd:ee:99"])

    def test_find_managed_dnsmasq_pids_by_proc_cmdline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            run_dir.mkdir()
            proc_root = root / "proc"
            # PID 1234: lifeline-managed dnsmasq (even with NO dnsmasq.pid file!)
            (proc_root / "1234").mkdir(parents=True)
            (proc_root / "1234" / "cmdline").write_bytes(
                b"/usr/sbin/dnsmasq\x00--keep-in-foreground\x00--conf-file="
                + str(run_dir / "dnsmasq.conf").encode()
                + b"\x00"
            )
            # PID 5678: unrelated libvirt dnsmasq must NOT be matched
            (proc_root / "5678").mkdir(parents=True)
            (proc_root / "5678" / "cmdline").write_bytes(
                b"/usr/sbin/dnsmasq\x00--conf-file=/var/lib/libvirt/dnsmasq/default.conf\x00"
            )

            pids = DnsmasqSupervisor.find_managed_dnsmasq_pids(run_dir, proc_root=proc_root)
            self.assertEqual(pids, [1234])

    def test_lease_hook_v4_and_v6_refcounting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lease_file = Path(tmp) / "dnsmasq.leases"
            future_exp = int(time.time()) + 600
            lease_file.write_text(
                f"{future_exp} aa:bb:cc:dd:ee:01 192.168.9.101 alpha *\n",
                encoding="utf-8",
            )
            env = {
                "LIFELINE_FWD_POLICY": "active_leases",
                "LIFELINE_NFT_TABLE": "lifeline",
                "LIFELINE_LEASE_FILE": str(lease_file),
                "DNSMASQ_MAC": "aa:bb:cc:dd:ee:01",
            }
            calls: list[list[str]] = []
            with patch("lifeline.lease_hook._nft", side_effect=lambda args: calls.append(args) or 0):
                handle_lease_event("add", "aa:bb:cc:dd:ee:01", "192.168.9.101", env=env)
                self.assertEqual(
                    calls,
                    [
                        ["add", "element", "inet", "lifeline", "allowed_v4", "{ 192.168.9.101 . aa:bb:cc:dd:ee:01 }"],
                        ["add", "element", "inet", "lifeline", "allowed_v6_mac", "{ aa:bb:cc:dd:ee:01 }"],
                    ],
                )
                calls.clear()

                # Deleting the IPv6 lease while IPv4 lease is still in dnsmasq.leases keeps allowed_v6_mac!
                handle_lease_event("del", "00:01:00:01:duid", "fd09:1234:5678::101", env=env)
                self.assertEqual(calls, [])

                # Removing IPv4 lease when no other lease exists deletes both sets
                lease_file.write_text("", encoding="utf-8")
                handle_lease_event("del", "aa:bb:cc:dd:ee:01", "192.168.9.101", env=env)
                self.assertEqual(
                    calls,
                    [
                        ["destroy", "element", "inet", "lifeline", "allowed_v4", "{ 192.168.9.101 . aa:bb:cc:dd:ee:01 }"],
                        ["destroy", "element", "inet", "lifeline", "allowed_v6_mac", "{ aa:bb:cc:dd:ee:01 }"],
                    ],
                )


if __name__ == "__main__":
    unittest.main()
