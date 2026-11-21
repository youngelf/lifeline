"""Unit tests for `lifeline.config`."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import tempfile
import unittest

from lifeline.config import (
    ConfigError,
    derive_ula_prefix,
    load_config,
    normalize_mac,
    parse_eth_ip,
)


class TestConfig(unittest.TestCase):
    def test_parse_eth_ip_variants(self) -> None:
        self.assertEqual(str(parse_eth_ip("192.168.9.24")), "192.168.9.24/24")
        self.assertEqual(str(parse_eth_ip("10.20.0.1/16")), "10.20.0.1/16")
        with self.assertRaises(ConfigError):
            parse_eth_ip("192.168.9.0/24")
        with self.assertRaises(ConfigError):
            parse_eth_ip("192.168.9.255/24")
        with self.assertRaises(ConfigError):
            parse_eth_ip("192.168.9.1/31")
        with self.assertRaises(ConfigError):
            parse_eth_ip("10.0.0.1/7")

    def test_normalize_mac(self) -> None:
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-01"), "aa:bb:cc:dd:ee:01")
        with self.assertRaises(ConfigError):
            normalize_mac("ff:ff:ff:ff:ff:ff")
        with self.assertRaises(ConfigError):
            normalize_mac("01:00:5e:00:00:01")  # multicast bit set
        with self.assertRaises(ConfigError):
            normalize_mac("00:00:00:00:00:00")

    def test_derive_ula_prefix_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mid = Path(tmp) / "machine-id"
            mid.write_text("0123456789abcdef0123456789abcdef\n", encoding="utf-8")
            p1 = derive_ula_prefix(mid)
            p2 = derive_ula_prefix(mid)
            self.assertEqual(p1, p2)
            self.assertEqual(p1.prefixlen, 64)
            self.assertTrue(str(p1).startswith("fd"))

    def test_load_config_with_env_override_and_dropins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_dir = root / "hosts.d"
            hosts_dir.mkdir()
            hosts_csv = root / "dhcp_hosts.csv"
            hosts_csv.write_text(
                "# comment\naa:bb:cc:dd:ee:01,10.55.0.10,node1,\n",
                encoding="utf-8",
            )
            (hosts_dir / "extra.csv").write_text(
                "aa:bb:cc:dd:ee:02,10.55.0.20,node2,::200\n",
                encoding="utf-8",
            )
            cfg_path = root / "config.toml"
            cfg_path.write_text(
                f"""
[interfaces]
eth = "auto"
wifi = "auto"

[lan]
eth_ip = "192.168.9.24/24"

[dhcp]
hosts_file = "{hosts_csv}"
hosts_dir = "{hosts_dir}"
""",
                encoding="utf-8",
            )
            env_path = root / "config.env"
            env_path.write_text("ETH_IP=10.55.0.1/24\nELECTION_PRIORITY=50\n", encoding="utf-8")
            mid_path = root / "machine-id"
            mid_path.write_text("machine-a\n", encoding="utf-8")

            cfg = load_config(cfg_path, env_path=env_path, machine_id_path=mid_path)
            self.assertEqual(str(cfg.lan.eth_ip), "10.55.0.1/24")
            self.assertEqual(cfg.election.priority, 50)
            self.assertEqual(len(cfg.hosts), 2)
            self.assertEqual(cfg.hosts[0].ipv6, ipaddress.IPv6Address(int(cfg.lan.eth_ipv6_prefix.network_address) | 0x10))
            self.assertEqual(cfg.hosts[1].ipv6, ipaddress.IPv6Address(int(cfg.lan.eth_ipv6_prefix.network_address) | 0x200))

    def test_reject_duplicate_or_router_ip_in_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_csv = root / "dhcp_hosts.csv"
            hosts_csv.write_text("aa:bb:cc:dd:ee:01,192.168.9.24,clash,\n", encoding="utf-8")
            cfg_path = root / "config.toml"
            cfg_path.write_text(
                f'[lan]\neth_ip = "192.168.9.24/24"\n[dhcp]\nhosts_file = "{hosts_csv}"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(cfg_path, env_path=None)

    def test_dynamic_pool_and_tunnel_uplink_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hosts_csv = root / "dhcp_hosts.csv"
            hosts_csv.write_text("aa:bb:cc:dd:ee:01,192.168.9.101,alpha,\n", encoding="utf-8")
            cfg_path = root / "config.toml"
            cfg_path.write_text(
                f"""
[lan]
eth_ip = "192.168.9.24/24"
[dhcp]
hosts_file = "{hosts_csv}"
dynamic_pool_start = "192.168.9.200"
dynamic_pool_end = "192.168.9.240"
[forwarding]
uplink_mode = "auto_tunnel"
tunnel_prefixes = ["tailscale", "tun"]
[election]
latency_bucket_ms = 25.0
""",
                encoding="utf-8",
            )
            cfg = load_config(cfg_path, env_path=None)
            self.assertEqual(str(cfg.dhcp.dynamic_pool_start), "192.168.9.200")
            self.assertEqual(str(cfg.dhcp.dynamic_pool_end), "192.168.9.240")
            self.assertEqual(cfg.forwarding.uplink_mode, "auto_tunnel")
            self.assertEqual(cfg.election.latency_bucket_ms, 25.0)

            # Overlapping a static host must be rejected
            cfg_path.write_text(
                f"""
[lan]
eth_ip = "192.168.9.24/24"
[dhcp]
hosts_file = "{hosts_csv}"
dynamic_pool_start = "192.168.9.100"
dynamic_pool_end = "192.168.9.120"
""",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(cfg_path, env_path=None)

            # Overlapping router IP must be rejected
            cfg_path.write_text(
                f"""
[lan]
eth_ip = "192.168.9.24/24"
[dhcp]
hosts_file = "{hosts_csv}"
dynamic_pool_start = "192.168.9.20"
dynamic_pool_end = "192.168.9.30"
""",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(cfg_path, env_path=None)


if __name__ == "__main__":
    unittest.main()
