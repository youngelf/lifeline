"""Unit tests for raw AF_PACKET DHCPDISCOVER / DHCPOFFER and ARP probe framing."""

from __future__ import annotations

import socket
import struct
import unittest

from lifeline.probe import (
    DHCP_MAGIC_COOKIE,
    ETH_P_ARP,
    ETH_P_IP,
    build_arp_probe_frame,
    build_dhcp_discover_frame,
    mac_str_to_bytes,
    parse_arp_conflict_frame,
    parse_dhcp_offer_frame,
)


def _make_fake_dhcp_offer(
    *,
    server_mac: str,
    client_mac: str,
    server_ip: str,
    offered_ip: str,
    xid: int,
    msg_type: int = 2,
    unicast: bool = False,
) -> bytes:
    dst_mac_b = mac_str_to_bytes(client_mac) if unicast else b"\xff\xff\xff\xff\xff\xff"
    src_mac_b = mac_str_to_bytes(server_mac)
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2,  # BOOTREPLY
        1,
        6,
        0,
        xid,
        0,
        0,
        b"\x00\x00\x00\x00",
        socket.inet_aton(offered_ip),
        socket.inet_aton(server_ip),
        b"\x00\x00\x00\x00",
        mac_str_to_bytes(client_mac) + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    opts = bytes([53, 1, msg_type, 54, 4]) + socket.inet_aton(server_ip) + bytes([255])
    payload = bootp + DHCP_MAGIC_COOKIE + opts
    udp_hdr = struct.pack("!HHHH", 67, 68, 8 + len(payload), 0)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + 8 + len(payload),
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton(server_ip),
        b"\xff\xff\xff\xff",
    )
    eth_hdr = struct.pack("!6s6sH", dst_mac_b, src_mac_b, ETH_P_IP)
    return eth_hdr + ip_hdr + udp_hdr + payload


class TestRawProbes(unittest.TestCase):
    def test_dhcp_discover_packet_structure(self) -> None:
        frame = build_dhcp_discover_frame("11:22:33:44:55:66", 0x12345678)
        self.assertGreaterEqual(len(frame), 14 + 20 + 8 + 300)
        dst, src, eth_t = struct.unpack("!6s6sH", frame[:14])
        self.assertEqual(dst, b"\xff" * 6)
        self.assertEqual(src, mac_str_to_bytes("11:22:33:44:55:66"))
        self.assertEqual(eth_t, ETH_P_IP)
        sport, dport = struct.unpack("!HH", frame[34:38])
        self.assertEqual((sport, dport), (68, 67))
        self.assertEqual(frame[42 + 236 : 42 + 240], DHCP_MAGIC_COOKIE)

    def test_parse_dhcp_offer_broadcast_and_unicast(self) -> None:
        our_mac = "11:22:33:44:55:66"
        xid = 0xCAFEBABE
        pkt = _make_fake_dhcp_offer(
            server_mac="aa:bb:cc:dd:ee:99",
            client_mac=our_mac,
            server_ip="192.168.1.1",
            offered_ip="192.168.1.50",
            xid=xid,
            unicast=True,
        )
        offer = parse_dhcp_offer_frame(pkt, xid, our_mac)
        self.assertIsNotNone(offer)
        assert offer is not None
        self.assertEqual(offer.server_ip, "192.168.1.1")
        self.assertEqual(offer.server_mac, "aa:bb:cc:dd:ee:99")
        self.assertEqual(offer.offered_ip, "192.168.1.50")

        # Wrong XID ignored
        self.assertIsNone(parse_dhcp_offer_frame(pkt, 0xDEADBEEF, our_mac))
        # Own MAC ignored
        self.assertIsNone(parse_dhcp_offer_frame(pkt, xid, "aa:bb:cc:dd:ee:99"))

    def test_arp_probe_and_conflict_detection(self) -> None:
        probe = build_arp_probe_frame("11:22:33:44:55:66", "192.168.9.24")
        self.assertEqual(len(probe), 42)
        reply = struct.pack(
            "!6s6sHHHBBH6s4s6s4s",
            mac_str_to_bytes("11:22:33:44:55:66"),
            mac_str_to_bytes("aa:bb:cc:dd:ee:77"),
            ETH_P_ARP,
            1,
            ETH_P_IP,
            6,
            4,
            2,  # ARP reply
            mac_str_to_bytes("aa:bb:cc:dd:ee:77"),
            socket.inet_aton("192.168.9.24"),
            mac_str_to_bytes("11:22:33:44:55:66"),
            socket.inet_aton("0.0.0.0"),
        )
        self.assertEqual(
            parse_arp_conflict_frame(reply, "192.168.9.24", "11:22:33:44:55:66"),
            "aa:bb:cc:dd:ee:77",
        )
        self.assertIsNone(
            parse_arp_conflict_frame(reply, "192.168.9.99", "11:22:33:44:55:66")
        )


if __name__ == "__main__":
    unittest.main()
