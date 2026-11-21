"""Unit tests for `lifeline.election` (5-laptop deterministic ranking)."""

from __future__ import annotations

import unittest

from lifeline.election import PeerRecord, compute_rank, decode_beacon, encode_beacon


class TestElection(unittest.TestCase):
    def test_beacon_roundtrip(self) -> None:
        pkt = encode_beacon("laptop-1", "AA:BB:CC:DD:EE:01", "PRIMARY", 100, True, 7, 14.36)
        decoded = decode_beacon(pkt)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(decoded["state"], "PRIMARY")
        self.assertEqual(decoded["latency_ms"], 14.4)
        self.assertTrue(decoded["wifi_ok"])
        self.assertIsNone(decode_beacon(b"not json"))
        self.assertIsNone(decode_beacon(b'{"v":2}'))

    def test_latency_tiebreak_among_equal_priority(self) -> None:
        now = 200.0
        peers = {
            # Higher MAC than us, but much better latency (18ms -> bucket 1 vs our 82ms -> bucket 4)
            "aa:00:00:00:00:99": PeerRecord("fast", "aa:00:00:00:00:99", "SECONDARY", 100, True, now, 18.0),
            # Same latency bucket as us (78ms -> bucket 4) and higher MAC -> does NOT outrank us
            "aa:00:00:00:00:88": PeerRecord("jitter", "aa:00:00:00:00:88", "SECONDARY", 100, True, now, 78.0),
            # Unknown latency -> loses to any measured latency
            "aa:00:00:00:00:01": PeerRecord("nolat", "aa:00:00:00:00:01", "SECONDARY", 100, True, now, None),
        }
        rank, _, _ = compute_rank(
            100,
            "aa:00:00:00:00:10",
            peers,
            now=now,
            peer_timeout_sec=4.0,
            our_latency_ms=82.0,
            latency_bucket_ms=20.0,
        )
        self.assertEqual(rank, 1)

    def test_five_laptop_deterministic_rank(self) -> None:
        now = 100.0
        peers = {
            "aa:00:00:00:00:01": PeerRecord("l1", "aa:00:00:00:00:01", "SECONDARY", 50, True, now - 0.5),
            "aa:00:00:00:00:02": PeerRecord("l2", "aa:00:00:00:00:02", "SECONDARY", 100, True, now - 0.5),
            "aa:00:00:00:00:04": PeerRecord("l4", "aa:00:00:00:00:04", "FAILOVER", 10, False, now - 0.5),
            "aa:00:00:00:00:05": PeerRecord("l5", "aa:00:00:00:00:05", "SECONDARY", 100, True, now - 10.0),  # timed out
        }
        # Laptop 3 has priority 100, MAC aa:00:00:00:00:03.
        # Outranked by l1 (prio 50) and l2 (prio 100, lower MAC).
        # NOT outranked by l4 (wifi_ok=False) or l5 (expired).
        rank, primary_seen, outranks = compute_rank(
            100, "aa:00:00:00:00:03", peers, now=now, peer_timeout_sec=4.0
        )
        self.assertEqual(rank, 2)
        self.assertFalse(primary_seen)
        self.assertFalse(outranks)

    def test_split_brain_tiebreak(self) -> None:
        now = 50.0
        peers = {
            "aa:00:00:00:00:01": PeerRecord("l1", "aa:00:00:00:00:01", "PRIMARY", 100, True, now),
        }
        rank, primary_seen, outranks = compute_rank(
            100, "aa:00:00:00:00:02", peers, now=now, peer_timeout_sec=4.0
        )
        self.assertEqual(rank, 1)
        self.assertTrue(primary_seen)
        self.assertTrue(outranks)

        # If WE have the lower MAC, peer does NOT outrank us
        _, primary_seen2, outranks2 = compute_rank(
            100, "aa:00:00:00:00:00", peers, now=now, peer_timeout_sec=4.0
        )
        self.assertTrue(primary_seen2)
        self.assertFalse(outranks2)


if __name__ == "__main__":
    unittest.main()
