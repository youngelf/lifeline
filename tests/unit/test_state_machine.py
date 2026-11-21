"""Unit tests for `lifeline.state.StateMachine`."""

from __future__ import annotations

import unittest

from lifeline.state import Mode, StateMachine, StateMachineParams, TickObservation


def make_obs(
    now: float,
    *,
    eth_carrier: bool = True,
    wifi_link_up: bool = True,
    wifi_probe_ok: bool | None = True,
    external_dhcp_seen: bool | None = False,
    peer_primary_seen: bool = False,
    peer_primary_outranks_us: bool = False,
    election_rank: int = 0,
    in_resume_grace: bool = False,
    force_mode: str | None = None,
) -> TickObservation:
    return TickObservation(
        now=now,
        eth_carrier=eth_carrier,
        wifi_link_up=wifi_link_up,
        wifi_probe_ok=wifi_probe_ok,
        external_dhcp_seen=external_dhcp_seen,
        peer_primary_seen=peer_primary_seen,
        peer_primary_outranks_us=peer_primary_outranks_us,
        election_rank=election_rank,
        in_resume_grace=in_resume_grace,
        force_mode=force_mode,
    )


class TestStateMachine(unittest.TestCase):
    def setUp(self) -> None:
        self.params = StateMachineParams(
            fail_threshold=3,
            recover_threshold=4,
            min_dwell_sec=15.0,
            primary_miss_threshold=2,
            rank_backoff_sec=2.0,
            yield_to_external_dhcp=True,
        )

    def test_failover_to_election_to_primary_when_no_dhcp(self) -> None:
        sm = StateMachine(self.params, initial_now=0.0)
        self.assertEqual(sm.mode, Mode.FAILOVER)

        # Build 4 consecutive OK probes, but dwell hasn't reached 15s yet.
        for t in (1.0, 4.0, 7.0, 10.0):
            tr = sm.step(make_obs(t))
            self.assertFalse(tr.changed)
            self.assertEqual(sm.mode, Mode.FAILOVER)

        # After dwell=15s -> enters ELECTION
        tr = sm.step(make_obs(15.0, wifi_probe_ok=None))
        self.assertTrue(tr.changed)
        self.assertEqual(tr.current, Mode.ELECTION)

        # Rank 0 settles after 0.5s -> enters PRIMARY
        self.assertFalse(sm.step(make_obs(15.2, wifi_probe_ok=None)).changed)
        tr2 = sm.step(make_obs(15.6, wifi_probe_ok=None))
        self.assertTrue(tr2.changed)
        self.assertEqual(tr2.current, Mode.PRIMARY)

    def test_failover_enters_secondary_when_dhcp_server_active(self) -> None:
        sm = StateMachine(self.params, initial_now=0.0)
        for t in (3.0, 6.0, 9.0, 12.0):
            sm.step(make_obs(t, external_dhcp_seen=True))
        tr = sm.step(make_obs(16.0, wifi_probe_ok=None, external_dhcp_seen=True))
        self.assertTrue(tr.changed)
        self.assertEqual(tr.current, Mode.SECONDARY)

    def test_secondary_promotes_when_primary_disappears_and_rank_wins(self) -> None:
        sm = StateMachine(self.params, initial_now=0.0)
        for t in (3.0, 6.0, 9.0, 12.0):
            sm.step(make_obs(t, external_dhcp_seen=True))
        sm.step(make_obs(16.0, external_dhcp_seen=True))
        self.assertEqual(sm.mode, Mode.SECONDARY)

        # Primary misses 2 DHCP probes after dwell (16 + 15 = 31s)
        sm.step(make_obs(32.0, external_dhcp_seen=False, peer_primary_seen=False, election_rank=1))
        tr = sm.step(make_obs(37.0, external_dhcp_seen=False, peer_primary_seen=False, election_rank=1))
        self.assertTrue(tr.changed)
        self.assertEqual(tr.current, Mode.ELECTION)

        # Rank 1 requires 0.5 + 1*2.0 = 2.5s backoff
        self.assertFalse(sm.step(make_obs(38.5, election_rank=1)).changed)
        tr_win = sm.step(make_obs(39.6, election_rank=1))
        self.assertTrue(tr_win.changed)
        self.assertEqual(tr_win.current, Mode.PRIMARY)

    def test_primary_yields_on_split_brain_or_external_dhcp(self) -> None:
        sm = StateMachine(self.params, initial_now=0.0)
        sm.mode = Mode.PRIMARY
        sm.mode_entered_at = 0.0

        # Higher-priority peer PRIMARY causes immediate yield
        tr = sm.step(make_obs(2.0, peer_primary_seen=True, peer_primary_outranks_us=True))
        self.assertTrue(tr.changed)
        self.assertEqual(tr.current, Mode.SECONDARY)

        # Also yields when an external DHCP router appears
        sm.mode = Mode.PRIMARY
        sm.mode_entered_at = 10.0
        tr2 = sm.step(make_obs(11.0, external_dhcp_seen=True))
        self.assertTrue(tr2.changed)
        self.assertEqual(tr2.current, Mode.SECONDARY)

    def test_primary_fails_over_on_wifi_loss_and_ignores_resume_grace(self) -> None:
        sm = StateMachine(self.params, initial_now=0.0)
        sm.mode = Mode.PRIMARY
        sm.mode_entered_at = 0.0

        # During resume grace, Wi-Fi failures do not trigger failover
        for t in (20.0, 23.0, 26.0, 29.0):
            sm.step(make_obs(t, wifi_link_up=False, wifi_probe_ok=False, in_resume_grace=True))
        self.assertEqual(sm.mode, Mode.PRIMARY)

        # Outside resume grace, 3 consecutive failures trigger FAILOVER
        sm.step(make_obs(32.0, wifi_probe_ok=False))
        sm.step(make_obs(35.0, wifi_probe_ok=False))
        tr = sm.step(make_obs(38.0, wifi_probe_ok=False))
        self.assertTrue(tr.changed)
        self.assertEqual(tr.current, Mode.FAILOVER)

    def test_carrier_loss_enters_idle_immediately(self) -> None:
        sm = StateMachine(self.params, initial_now=0.0)
        sm.mode = Mode.PRIMARY
        tr = sm.step(make_obs(5.0, eth_carrier=False))
        self.assertTrue(tr.changed)
        self.assertEqual(tr.current, Mode.IDLE)


if __name__ == "__main__":
    unittest.main()
