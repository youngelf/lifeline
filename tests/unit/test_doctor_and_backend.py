"""Unit tests for auto backend selection and `lifelinectl doctor`."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lifeline.backends import NetworkManagerBackend, NetworkdBackend
from lifeline.cli import cmd_doctor
from lifeline.daemon import build_backend


class TestDoctorAndAutoBackend(unittest.TestCase):
    def test_build_backend_auto_detects_networkmanager_vs_networkd(self) -> None:
        with patch("lifeline.daemon._is_systemd_unit_active") as m_act, patch(
            "lifeline.daemon._nm_device_table"
        ) as m_nm:
            # Case 1: NM active & manages eth0 -> NetworkManagerBackend
            m_act.side_effect = lambda u: "active" if u == "NetworkManager" else "inactive"
            m_nm.return_value = [("eth0", "ethernet", "connected", "Wired")]
            self.assertIsInstance(build_backend("auto", "eth0"), NetworkManagerBackend)

            # Case 2: NM active, but eth0 is unmanaged and systemd-networkd active -> NetworkdBackend
            m_act.side_effect = lambda u: "active"
            m_nm.return_value = [("eth0", "ethernet", "unmanaged", "--")]
            self.assertIsInstance(build_backend("auto", "eth0"), NetworkdBackend)

            # Case 3: NM inactive, systemd-networkd active -> NetworkdBackend
            m_act.side_effect = lambda u: "active" if u == "systemd-networkd" else "inactive"
            self.assertIsInstance(build_backend("auto", "auto"), NetworkdBackend)

    def test_doctor_reports_config_error_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.toml"
            rc = cmd_doctor(missing)
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
