from __future__ import annotations

import unittest

from vlan_tool.diagnostics.bdcom import (
    onu_cli_ref,
    parse_onu_basic_info,
    parse_onu_rx_dbm,
    summarize_onu_history,
)
from vlan_tool.vendors.bdcom import _parse_bdcom_mac_lines, normalize_bdcom_interface


_BASIC = """
Serial number                  VNDR:A64E310A (42495356A64E310A)
VendorID                       VNDR (42495356)
Admin state                    Unlock (1)
Operational state              Enabled (1)
Distance                       1287.3 m
ONU Config                     Success (2, 0)
ONU Description                rt70527_ClientA
Online Duration                0h 19m 5s
--------------------------------------------------------------
The current time: 2026-9-3 13:33:35
Seq  Active Time          Deactive Time        Deactive Reason
 01  2026-07-28 22:52:03  2026-08-04 08:30:54  Dying Gasp
 19  2026-09-01 19:37:49  2026-09-03 13:13:43  Losi
 20  2026-09-03 13:14:29
"""

_OPTICAL = """
 interface    RxPower(dBm)
-----------  --------------
 gpon0/2:52   -24.4
"""

_MAC = """
        Mac Address Table (Total 1)
------------------------------------------

Vlan    Mac Address       Type       Ports
----    -----------       ----       -----
126     18e8.29c3.7d5a    DYNAMIC    gpon0/2:52-1
"""


class BdcomCheckTests(unittest.TestCase):
    def test_onu_cli_ref_accepts_common_forms(self) -> None:
        ref = onu_cli_ref("2/52")
        self.assertEqual(ref.compact, "gpon0/2:52")
        self.assertEqual(ref.cli, "gpon 0/2:52")
        self.assertEqual(onu_cli_ref("0/2:52").compact, "gpon0/2:52")
        self.assertEqual(onu_cli_ref("0/2/52").compact, "gpon0/2:52")
        self.assertEqual(onu_cli_ref("gpon0/2:52").onu_id, 52)
        self.assertEqual(onu_cli_ref("gpon 0/2:52").pon, 2)

    def test_parse_onu_basic_info(self) -> None:
        ref = onu_cli_ref("0/2:52")
        ont = parse_onu_basic_info(_BASIC, ref=ref)
        self.assertIsNotNone(ont)
        assert ont is not None
        self.assertEqual(ont.operational_state, "Enabled")
        self.assertEqual(ont.serial, "VNDR:A64E310A")
        self.assertEqual(ont.description, "rt70527_ClientA")
        self.assertEqual(ont.distance_m, 1287.3)
        self.assertEqual(ont.online_seconds, 19 * 60 + 5)
        self.assertEqual(len(ont.history), 3)
        self.assertIsNone(ont.history[-1][1])
        self.assertEqual(ont.history[-2][2], "Losi")

    def test_stable_online_history_is_pass(self) -> None:
        ref = onu_cli_ref("0/2:52")
        ont = parse_onu_basic_info(_BASIC, ref=ref)
        assert ont is not None
        status, summary = summarize_onu_history(ont.history, online_seconds=ont.online_seconds)
        self.assertEqual(status, "PASS")
        self.assertIn("stable", summary)
        self.assertIn("Losi", summary)

    def test_recent_losi_with_short_uptime_is_warn(self) -> None:
        history = [
            ("2026-09-03 13:13:00", "2026-09-03 13:13:43", "Losi"),
            ("2026-09-03 13:14:29", None, None),
        ]
        status, summary = summarize_onu_history(history, online_seconds=60)
        self.assertEqual(status, "WARN")
        self.assertIn("Losi", summary)

    def test_parse_optical_and_mac(self) -> None:
        self.assertEqual(parse_onu_rx_dbm(_OPTICAL), -24.4)
        entries = _parse_bdcom_mac_lines(
            _MAC,
            wanted_interface=normalize_bdcom_interface("gpon0/2:52"),
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].mac_address, "18e8.29c3.7d5a")
        self.assertEqual(entries[0].vlan_id, 126)


if __name__ == "__main__":
    unittest.main()
