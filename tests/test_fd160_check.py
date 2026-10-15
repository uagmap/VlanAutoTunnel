from __future__ import annotations

import unittest

from vlan_tool.diagnostics.fd160 import (
    Fd160OntRef,
    ont_cli_ref,
    parse_ont_all_rows,
    parse_ont_events,
    parse_ont_info,
    parse_ont_learned_mac,
    parse_ont_rx_dbm,
    resolve_ont_ref,
    strip_fd160_noise,
    summarize_ont_events,
    summarize_pon_port,
)

_ONT_INFO = """
2026-08-31 12:58:55   PON 0/0/1 ONU: 42 ONU-SN(VNDRAF29B093) The ONT offline
--------------------------------------------------------------------------------------------------------
  F/S                  : 0/0
  Port                 : 1
  ONT-ID               : 41
  Control flag         : active
  Run state            : Online
  Config state         : success
  Match state          : match
  Distance(m)          : 456
  SN                   : VNDRAF29B091 (VNDR-AF29B091)
  Description          : U89937_IP_ClientB
  Last down cause      : reboot
  Online  time         : 0days 13h:41m:8s
---------------------------------------------------------------
  Port  Port  Max-MAC-Count  Max-Frame-Size     N-VLAN     N-PRI Outbound Inbound Dhcp-ip
  type  ID
---------------------------------------------------------------
  ETH   1    1                  1522            142         0     -       -        --
"""

_ONT_ALL = """
  0/0 1  40     VNDRAF29B08F     Active   Online  success   match     --          U89169_IP_ClientA
  0/0 1  41     VNDRAF29B091     Active   Online  success   match     reboot      U89937_IP_ClientB
 --More ( Press 'Q' to quit )--   2026-08-31 12:59:46   PON 0/0/1 ONU: 42 ONU-SN  0/0 1  42     VNDRAF29B093     Active   Offline initial   match     dying-gasp  U99838_IP_ClientC
----------------------------------------------------------------------------------------
  Total: 78,  online: 71,  deactive: 0,  success: 71 , failed: 0
"""

_OPTICAL = """
  Rx optical power(dBm)                   : -21.74
  Tx optical power(dBm)                   : 2.01
"""

_LEARNED_MAC = """
--------------------------------------------------------------------------------------------------------
  PORT         ONT     ONT         ONT         MAC-ADDRESS
               ID      port-type   port-ID
--------------------------------------------------------------------------------------------------------
  gpon 0/0/1    41     ETH         1           50:FF:20:E3:79:20
--------------------------------------------------------------------------------------------------------
"""

_EVENTS = """
 113002    2026-08-30 23:17:08  Warning    PON 0/0/1 ONU: 41 ONU-SN(VNDRAF29B091)   The ONT offline
 113001    2026-08-30 23:17:52  Warning    PON 0/0/1 ONU: 41 ONU-SN(VNDRAF29B091)   The ONT online
 113002    2026-08-31 12:58:55  Warning    PON 0/0/1 ONU: 42 ONU-SN(VNDRAF29B093)   The ONT offline
"""


class Fd160CheckTests(unittest.TestCase):
    def test_ont_cli_ref_accepts_pon_ont_or_serial(self) -> None:
        ref = ont_cli_ref("1/41")
        self.assertIsInstance(ref, Fd160OntRef)
        self.assertEqual(ref.pon_port, 1)
        self.assertEqual(ref.ont_id, 41)
        fs_ref = ont_cli_ref("0/0/1/41")
        self.assertIsInstance(fs_ref, Fd160OntRef)
        self.assertEqual(fs_ref.label, "0/0/1/41")
        self.assertEqual(ont_cli_ref("VNDRAF29B091"), "VNDRAF29B091")

    def test_strip_fd160_noise_removes_async_pon_lines(self) -> None:
        cleaned = strip_fd160_noise(_ONT_INFO)
        self.assertNotIn("The ONT offline", cleaned)
        self.assertIn("Run state", cleaned)

    def test_parse_ont_info(self) -> None:
        ref = ont_cli_ref("1/41")
        self.assertIsInstance(ref, Fd160OntRef)
        ont = parse_ont_info(_ONT_INFO, ref=ref)
        self.assertIsNotNone(ont)
        assert ont is not None
        self.assertEqual(ont.run_state, "Online")
        self.assertEqual(ont.description, "U89937_IP_ClientB")
        self.assertEqual(ont.native_vlan, 142)
        self.assertEqual(ont.last_down_cause, "reboot")
        self.assertEqual(ont.online_seconds, (13 * 60 + 41) * 60)

    def test_parse_ont_all_rows_and_serial_resolve(self) -> None:
        rows = parse_ont_all_rows(_ONT_ALL)
        self.assertEqual(len(rows), 3)
        ref = resolve_ont_ref(rows, "VNDRAF29B091")
        self.assertIsNotNone(ref)
        assert ref is not None
        self.assertEqual(ref.ont_id, 41)

    def test_pon_health_passes_for_mostly_online_pon(self) -> None:
        rows = parse_ont_all_rows(_ONT_ALL)
        status, summary = summarize_pon_port(rows, pon_port=1)
        self.assertEqual(status, "PASS")
        self.assertIn("2/3", summary)

    def test_parse_optical_and_mac(self) -> None:
        self.assertEqual(parse_ont_rx_dbm(_OPTICAL), -21.74)
        self.assertEqual(parse_ont_learned_mac(_LEARNED_MAC), "50:FF:20:E3:79:20")

    def test_ont_events_filter_and_stable_uptime_is_pass(self) -> None:
        events = parse_ont_events(_EVENTS, ont_id=41, serial="VNDRAF29B091")
        self.assertEqual(len(events), 2)
        status, summary = summarize_ont_events(events, online_seconds=13 * 3600)
        self.assertEqual(status, "PASS")
        self.assertIn("stable", summary)


if __name__ == "__main__":
    unittest.main()
