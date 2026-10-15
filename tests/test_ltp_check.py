from __future__ import annotations

import unittest

from vlan_tool.diagnostics.ltp import (
    ont_cli_id,
    parse_ont_configured,
    parse_ont_events,
    parse_ont_inet_vlan,
    parse_ont_macs,
    summarize_ont_events,
)


_OK_CONFIGURED = """
-----------------------------------
GPON-port 0 ONT configured list
-----------------------------------

   ##              Serial    ONT ID   GPON-port           Status   RSSI[dBm]        Version           EquipmentID   Description
    1        VNDRA8002FFE        63           0               OK      -27.70     3.30.0.186                NTU-1L   U92059_IP_ClientA
"""

_OFFLINE_CONFIGURED = """
-----------------------------------
GPON-port 0 ONT configured list
-----------------------------------

   ##              Serial    ONT ID   GPON-port           Status   RSSI[dBm]        Version           EquipmentID   Description
    1        VNDRA80013EA        62           0          OFFLINE         n/a            n/a                   n/a   U90487_IP_ClientB
"""

_MAC_TABLE = """
-----------------------------------
[ONT0/63] MAC table (1 records)
-----------------------------------

        ##     GEM    UVID    CVID    SVID                  MAC
         1    2084                     120    F8:F0:82:58:6B:46

Total records: 1 of 1
"""

_EMPTY_MAC = """
-----------------------------------
[ONT0/62] MAC table
-----------------------------------

    ONT not found

Total records: 0 of 0
"""

_RUN_CFG = """
configure terminal
interface ont 0/62
  description "U90487_IP_ClientB"
  serial "VNDRA80013EA"
  service 0 profile cross-connect "inet172"
  service 0 profile dba "dba-00"
  profile ports "ports-all"
exit
exit
"""

_EVENTS = """
-----------------------------------
[ONT0/36] connections
-----------------------------------


----------------------------------------------
    Serial number:       VNDR6206138C
    Equipment ID         NTU-1
    Version:             3.26.5.101
    LinkUp :             2026-08-24 10:56:35
    LinkDown :           2026-08-24 10:56:45
    Last state :         Blocked

----------------------------------------------
    Serial number:       VNDR6206138C
    Equipment ID         NTU-1
    Version:             3.26.5.101
    LinkUp :             2026-08-24 10:58:03
    LinkDown :           ------
    Last state :         Working
"""


class LtpCheckTests(unittest.TestCase):
    def test_ont_cli_id_accepts_port_or_serial(self) -> None:
        self.assertEqual(ont_cli_id("0/63"), "0/63")
        self.assertEqual(ont_cli_id("ont 0/63"), "0/63")
        self.assertEqual(ont_cli_id("VNDRA8002FFE"), "VNDRA8002FFE")

    def test_parse_ok_ont_row(self) -> None:
        ont = parse_ont_configured(_OK_CONFIGURED)
        self.assertIsNotNone(ont)
        assert ont is not None
        self.assertEqual(ont.serial, "VNDRA8002FFE")
        self.assertEqual(ont.ont_ref, "0/63")
        self.assertEqual(ont.status, "OK")
        self.assertEqual(ont.rssi_dbm, -27.70)
        self.assertEqual(ont.description, "U92059_IP_ClientA")

    def test_parse_offline_ont_row(self) -> None:
        ont = parse_ont_configured(_OFFLINE_CONFIGURED)
        self.assertIsNotNone(ont)
        assert ont is not None
        self.assertEqual(ont.status, "OFFLINE")
        self.assertIsNone(ont.rssi_dbm)
        self.assertEqual(ont.ont_ref, "0/62")

    def test_parse_mac_and_empty_mac(self) -> None:
        entries = parse_ont_macs(_MAC_TABLE, ont_ref="0/63")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].mac_address, "F8:F0:82:58:6B:46")
        self.assertEqual(entries[0].vlan_id, 120)
        self.assertEqual(parse_ont_macs(_EMPTY_MAC, ont_ref="0/62"), [])

    def test_parse_inet_vlan(self) -> None:
        self.assertEqual(parse_ont_inet_vlan(_RUN_CFG), 172)

    def test_ont_events_latest_working_with_prior_down_is_warn(self) -> None:
        events = parse_ont_events(_EVENTS)
        self.assertEqual(len(events), 2)
        status, summary = summarize_ont_events(events)
        self.assertEqual(status, "WARN")
        self.assertIn("Working", summary)
        self.assertIn("LinkDown", summary)


if __name__ == "__main__":
    unittest.main()
