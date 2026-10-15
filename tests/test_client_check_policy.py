"""Self-check for client-check helpers."""

from vlan_tool.diagnostics.physical import _parse_snr_vct
from vlan_tool.diagnostics.port import (
    _log_timestamp_snippet,
    format_status_change_age,
    parse_status_change_seconds,
)
from vlan_tool.diagnostics.vlan_policy import expected_vlans_for_port
from vlan_tool.provisioning.discovery import extract_ip_for_mac

vlans, _ = expected_vlans_for_port("F64082_ClientA")
assert vlans == {20, 21}

vlans, _ = expected_vlans_for_port("U12345_client", access_vlan=512)
assert vlans == {512}

sample_arp = """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.20.5.148             5   8cae.db54.b65f   ARPA   Vlan20
"""
assert extract_ip_for_mac(output=sample_arp, mac_address="8c-ae-db-54-b6-5f") == "10.20.5.148"

sample_iface = """
  Time since last status change:0w-1d-7h-4m-4s  (111844 seconds)
"""
assert parse_status_change_seconds(sample_iface) == 111844
assert format_status_change_age(sample_iface) == "1d 7h"

sample_log = (
    "2115 %Aug 15 22:42:38:294 2026 <warnings> MODULE_PORT[tphyDaemon]:"
    "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1/0/8, changed state to DOWN"
)
assert _log_timestamp_snippet(sample_log) == "%Aug 15 22:42:38:294 2026"

sample_vct = """
Interface Ethernet1/0/8:
Cable pairs Cable status Error length (meters)
(1, 2) well 0
(3, 6) well 0
(4, 5) open 5
(7, 8) open 5
"""
vct = _parse_snr_vct(
    sample_vct,
    link_up=True,
    interface_detail="Auto-speed: Negotiation 100M bits",
)
assert vct.status == "PASS"

print("ok")
