from vlan_tool.naming import infer_vendor_from_name
from vlan_tool.provisioning.actions import (
    build_gr_ep_olt2_epon_blanket_action,
    build_vlan_create_action,
    build_vlan_tag_action,
)
from vlan_tool.vendors.gr_ep_olt2 import (
    _is_pager_noise,
    format_gr_ep_olt2_section_interface,
    gr_ep_olt2_interface_tagged,
    gr_ep_olt2_trunk_context,
    gr_ep_olt2_vlan_exists,
    parse_gr_ep_olt2_mac_lines,
)

VLAN_SAMPLE = """
-----------------------------------------------------------------------------
 Vlan-ID: 3333        Vlan-Name: vlan3333
 Untagged-Ports: -
 Tagged-Ports:
        ge0/0/1      ge0/0/5      xge0/0/1     pon0/0/4
-----------------------------------------------------------------------------
"""


SAMPLE = """
 MAC                 VLAN   Port          MAC-Type
-----------------------------------------------------------------------------
 E0:D9:E3:A7:16:C0   10     xge0/0/1      dynamic
 F8:F0:82:D4:57:F1   10     pon0/0/4      dynamic
 00:55:B1:49:5A:D6   10     ge0/0/5       dynamic
 E0:67:B3:7A:E5:A4   10     cpu           static
"""


assert infer_vendor_from_name("GR-EP-OLT2-8-2AC.site12a_id1013") == "gr_ep_olt2"
assert infer_vendor_from_name("GR-EP-OLT1-4.site12b_id1014") == "gr_ep_olt1"

entries = parse_gr_ep_olt2_mac_lines(SAMPLE, wanted_mac="e0d9e3a716c0")
assert len(entries) == 1
assert entries[0].vlan_id == 10
assert entries[0].interface == "xge0/0/1"
assert entries[0].mac_address == "E0:D9:E3:A7:16:C0"

entries = parse_gr_ep_olt2_mac_lines(SAMPLE, wanted_mac="0055.b149.5ad6")
assert len(entries) == 1
assert entries[0].interface == "ge0/0/5"
assert entries[0].mac_address == "00:55:B1:49:5A:D6"

assert _is_pager_noise(" --More ( Press 'Q' to quit )-- ")
assert not _is_pager_noise(" 00:55:B1:49:5A:D6   10     ge0/0/5       dynamic")

assert format_gr_ep_olt2_section_interface("ge0/0/5") == "ge 0/0/5"
assert gr_ep_olt2_vlan_exists(3333, VLAN_SAMPLE)
assert gr_ep_olt2_interface_tagged(vlan_id=3333, interface="ge0/0/5", snapshot=VLAN_SAMPLE)
assert not gr_ep_olt2_interface_tagged(vlan_id=3333, interface="ge0/0/2", snapshot=VLAN_SAMPLE)

assert gr_ep_olt2_trunk_context("ge0/0/4") == ("ge 0/0", "4")
assert gr_ep_olt2_trunk_context("xge0/0/1") == ("xge 0/0", "1")
assert gr_ep_olt2_trunk_context("pon0/0/4") == ("pon 0/0", "4")

assert build_vlan_create_action("gr_ep_olt2", 150) == "vlan 150"
assert build_vlan_tag_action(vendor_key="gr_ep_olt2", interface="ge0/0/4", vlan_id=150) == (
    "interface ge 0/0 ; vlan trunk 4 150 ; exit"
)
assert build_vlan_tag_action(vendor_key="gr_ep_olt2", interface="xge0/0/1", vlan_id=150) == (
    "interface xge 0/0 ; vlan trunk 1 150 ; exit"
)
assert build_gr_ep_olt2_epon_blanket_action(1050) == (
    "interface epon 0/0 ; vlan trunk 1-8 1050 ; exit"
)
