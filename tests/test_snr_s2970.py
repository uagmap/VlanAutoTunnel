from vlan_tool.naming import infer_vendor_from_name
from vlan_tool.provisioning.actions import build_vlan_create_action, build_vlan_tag_action
from vlan_tool.vendors.base import format_mac
from vlan_tool.vendors.snr_s2970 import (
    normalize_snr_s2970_interface,
    snr_s2970_interface_tagged,
    snr_s2970_vlan_exists,
)

assert infer_vendor_from_name("SNR-S2970G-24S.site_id1012") == "snr_s2970"
assert infer_vendor_from_name("SNR-S5210G-24FX.foo") == "snr_s5xxx"
assert infer_vendor_from_name("SNR-S2985G-8T.foo") == "snr"

assert format_mac("aabbccddeeff", sep=".", group=4) == "aabb.ccdd.eeff"
assert normalize_snr_s2970_interface("G0/24") == "g0/24"
assert normalize_snr_s2970_interface("g0/1") == "g0/1"

assert build_vlan_create_action("snr_s2970", 180) == "config ; vlan 180 ; exit"
assert build_vlan_tag_action(vendor_key="snr_s2970", interface="G0/1", vlan_id=180) == (
    "config ; interface g0/1 ; switchport trunk vlan-allowed add 180 ; exit"
)

vlan_sample = """
VLAN id: 20, Name: VLAN0020
Mode: Static, Total Ports: 9

Interface       Attributes
G0/3            Trunk, Tagged
G0/10           Access
G0/24           Trunk, Tagged
"""
assert snr_s2970_vlan_exists(20, vlan_sample)
assert snr_s2970_interface_tagged(vlan_id=20, interface="g0/24", snapshot=vlan_sample)
assert not snr_s2970_interface_tagged(vlan_id=20, interface="g0/10", snapshot=vlan_sample)
assert not snr_s2970_interface_tagged(vlan_id=20, interface="g0/2", snapshot=vlan_sample)
