from vlan_tool.naming import infer_vendor_from_name
from vlan_tool.provisioning.actions import build_vlan_create_action, build_vlan_tag_action
from vlan_tool.vendors.bdcom import bdcom_trunk_interface, format_bdcom_config_interface


assert infer_vendor_from_name("bdcom.gp3600.foo_id1") == "bdcom_gpon"
assert infer_vendor_from_name("bdcom.gpon.foo_id1") == "bdcom_gpon"
assert infer_vendor_from_name("bdcom.epon.foo_id1") == "bdcom"

assert build_vlan_create_action("bdcom_gpon", 150) == (
    "conf ; vlan 150 ; exit ; "
    "gpon profile onu-vlan V150 ; "
    "gpon-profile vlan mode tag ; "
    "gpon-profile vlan pvid 150 ; exit"
)

assert bdcom_trunk_interface("gpon0/6:49-1") == "gpon0/6"
assert format_bdcom_config_interface("gpon0/6:49") == "gpon 0/6"
assert build_vlan_tag_action(vendor_key="bdcom_gpon", interface="gpon0/6:49", vlan_id=160) == (
    "conf ; interface gpon 0/6 ; switchport trunk vlan-allowed add 160 ; exit"
)

print("ok")
