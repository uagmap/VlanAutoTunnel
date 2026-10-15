"""FD160 interface naming: MAC table xe* maps to config xge*."""

from vlan_tool.provisioning.actions import build_vlan_tag_action
from vlan_tool.vendors.fd160 import fd160_trunk_context, normalize_fd160_interface

assert normalize_fd160_interface("xe0/0/1") == "xge0/0/1"
assert normalize_fd160_interface("xge0/0/1") == "xge0/0/1"
assert fd160_trunk_context("xe0/0/1") == ("xge 0/0", "1")

action = build_vlan_tag_action(vendor_key="fd160", interface="xe0/0/1", vlan_id=1050)
assert "interface xge 0/0" in action
assert "vlan trunk 1 1050" in action
assert "interface xe 0/0" not in action
