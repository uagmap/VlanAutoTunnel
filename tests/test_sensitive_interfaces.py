from vlan_tool.provisioning.discovery import is_sensitive_olt_terminal_interface

assert is_sensitive_olt_terminal_interface("epon0/5:6")
assert is_sensitive_olt_terminal_interface("gpon0/1:3")
assert is_sensitive_olt_terminal_interface("pon0/0/4")
assert not is_sensitive_olt_terminal_interface("xge0/0/1")
assert not is_sensitive_olt_terminal_interface("ge0/0/5")

assert is_sensitive_olt_terminal_interface("ge5", vendor_key="gr_ep_olt1")
assert is_sensitive_olt_terminal_interface("ge-6", vendor_key="gr_ep_olt1")
assert not is_sensitive_olt_terminal_interface("ge-1", vendor_key="gr_ep_olt1")
assert not is_sensitive_olt_terminal_interface("ge4", vendor_key="gr_ep_olt1")
