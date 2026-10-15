"""Vendor-specific CLI snippets for create-VLAN and trunk-tag actions.

Returns command bundles as strings; executor/live_path send them to the switch.
"""

from __future__ import annotations

from vlan_tool.vendors.bdcom import format_bdcom_config_interface
from vlan_tool.vendors.fd160 import fd160_trunk_context
from vlan_tool.vendors.gr_ep_olt1 import gr_ep_olt1_swport_interface
from vlan_tool.vendors.gr_ep_olt2 import gr_ep_olt2_trunk_context
from vlan_tool.vendors.snr import format_snr_cli_interface
from vlan_tool.vendors.snr_s2970 import format_snr_s2970_config_interface

_CREATE_VLAN = {
    "arista": "conf t ; vlan {v} ; exit",
    "cisco_ios": "conf t ; vlan {v} ; exit",
    "snr": "config terminal ; vlan {v} ; exit",
    "snr_s2970": "config ; vlan {v} ; exit",
    "snr_s5xxx": "conf ; vlan {v} ; exit",
    "eltex_mes": "configure terminal ; vlan database ; vlan {v} ; exit ; exit",
    "fd160": "conf ; vlan {v}",
    "gr_ep_olt2": "vlan {v}",
    "ltp": "configure terminal ; vlan {v} ; exit ; commit ; exit",
    "bdcom_gpon": (
        "conf ; vlan {v} ; exit ; gpon profile onu-vlan V{v} ; "
        "gpon-profile vlan mode tag ; gpon-profile vlan pvid {v} ; exit"
    ),
    "bdcom": "conf ; vlan {v} ; exit",
}
# (config-enter, interface formatter, allow command). Interface formatter gets the raw name.
_TAG_VLAN = {
    "arista": ("conf t", lambda i: i, "switchport trunk allowed vlan add {v}"),
    "cisco_ios": ("conf t", lambda i: i, "switchport trunk allowed vlan add {v}"),
    "snr": ("config terminal", lambda i: format_snr_cli_interface(i, "eth"), "switchport trunk allowed vlan add {v}"),
    "snr_s2970": ("config", format_snr_s2970_config_interface, "switchport trunk vlan-allowed add {v}"),
    "snr_s5xxx": ("conf", lambda i: i, "switchport trunk allowed vlan add {v}"),
    "eltex_mes": ("configure terminal", lambda i: i, "switchport trunk allowed vlan add {v}"),
    "bdcom": ("conf", format_bdcom_config_interface, "switchport trunk vlan-allowed add {v}"),
    "bdcom_gpon": ("conf", format_bdcom_config_interface, "switchport trunk vlan-allowed add {v}"),
}


def build_vlan_create_action(vendor_key: str, vlan_id: int) -> str | None:
    if vendor_key == "gr_ep_olt1":
        return None
    template = _CREATE_VLAN.get(vendor_key, "create VLAN {v} (vendor-specific command required)")
    return template.format(v=vlan_id)


def build_vlan_tag_action(*, vendor_key: str, interface: str, vlan_id: int) -> str:
    if vendor_key in _TAG_VLAN:
        enter, fmt, allow = _TAG_VLAN[vendor_key]
        return f"{enter} ; interface {fmt(interface)} ; {allow.format(v=vlan_id)} ; exit"
    if vendor_key in {"fd160", "gr_ep_olt2"}:
        context, port_id = (fd160_trunk_context if vendor_key == "fd160" else gr_ep_olt2_trunk_context)(interface)
        prefix = "conf ; " if vendor_key == "fd160" else ""
        return f"{prefix}interface {context} ; vlan trunk {port_id} {vlan_id} ; exit"
    if vendor_key == "gr_ep_olt1":
        return f"swport {gr_ep_olt1_swport_interface(interface)} ; vlan add {vlan_id} tag ; exit"
    if vendor_key == "ltp":
        return f"configure terminal ; vlan {vlan_id} ; tagged {interface} ; exit ; commit ; exit"
    return f"allow VLAN {vlan_id} on {interface} (vendor-specific command required)"


def build_gr_ep_olt2_epon_blanket_action(vlan_id: int) -> str:
    # ponytail: ONU side is opaque; blanket-tag EPON ports 1-8 like field practice.
    return f"interface epon 0/0 ; vlan trunk 1-8 {vlan_id} ; exit"
