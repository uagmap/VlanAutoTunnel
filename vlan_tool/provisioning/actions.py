from __future__ import annotations

import re


def build_vlan_create_action(
    vendor_key: str,
    vlan_id: int,
) -> str:
    if vendor_key == "arista":
        return f"conf t ; vlan {vlan_id} ; exit"
    if vendor_key == "cisco_ios":
        return f"conf t ; vlan {vlan_id} ; exit"
    if vendor_key == "snr":
        return f"config terminal ; vlan {vlan_id} ; exit"
    if vendor_key == "snr_s5xxx":
        return f"conf ; vlan {vlan_id} ; exit"
    if vendor_key == "eltex_mes":
        return f"configure terminal ; vlan database ; vlan {vlan_id} ; exit ; exit"
    if vendor_key == "ltp":
        return f"configure terminal ; vlan {vlan_id} ; exit ; commit ; exit"
    if vendor_key == "bdcom":
        return f"conf ; vlan {vlan_id} ; exit"
    return f"create VLAN {vlan_id} (vendor-specific command required)"


def build_vlan_tag_action(*, vendor_key: str, interface: str, vlan_id: int) -> str:
    if vendor_key == "arista":
        return (
            f"conf t ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "cisco_ios":
        return (
            f"conf t ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "snr":
        return (
            f"config terminal ; interface {to_snr_config_interface(interface)} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "snr_s5xxx":
        return (
            f"conf ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "eltex_mes":
        return (
            f"configure terminal ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "ltp":
        return (
            f"configure terminal ; vlan {vlan_id} ; "
            f"tagged {interface} ; exit ; commit ; exit"
        )
    if vendor_key == "bdcom":
        return (
            f"conf ; interface {interface} ; "
            f"switchport trunk vlan-allowed add {vlan_id} ; exit"
        )
    return f"allow VLAN {vlan_id} on {interface} (vendor-specific command required)"


def to_snr_ethernet_name(interface: str) -> str:
    normalized = interface.strip()
    lowered = normalized.casefold().replace(" ", "")
    if lowered.startswith("ethernet"):
        suffix = lowered[len("ethernet") :]
        return f"Ethernet{suffix}"
    if lowered.startswith("eth"):
        suffix = lowered[len("eth") :]
        return f"Ethernet{suffix}"
    if re.match(r"^\d+/\d+/\d+$", lowered):
        return f"Ethernet{lowered}"
    return normalized


def normalize_snr_interface_local(interface: str) -> str:
    raw = interface.strip().casefold().replace(" ", "")
    if raw.startswith("ethernet"):
        raw = raw[len("ethernet") :]
    elif raw.startswith("eth"):
        raw = raw[len("eth") :]
    return raw


def to_snr_config_interface(interface: str) -> str:
    lowered = interface.strip().casefold().replace(" ", "")
    if lowered.startswith("ethernet"):
        suffix = lowered[len("ethernet") :]
        return f"eth{suffix}"
    if lowered.startswith("eth"):
        suffix = lowered[len("eth") :]
        return f"eth{suffix}"
    if re.match(r"^\d+/\d+/\d+$", lowered):
        return f"eth{lowered}"
    return interface.strip()
