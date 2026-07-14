from __future__ import annotations

import re

from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<index>\d+)\s+"
    r"(?P<mac>[0-9A-Fa-f:.-]+)\s+"
    r"(?P<vlan>\d+)\s+"
    r"(?P<entry_type>\S+)\s+"
    r"(?P<interface>\S+)\s*$",
    flags=re.IGNORECASE,
)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command|error:)",
    re.IGNORECASE,
)


class GREPOLT1Driver(VendorDriver):
    vendor_key = "gr_ep_olt1"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=False,
        interface_inventory=False,
        provisioning=False,
    )

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_gr_ep_olt1_mac(mac_address)
        lookup_mac = format_gr_ep_olt1_cli_mac(wanted)
        output = session.run_timing(f"show mac-address-table mac {lookup_mac}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            return []
        return parse_gr_ep_olt1_mac_lines(output, wanted_mac=wanted)

    def normalize_interface(self, interface: str) -> str:
        return normalize_gr_ep_olt1_interface(interface)

    def summary(self) -> str:
        return "GR-EP-OLT1 local-auth EPON driver with MAC tracing and uplink VLAN tagging support."


def normalize_gr_ep_olt1_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_gr_ep_olt1_cli_mac(normalized_mac: str) -> str:
    return "-".join(normalized_mac[index : index + 2] for index in range(0, 12, 2)).upper()


def normalize_gr_ep_olt1_interface(interface: str) -> str:
    text = interface.strip().casefold().replace(" ", "")
    match = re.match(r"^ge-?(\d+)$", text)
    if not match:
        return text
    return f"ge-{match.group(1)}"


def gr_ep_olt1_swport_interface(interface: str) -> str:
    normalized = normalize_gr_ep_olt1_interface(interface)
    match = re.match(r"^ge-(?P<port>\d+)$", normalized)
    if not match:
        raise ValueError(
            f"GR-EP-OLT1 VLAN tagging expects a ge-N uplink interface, got: {interface}"
        )
    return f"ge{match.group('port')}"


def parse_gr_ep_olt1_mac_lines(output: str, *, wanted_mac: str | None = None) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        match = MAC_LINE_RE.match(line.rstrip())
        if not match:
            continue
        parsed_mac = normalize_gr_ep_olt1_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=format_gr_ep_olt1_cli_mac(parsed_mac),
                interface=match.group("interface"),
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
