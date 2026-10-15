from __future__ import annotations

import re

from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import CLI_ERROR_STRICT_RE as CLI_ERROR_RE, DriverCapabilities, VendorDriver, compact_mac, format_mac


MAC_LINE_RE = re.compile(
    r"^\s*(?P<index>\d+)\s+"
    r"(?P<mac>[0-9A-Fa-f:.-]+)\s+"
    r"(?P<vlan>\d+)\s+"
    r"(?P<entry_type>\S+)\s+"
    r"(?P<interface>\S+)\s*$",
    flags=re.IGNORECASE,
)
class GREPOLT1Driver(VendorDriver):
    vendor_key = "gr_ep_olt1"
    capabilities = DriverCapabilities(mac_lookup=True)

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = compact_mac(mac_address)
        lookup_mac = format_mac(wanted, sep="-", group=2, upper=True)
        output = session.run_timing(f"show mac-address-table mac {lookup_mac}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            return []
        return parse_gr_ep_olt1_mac_lines(output, wanted_mac=wanted)

    def normalize_interface(self, interface: str) -> str:
        return normalize_gr_ep_olt1_interface(interface)

    def summary(self) -> str:
        return "GR-EP-OLT1 local-auth EPON driver with MAC tracing and uplink VLAN tagging support."


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
        parsed_mac = compact_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=format_mac(parsed_mac, sep="-", group=2, upper=True),
                interface=match.group("interface"),
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
