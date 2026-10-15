from __future__ import annotations

import re

from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import CLI_ERROR_STRICT_RE as CLI_ERROR_RE, DriverCapabilities, VendorDriver, compact_mac, format_mac


MAC_LINE_RE = re.compile(
    r"^\s*(?P<mac>[0-9A-Fa-f:.-]+)\s+"
    r"(?P<vlan>\d+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<onu>\S+)\s+"
    r"(?P<gemid>\S+)\s+"
    r"(?P<entry_type>\S+)\s*$",
    flags=re.IGNORECASE,
)
FD160_PHYS_IF_RE = re.compile(
    r"^(?P<type>ge|xe|xge|gpon)(?P<slot>\d+)/(?P<group>\d+)(?:/(?P<port>\d+))?$",
    re.IGNORECASE,
)


class FD160Driver(VendorDriver):
    vendor_key = "fd160"
    capabilities = DriverCapabilities(mac_lookup=True)

    def prepare_session(self, session: SwitchSession) -> None:
        prompt = ""
        try:
            prompt = session.connection.find_prompt()
        except Exception:
            pass
        if prompt.rstrip().endswith(">"):
            session.run_timing("ENABLE")

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = compact_mac(mac_address)
        lookup_mac = format_mac(wanted, sep=":", group=2, upper=True)
        output = session.run_timing(f"show mac-address dynamic include {lookup_mac}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            return []
        return parse_fd160_mac_lines(output, wanted_mac=wanted)

    def normalize_interface(self, interface: str) -> str:
        return normalize_fd160_interface(interface)

    def summary(self) -> str:
        return "FD160 OLT driver with dynamic MAC tracing and uplink VLAN tagging support."


def normalize_fd160_interface(interface: str) -> str:
    text = interface.strip().casefold().replace(" ", "")
    match = FD160_PHYS_IF_RE.match(text)
    if not match:
        return text
    if_type = _fd160_config_if_type(match.group("type"))
    if match.group("port") is None:
        return f"{if_type}{match.group('slot')}/{match.group('group')}"
    return (
        f"{if_type}{match.group('slot')}/"
        f"{match.group('group')}/{match.group('port')}"
    )


def _fd160_config_if_type(if_type: str) -> str:
    # ponytail: MAC table abbreviates 10G as xe; config CLI uses xge.
    if if_type == "xe":
        return "xge"
    return if_type


def fd160_trunk_context(interface: str) -> tuple[str, str]:
    normalized = normalize_fd160_interface(interface)
    match = FD160_PHYS_IF_RE.match(normalized)
    if not match or not match.group("port"):
        raise ValueError(
            f"FD160 trunk tagging expects ge/xe/xge/gpon X/Y/Z, got: {interface}"
        )
    if_type = _fd160_config_if_type(match.group("type"))
    return (
        f"{if_type} {match.group('slot')}/{match.group('group')}",
        match.group("port"),
    )


def parse_fd160_mac_lines(output: str, *, wanted_mac: str | None = None) -> list[MacTableEntry]:
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
                mac_address=format_mac(parsed_mac, sep=":", group=2, upper=True),
                interface=match.group("interface"),
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
