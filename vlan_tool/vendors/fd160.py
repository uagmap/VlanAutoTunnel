from __future__ import annotations

import re

from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<mac>[0-9A-Fa-f:.-]+)\s+"
    r"(?P<vlan>\d+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<onu>\S+)\s+"
    r"(?P<gemid>\S+)\s+"
    r"(?P<entry_type>\S+)\s*$",
    flags=re.IGNORECASE,
)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command|error:)",
    re.IGNORECASE,
)
FD160_PHYS_IF_RE = re.compile(
    r"^(?P<type>ge|xe|xge|gpon)(?P<slot>\d+)/(?P<group>\d+)(?:/(?P<port>\d+))?$",
    re.IGNORECASE,
)


class FD160Driver(VendorDriver):
    vendor_key = "fd160"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=False,
        interface_inventory=False,
        provisioning=False,
    )

    def prepare_session(self, session: SwitchSession) -> None:
        prompt = ""
        try:
            prompt = session.connection.find_prompt()
        except Exception:
            pass
        if prompt.rstrip().endswith(">"):
            session.run_timing("ENABLE")

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_fd160_mac(mac_address)
        lookup_mac = format_fd160_cli_mac(wanted)
        output = session.run_timing(f"show mac-address dynamic include {lookup_mac}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            return []
        return parse_fd160_mac_lines(output, wanted_mac=wanted)

    def normalize_interface(self, interface: str) -> str:
        return normalize_fd160_interface(interface)

    def summary(self) -> str:
        return "FD160 OLT driver with dynamic MAC tracing and uplink VLAN tagging support."


def normalize_fd160_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_fd160_cli_mac(normalized_mac: str) -> str:
    return ":".join(normalized_mac[index : index + 2] for index in range(0, 12, 2)).upper()


def normalize_fd160_interface(interface: str) -> str:
    text = interface.strip().casefold().replace(" ", "")
    match = FD160_PHYS_IF_RE.match(text)
    if not match:
        return text
    if match.group("port") is None:
        return f"{match.group('type')}{match.group('slot')}/{match.group('group')}"
    return (
        f"{match.group('type')}{match.group('slot')}/"
        f"{match.group('group')}/{match.group('port')}"
    )


def fd160_trunk_context(interface: str) -> tuple[str, str]:
    normalized = normalize_fd160_interface(interface)
    match = FD160_PHYS_IF_RE.match(normalized)
    if not match or not match.group("port"):
        raise ValueError(
            f"FD160 trunk tagging expects ge/xe/xge/gpon X/Y/Z, got: {interface}"
        )
    return (
        f"{match.group('type')} {match.group('slot')}/{match.group('group')}",
        match.group("port"),
    )


def parse_fd160_mac_lines(output: str, *, wanted_mac: str | None = None) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        match = MAC_LINE_RE.match(line.rstrip())
        if not match:
            continue
        parsed_mac = normalize_fd160_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=format_fd160_cli_mac(parsed_mac),
                interface=match.group("interface"),
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
