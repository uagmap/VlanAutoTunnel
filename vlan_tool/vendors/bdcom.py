from __future__ import annotations

import re

from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import (
    CLI_ERROR_STRICT_RE as CLI_ERROR_RE,
    DriverCapabilities,
    VendorDriver,
    compact_mac,
    first_accepted,
    format_mac,
    mac_on_line_containing,
)


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F.:-]+)\s+(?P<entry_type>\S+)\s+(?P<interface>\S+)\s*$"
)


class BDCOMDriver(VendorDriver):
    vendor_key = "bdcom"
    capabilities = DriverCapabilities(mac_lookup=True, mac_lookup_by_interface=True)

    def prepare_session(self, session: SwitchSession) -> None:
        first_accepted(session, ("terminal length 0", "no page"), CLI_ERROR_RE)

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = compact_mac(mac_address)
        output = session.run_timing(f"show mac address-table {format_mac(wanted, sep='.', group=4)}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            output = session.run_timing("show mac address-table")
        return _parse_bdcom_mac_lines(output, wanted_mac=wanted)

    def lookup_interface_macs(self, session: SwitchSession, interface: str) -> list[MacTableEntry]:
        lookup_interface = format_bdcom_cli_interface(interface)
        output = session.run_timing(f"show mac address-table interface {lookup_interface}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            output = session.run_timing("show mac address-table")
        return _parse_bdcom_mac_lines(
            output,
            wanted_interface=self.normalize_interface(interface),
        )

    def normalize_interface(self, interface: str) -> str:
        return normalize_bdcom_interface(interface)

    def summary(self) -> str:
        return "BDCOM driver with VLAN/MAC tracing support for switch uplinks."


class BDCOMGPONDriver(BDCOMDriver):
    vendor_key = "bdcom_gpon"

    def summary(self) -> str:
        return "BDCOM GPON driver with ONU VLAN profile creation support."


def normalize_bdcom_interface(interface: str) -> str:
    normalized = interface.strip().casefold().replace(" ", "")
    replacements = (
        ("gigabitethernet", "g"),
        ("fastethernet", "f"),
        ("tengigabitethernet", "te"),
        ("vlan", "vl"),
    )
    for source, target in replacements:
        if normalized.startswith(source):
            normalized = normalized.replace(source, target, 1)
            break
    # MAC table often shows ONU UNI as gpon0/6:49-1; treat as gpon0/6:49.
    onu_uni = re.match(r"^((?:epon|gpon)\d+/\d+:\d+)-\d+$", normalized)
    if onu_uni:
        return onu_uni.group(1)
    return normalized


def bdcom_trunk_interface(interface: str) -> str:
    """Parent trunk port for VLAN allow / show vlan (gpon0/6:49 -> gpon0/6)."""
    normalized = normalize_bdcom_interface(interface)
    parent = re.match(r"^((?:epon|gpon)\d+/\d+)(?::\d+)?$", normalized)
    if parent:
        return parent.group(1)
    return normalized


def format_bdcom_config_interface(interface: str) -> str:
    """Config-mode interface name (gpon0/6:49 -> 'gpon 0/6')."""
    trunk = bdcom_trunk_interface(interface)
    pon = re.match(r"^(epon|gpon)(\d+/\d+)$", trunk)
    if pon:
        return f"{pon.group(1)} {pon.group(2)}"
    return interface.strip()


def format_bdcom_cli_interface(interface: str) -> str:
    normalized = normalize_bdcom_interface(interface)
    if re.match(r"^(?:g|f|te|epon|gpon)\d+/\d+(?::\d+)?$", normalized):
        return normalized
    return interface.strip()


def extract_bdcom_base_mac_from_version(output: str) -> str | None:
    return mac_on_line_containing(output, "base ethernet mac address")


def _parse_bdcom_mac_lines(
    output: str,
    *,
    wanted_mac: str | None = None,
    wanted_interface: str | None = None,
) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        match = MAC_LINE_RE.match(line.rstrip())
        if not match:
            continue

        parsed_mac = compact_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue

        parsed_interface = match.group("interface")
        if wanted_interface and normalize_bdcom_interface(parsed_interface) != wanted_interface:
            continue

        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=match.group("mac"),
                interface=parsed_interface,
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
