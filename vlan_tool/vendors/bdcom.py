from __future__ import annotations

import re

from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F.:-]+)\s+(?P<entry_type>\S+)\s+(?P<interface>\S+)\s*$"
)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command|error:)",
    re.IGNORECASE,
)


class BDCOMDriver(VendorDriver):
    vendor_key = "bdcom"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=False,
        provisioning=False,
    )

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def prepare_session(self, session: SwitchSession) -> None:
        for command in ("terminal length 0", "no page"):
            response = session.run_timing(command)
            if not CLI_ERROR_RE.search(response):
                break

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_bdcom_mac(mac_address)
        output = session.run_timing(f"show mac address-table {format_bdcom_cli_mac(wanted)}")
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


def normalize_bdcom_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_bdcom_cli_mac(normalized_mac: str) -> str:
    groups = [normalized_mac[index : index + 4] for index in range(0, 12, 4)]
    return ".".join(groups)


def normalize_bdcom_interface(interface: str) -> str:
    normalized = interface.strip().casefold().replace(" ", "")
    replacements = (
        ("gigabitethernet", "g"),
        ("fastethernet", "f"),
        ("tengigabitethernet", "te"),
        ("epon", "epon"),
        ("gpon", "gpon"),
        ("vlan", "vl"),
    )
    for source, target in replacements:
        if normalized.startswith(source):
            return normalized.replace(source, target, 1)
    return normalized


def format_bdcom_cli_interface(interface: str) -> str:
    normalized = normalize_bdcom_interface(interface)
    if normalized.startswith("g") and re.match(r"^g\d+/\d+(?::\d+)?$", normalized):
        return normalized
    if normalized.startswith("f") and re.match(r"^f\d+/\d+(?::\d+)?$", normalized):
        return normalized
    if normalized.startswith("te") and re.match(r"^te\d+/\d+(?::\d+)?$", normalized):
        return normalized
    if normalized.startswith("epon") and re.match(r"^epon\d+/\d+(?::\d+)?$", normalized):
        return normalized
    if normalized.startswith("gpon") and re.match(r"^gpon\d+/\d+(?::\d+)?$", normalized):
        return normalized
    return interface.strip()


def extract_bdcom_base_mac_from_version(output: str) -> str | None:
    for line in output.splitlines():
        if "base ethernet mac address" not in line.casefold():
            continue
        mac_match = re.search(
            r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})",
            line,
        )
        if not mac_match:
            continue
        try:
            normalize_bdcom_mac(mac_match.group(1))
        except ValueError:
            continue
        return mac_match.group(1)
    return None


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

        parsed_mac = normalize_bdcom_mac(match.group("mac"))
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
