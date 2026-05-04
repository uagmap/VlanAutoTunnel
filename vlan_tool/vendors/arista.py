from __future__ import annotations

import re

from vlan_tool.models import InterfaceStatus, MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F.:-]+)\s+(?P<entry_type>\S+)\s+(?P<interface>\S+)\s+.*$"
)
INTERFACE_RE = re.compile(
    r"^(?P<interface>\S+)\s{2,}(?P<status>\S+)\s{2,}(?P<protocol>\S+)\s{2,}(?P<description>.*)$"
)
PASSWORD_PROMPT_RE = re.compile(r"(?:password|passcode)\s*[:>]\s*$", re.IGNORECASE)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command)",
    re.IGNORECASE,
)


class AristaDriver(VendorDriver):
    vendor_key = "arista"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=True,
        provisioning=False,
    )

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def prepare_session(self, session: SwitchSession) -> None:
        # Netmiko's arista_eos_telnet already disables pagination.
        # Only handle enable password if needed.
        enable_output = session.run_timing("enable", confirm_label="enter enable mode")
        if PASSWORD_PROMPT_RE.search(enable_output):
            secret = str(getattr(session.connection, "secret", "") or "")
            session.run_timing(
                secret,
                confirm_label="send enable password",
                sensitive=True,
            )

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_arista_mac(mac_address)
        lookup_mac = format_arista_cli_mac(wanted)
        output = session.run_timing(f"show mac address-table address {lookup_mac}")
        if CLI_ERROR_RE.search(output):
            output = session.run_timing("show mac address-table")
        return _parse_arista_mac_lines(output, wanted_mac=wanted)

    def lookup_interface_macs(self, session: SwitchSession, interface: str) -> list[MacTableEntry]:
        lookup_interface = format_arista_cli_interface(interface)
        output = session.run_timing(f"show mac address-table interface {lookup_interface}")
        if CLI_ERROR_RE.search(output):
            output = session.run_timing("show mac address-table")
        return _parse_arista_mac_lines(
            output,
            wanted_interface=self.normalize_interface(interface),
        )

    def get_interface_statuses(self, session: SwitchSession) -> dict[str, InterfaceStatus]:
        output = session.run_timing("show int desc")
        results: dict[str, InterfaceStatus] = {}
        for line in output.splitlines():
            match = INTERFACE_RE.match(line.rstrip())
            if not match:
                continue

            interface = match.group("interface")
            if interface.casefold() == "interface":
                continue

            normalized = self.normalize_interface(interface)
            results[normalized] = InterfaceStatus(
                interface=interface,
                normalized_interface=normalized,
                admin_state=match.group("status").strip(),
                link_state=match.group("protocol").strip(),
                description=match.group("description").strip() or None,
                raw_line=line,
            )
        return results

    def normalize_interface(self, interface: str) -> str:
        return normalize_arista_interface(interface)

    def summary(self) -> str:
        return "Arista EOS driver with MAC lookup and interface-description parsing."


def normalize_arista_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_arista_cli_mac(normalized_mac: str) -> str:
    groups = [normalized_mac[index : index + 4] for index in range(0, 12, 4)]
    return ".".join(groups)


def normalize_arista_interface(interface: str) -> str:
    normalized = interface.strip().lower().replace(" ", "")
    replacements = (
        ("ethernet", "et"),
        ("eth", "et"),
        ("port-channel", "po"),
        ("vlan", "vl"),
    )
    for source, target in replacements:
        if normalized.startswith(source):
            return normalized.replace(source, target, 1)
    return normalized


def format_arista_cli_interface(interface: str) -> str:
    normalized = normalize_arista_interface(interface)
    if normalized.startswith("et"):
        return f"Et{normalized[2:]}"
    if normalized.startswith("po"):
        return f"Po{normalized[2:]}"
    if normalized.startswith("vl"):
        return f"Vl{normalized[2:]}"
    return interface.strip()


def _parse_arista_mac_lines(
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

        parsed_mac = normalize_arista_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue

        parsed_interface = match.group("interface")
        if wanted_interface and normalize_arista_interface(parsed_interface) != wanted_interface:
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
