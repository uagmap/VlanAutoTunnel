from __future__ import annotations

import re

from vlan_tool.models import InterfaceStatus, MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import (
    CLI_ERROR_RE,
    DriverCapabilities,
    VendorDriver,
    compact_mac,
    enter_enable_mode,
    first_accepted,
    format_mac,
)


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F:-]+)\s+(?P<entry_type>\S+)\s+(?P<creator>\S+)\s+(?P<interface>\S+)\s*$"
)
INTERFACE_RE = re.compile(
    r"^(?P<interface>\d+/\d+/\d+)\s+(?P<link_protocol>\S+)\s+(?P<speed>\S+)\s+(?P<duplex>\S+)\s+(?P<vlan>\S+)\s+(?P<port_type>\S+)\s*(?P<description>.*)$"
)
class SNRDriver(VendorDriver):
    vendor_key = "snr"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=True,
    )

    def prepare_session(self, session: SwitchSession) -> None:
        # SNR usually lands in user prompt ('>') and requires explicit enable.
        enter_enable_mode(session)
        # Best-effort pager disable; command support varies by SNR software train.
        first_accepted(session, ("terminal length 0", "terminal datadump", "no page"))

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = compact_mac(mac_address)
        lookup_mac = format_mac(wanted, sep="-", group=2)
        output = session.run_timing(f"show mac-address-table address {lookup_mac}")
        if CLI_ERROR_RE.search(output):
            # Fallback for older firmware where address filter syntax may differ.
            output = session.run_timing("show mac-address-table")
        return _parse_snr_mac_lines(output, wanted_mac=wanted)

    def lookup_interface_macs(self, session: SwitchSession, interface: str) -> list[MacTableEntry]:
        lookup_interface = format_snr_cli_interface(interface)
        output = session.run_timing(f"show mac-address-table interface {lookup_interface}")
        if CLI_ERROR_RE.search(output):
            output = session.run_timing(
                f"show mac-address-table int eth {normalize_snr_interface(interface)}"
            )
        if CLI_ERROR_RE.search(output):
            output = session.run_timing("show mac-address-table")
        return _parse_snr_mac_lines(
            output,
            wanted_interface=self.normalize_interface(interface),
        )

    def get_interface_statuses(self, session: SwitchSession) -> dict[str, InterfaceStatus]:
        output = session.run_timing("show interface ethernet status")
        results: dict[str, InterfaceStatus] = {}
        for line in output.splitlines():
            match = INTERFACE_RE.match(line.rstrip())
            if not match:
                continue

            interface = match.group("interface")
            vlan_text = match.group("vlan")
            mode = "trunk" if vlan_text.casefold() == "trunk" else "access"
            access_vlan = int(vlan_text) if vlan_text.isdigit() else None
            description = match.group("description").strip() or None
            link_text = match.group("link_protocol")
            admin_state, _, link_state = link_text.partition("/")
            normalized = self.normalize_interface(interface)
            results[normalized] = InterfaceStatus(
                interface=interface,
                normalized_interface=normalized,
                mode=mode,
                access_vlan=access_vlan,
                admin_state=admin_state or None,
                link_state=link_state or None,
                description=description,
                raw_line=line,
            )
        return results

    def normalize_interface(self, interface: str) -> str:
        return normalize_snr_interface(interface)

    def summary(self) -> str:
        return "SNR driver with MAC lookup and interface-status parsing."


def normalize_snr_interface(interface: str) -> str:
    """'Ethernet1/0/5', 'eth 1/0/5', '1/0/5' -> '1/0/5' (lowercase, no spaces)."""
    normalized = interface.strip().casefold().replace(" ", "")
    for prefix in ("ethernet", "eth"):
        if normalized.startswith(prefix):
            return normalized[len(prefix):]
    return normalized


def format_snr_cli_interface(interface: str, prefix: str = "Ethernet") -> str:
    """Rebuild the CLI name with the given prefix; unknown shapes pass through unchanged."""
    normalized = normalize_snr_interface(interface)
    if normalized != interface.strip().casefold().replace(" ", "") or re.match(r"^\d+/\d+/\d+$", normalized):
        return f"{prefix}{normalized}"
    return interface.strip()


def _parse_snr_mac_lines(
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
        if wanted_interface and normalize_snr_interface(parsed_interface) != wanted_interface:
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
