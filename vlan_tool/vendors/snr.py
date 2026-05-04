from __future__ import annotations

import re

from vlan_tool.models import InterfaceStatus, MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F:-]+)\s+(?P<entry_type>\S+)\s+(?P<creator>\S+)\s+(?P<interface>\S+)\s*$"
)
INTERFACE_RE = re.compile(
    r"^(?P<interface>\d+/\d+/\d+)\s+(?P<link_protocol>\S+)\s+(?P<speed>\S+)\s+(?P<duplex>\S+)\s+(?P<vlan>\S+)\s+(?P<port_type>\S+)\s*(?P<description>.*)$"
)
PASSWORD_PROMPT_RE = re.compile(r"(?:password|passcode)\s*[:>]\s*$", re.IGNORECASE)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command)",
    re.IGNORECASE,
)


class SNRDriver(VendorDriver):
    vendor_key = "snr"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=True,
        provisioning=False,
    )

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def prepare_session(self, session: SwitchSession) -> None:
        # SNR usually lands in user prompt ('>') and requires explicit enable.
        enable_output = session.run_timing("enable", confirm_label="enter enable mode")
        if PASSWORD_PROMPT_RE.search(enable_output):
            secret = str(getattr(session.connection, "secret", "") or "")
            session.run_timing(
                secret,
                confirm_label="send enable password",
                sensitive=True,
            )

        # Best-effort pager disable; command support varies by SNR software train.
        for command in ("terminal length 0", "terminal datadump", "no page"):
            response = session.run_timing(command)
            if not CLI_ERROR_RE.search(response):
                break

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_snr_mac(mac_address)
        lookup_mac = format_snr_cli_mac(wanted)
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
                f"show mac-address-table int {format_snr_cli_interface_short(interface)}"
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


def normalize_snr_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_snr_cli_mac(normalized_mac: str) -> str:
    return "-".join(normalized_mac[index : index + 2] for index in range(0, 12, 2))


def format_snr_cli_interface(interface: str) -> str:
    normalized = interface.strip().casefold().replace(" ", "")
    if normalized.startswith("ethernet"):
        return f"Ethernet{normalized[len('ethernet'):]}"
    if normalized.startswith("eth"):
        return f"Ethernet{normalized[len('eth'):]}"
    if re.match(r"^\d+/\d+/\d+$", normalized):
        return f"Ethernet{normalized}"
    return interface.strip()


def normalize_snr_interface(interface: str) -> str:
    normalized = interface.strip()
    lower = normalized.casefold()
    if lower.startswith("ethernet"):
        normalized = normalized[len("ethernet") :]
    elif lower.startswith("eth"):
        normalized = normalized[len("eth") :]
    return normalized.casefold()


def format_snr_cli_interface_short(interface: str) -> str:
    normalized = normalize_snr_interface(interface)
    if normalized:
        return f"eth {normalized}"
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
        parsed_mac = normalize_snr_mac(match.group("mac"))
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
