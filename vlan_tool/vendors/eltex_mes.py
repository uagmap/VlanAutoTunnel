from __future__ import annotations

import re

from vlan_tool.models import InterfaceStatus, MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F:.-]+)\s+(?P<interface>\S+)\s+(?P<entry_type>\S+)\s*$"
)
INTERFACE_RE = re.compile(
    r"^(?P<interface>\S+)\s{2,}(?P<mode>.+?)\s{2,}(?P<admin>\S+)\s{2,}(?P<link>.+?)\s{2,}(?P<description>.*)$"
)
ACCESS_MODE_RE = re.compile(r"Access\s+\((?P<vlan>\d+)\)", re.IGNORECASE)
PASSWORD_PROMPT_RE = re.compile(r"(?:password|passcode)\s*[:>]\s*$", re.IGNORECASE)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command)",
    re.IGNORECASE,
)


class EltexMESDriver(VendorDriver):
    vendor_key = "eltex_mes"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=True,
        provisioning=False,
    )

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def prepare_session(self, session: SwitchSession) -> None:
        # Eltex often starts at '>' and needs ENABLE to reach privileged prompt.
        enable_output = session.run_timing("enable", confirm_label="enter enable mode")
        if PASSWORD_PROMPT_RE.search(enable_output):
            secret = str(getattr(session.connection, "secret", "") or "")
            session.run_timing(
                secret,
                confirm_label="send enable password",
                sensitive=True,
            )

        # Best-effort pager disable; command support can vary by firmware.
        for command in ("terminal datadump", "terminal length 0", "no page"):
            response = session.run_timing(command)
            if not CLI_ERROR_RE.search(response):
                break

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_eltex_mac(mac_address)
        lookup_mac = format_eltex_cli_mac(wanted)
        output = session.run_timing(f"show mac address-table address {lookup_mac}")
        if CLI_ERROR_RE.search(output):
            # Fallback for firmware variants without direct address filter.
            output = session.run_timing("show mac address-table")
        return _parse_eltex_mac_lines(output, wanted_mac=wanted)

    def lookup_interface_macs(self, session: SwitchSession, interface: str) -> list[MacTableEntry]:
        lookup_interface = interface.strip().lower().replace(" ", "")
        output = session.run_timing(f"show mac address-table interface {lookup_interface}")
        if CLI_ERROR_RE.search(output):
            output = session.run_timing("show mac address-table")
        return _parse_eltex_mac_lines(
            output,
            wanted_interface=self.normalize_interface(interface),
        )

    def get_interface_statuses(self, session: SwitchSession) -> dict[str, InterfaceStatus]:
        # Prefer physical ports only to avoid large channel/VLAN blocks in output.
        output = session.run_timing("show int description | i 1/0")
        if CLI_ERROR_RE.search(output):
            output = session.run_timing("show int description")
        results = _parse_eltex_interface_statuses_output(self, output)
        if results:
            return results

        # Fallback for platforms where CLI filter syntax differs.
        full_output = session.run_timing("show int description")
        return _parse_eltex_interface_statuses_output(self, full_output)

    def normalize_interface(self, interface: str) -> str:
        return normalize_eltex_interface(interface)

    def summary(self) -> str:
        return "Eltex MES driver with MAC lookup and interface-description parsing."


def normalize_eltex_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_eltex_cli_mac(normalized_mac: str) -> str:
    return "-".join(normalized_mac[index : index + 2] for index in range(0, 12, 2))


def normalize_eltex_interface(interface: str) -> str:
    return interface.strip().lower().replace(" ", "")


def _parse_eltex_mac_lines(
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
        parsed_mac = normalize_eltex_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue

        parsed_interface = match.group("interface")
        if wanted_interface and normalize_eltex_interface(parsed_interface) != wanted_interface:
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


def _parse_eltex_interface_statuses_output(
    driver: EltexMESDriver,
    output: str,
) -> dict[str, InterfaceStatus]:
    results: dict[str, InterfaceStatus] = {}
    for line in output.splitlines():
        match = INTERFACE_RE.match(line.rstrip())
        if not match:
            continue

        interface = match.group("interface")
        if interface.lower() in {"port", "ch"}:
            continue

        mode_text = match.group("mode").strip()
        description = match.group("description").strip() or None
        access_match = ACCESS_MODE_RE.search(mode_text)
        mode = mode_text
        access_vlan = None
        if access_match:
            mode = "access"
            access_vlan = int(access_match.group("vlan"))
        elif mode_text.casefold().startswith("trunk"):
            mode = "trunk"

        normalized = driver.normalize_interface(interface)
        results[normalized] = InterfaceStatus(
            interface=interface,
            normalized_interface=normalized,
            mode=mode,
            access_vlan=access_vlan,
            admin_state=match.group("admin").strip(),
            link_state=match.group("link").strip(),
            description=description,
            raw_line=line,
        )
    return results
