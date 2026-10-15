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
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F:.-]+)\s+(?P<interface>\S+)\s+(?P<entry_type>\S+)\s*$"
)
# Older MES: Port  Admin  Link  Description
INTERFACE_RE = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<admin>\S+)\s+"
    r"(?P<link>\S+)"
    r"(?:\s+(?P<description>.*))?$"
)
# MES2324b: Port  Access (20)|Trunk  Admin  Link  Description
INTERFACE_MODE_RE = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<mode>Access\s+\(\d+\)|Trunk)\s+"
    r"(?P<admin>Up|Down)\s+"
    r"(?P<link>Up|Down|Not\s+Present)"
    r"(?:\s+(?P<description>.*))?$",
    re.IGNORECASE,
)
ACCESS_MODE_RE = re.compile(r"Access\s+\((?P<vlan>\d+)\)", re.IGNORECASE)


class EltexMESDriver(VendorDriver):
    vendor_key = "eltex_mes"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=True,
    )

    def prepare_session(self, session: SwitchSession) -> None:
        # Eltex often starts at '>' and needs ENABLE to reach privileged prompt.
        enter_enable_mode(session)
        # Best-effort pager/width; command support can vary by firmware.
        # Wide width avoids mid-command wrap redisplays that look like prompts.
        # (terminal* only — never touch running-config here; no logging console.)
        first_accepted(session, ("terminal datadump", "terminal length 0", "no page"))
        first_accepted(session, ("terminal width 512", "terminal width 0"))

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = compact_mac(mac_address)
        # Dotted form is shorter; hyphen form wraps on narrow MES terminals and
        # redisplays hostname# mid-command, which false-triggers prompt expect.
        lookup_mac = format_mac(wanted, sep=".", group=4)
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
        parsed_mac = compact_mac(match.group("mac"))
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
        text = line.rstrip()
        match = INTERFACE_MODE_RE.match(text) or INTERFACE_RE.match(text)
        if not match:
            continue

        interface = match.group("interface")
        if interface.lower() in {"port", "ch"}:
            continue

        description = (match.group("description") or "").strip() or None
        mode_text = match.groupdict().get("mode") or ""
        access_match = ACCESS_MODE_RE.search(mode_text) or ACCESS_MODE_RE.search(description or "")
        access_vlan = int(access_match.group("vlan")) if access_match else None
        if access_match:
            mode = "access"
        elif mode_text.casefold() == "trunk":
            mode = "trunk"
        else:
            mode = None

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
