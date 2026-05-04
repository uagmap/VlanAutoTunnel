from __future__ import annotations

import re

from vlan_tool.models import FreeVlanResult, InterfaceStatus, MacTableEntry, VlanRange
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F.:-]+)\s+(?P<entry_type>\S+)\s+.+?\s+(?P<interface>\S+)\s*$"
)
INTERFACE_RE = re.compile(
    r"^(?P<interface>\S+)\s{2,}(?P<status>.+?)\s{2,}(?P<protocol>\S+)\s{2,}(?P<description>.*)$"
)


class CiscoIOSDriver(VendorDriver):
    vendor_key = "cisco_ios"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=True,
        free_vlan_search=True,
        provisioning=False,
    )

    def session_setup_commands(self) -> list[str]:
        # Netmiko cisco_ios_telnet already runs terminal width/length setup.
        # Keep this empty to avoid duplicate pager commands in session logs.
        return []

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        normalized = normalize_cisco_mac(mac_address)
        output = session.run_show(f"show mac address-table address {normalized}")
        return _parse_cisco_mac_lines(output)

    def lookup_interface_macs(self, session: SwitchSession, interface: str) -> list[MacTableEntry]:
        output = session.run_show(f"show mac address-table interface {interface.strip()}")
        wanted_interface = self.normalize_interface(interface)
        return _parse_cisco_mac_lines(output, wanted_interface=wanted_interface)

    def get_interface_statuses(self, session: SwitchSession) -> dict[str, InterfaceStatus]:
        output = _get_cisco_int_desc_output(session)
        results: dict[str, InterfaceStatus] = {}
        for line in output.splitlines():
            match = INTERFACE_RE.match(line.rstrip())
            if not match:
                continue

            interface = match.group("interface")
            normalized = self.normalize_interface(interface)
            description = match.group("description").strip() or None
            results[normalized] = InterfaceStatus(
                interface=interface,
                normalized_interface=normalized,
                admin_state=match.group("status").strip(),
                link_state=match.group("protocol").strip(),
                description=description,
                raw_line=line,
            )
        return results

    def normalize_interface(self, interface: str) -> str:
        return normalize_cisco_interface(interface)

    def find_free_vlan(self, session: SwitchSession, vlan_ranges: list[VlanRange]) -> FreeVlanResult | None:
        interface_rows = _get_cisco_int_desc_output(session)
        svi_rows = _parse_cisco_svi_rows(interface_rows)

        # Prefer reusing explicitly marked free VLANs before creating brand-new VLANs.
        for vlan_range in vlan_ranges:
            for vlan_id in range(vlan_range.start, vlan_range.end + 1):
                svi = svi_rows.get(vlan_id)
                if svi and svi["shutdown"] and "free" in svi["description"].casefold():
                    description = svi["description"]
                    return FreeVlanResult(
                        vlan_id=vlan_id,
                        reason="description-free-and-shutdown",
                        details=(
                            f"SVI Vlan{vlan_id} is admin-down with description '{description}'."
                        ),
                    )

        # Only query VLAN DB if we did not find an existing "free+shutdown" SVI candidate.
        existing_vlans = _collect_cisco_existing_vlans(session)
        if not existing_vlans and not svi_rows:
            return self._find_free_vlan_slow(session, vlan_ranges)

        for vlan_range in vlan_ranges:
            for vlan_id in range(vlan_range.start, vlan_range.end + 1):
                if vlan_id not in existing_vlans:
                    return FreeVlanResult(
                        vlan_id=vlan_id,
                        reason="non-existent",
                        details=f"VLAN {vlan_id} is missing from VLAN database.",
                    )
        return None

    def _find_free_vlan_slow(self, session: SwitchSession, vlan_ranges: list[VlanRange]) -> FreeVlanResult | None:
        first_missing: int | None = None
        for vlan_range in vlan_ranges:
            for vlan_id in range(vlan_range.start, vlan_range.end + 1):
                vlan_output = session.run_show(f"show vlan id {vlan_id}")
                if not _cisco_vlan_exists(vlan_output, vlan_id):
                    if first_missing is None:
                        first_missing = vlan_id
                    continue

                svi_output = session.run_show(f"show run int vlan {vlan_id}")
                svi = _parse_cisco_svi(svi_output, vlan_id)
                if not svi["exists"]:
                    continue

                description = svi["description"] or ""
                if "free" in description.casefold() and bool(svi["shutdown"]):
                    return FreeVlanResult(
                        vlan_id=vlan_id,
                        reason="description-free-and-shutdown",
                        details=(
                            f"SVI Vlan{vlan_id} has description '{description}' and is shutdown."
                        ),
                    )

        if first_missing is not None:
            return FreeVlanResult(
                vlan_id=first_missing,
                reason="non-existent",
                details=f"VLAN {first_missing} is missing from VLAN database.",
            )
        return None

    def summary(self) -> str:
        return "Cisco IOS over Telnet with MAC lookup, interface parsing, and free-VLAN search."


def normalize_cisco_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    groups = [compact[index : index + 4] for index in range(0, 12, 4)]
    return ".".join(group.lower() for group in groups)


def normalize_cisco_interface(interface: str) -> str:
    normalized = interface.strip().lower().replace(" ", "")
    replacements = (
        ("tengigabitethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("port-channel", "po"),
        ("ethernet", "eth"),
        ("vlan", "vl"),
    )
    for source, target in replacements:
        if normalized.startswith(source):
            return normalized.replace(source, target, 1)
    return normalized


def _cisco_vlan_exists(output: str, vlan_id: int) -> bool:
    text = output.casefold()
    missing_markers = (
        "not found in current vlan database",
        "vlan id not found",
        "invalid input",
        "incomplete command",
    )
    if any(marker in text for marker in missing_markers):
        return False
    return bool(re.search(rf"^\s*{vlan_id}\s+", output, flags=re.IGNORECASE | re.MULTILINE))


def _parse_cisco_svi(output: str, vlan_id: int) -> dict[str, str | bool | None]:
    has_interface = bool(
        re.search(
            rf"^\s*interface\s+vlan{vlan_id}\b",
            output,
            flags=re.IGNORECASE | re.MULTILINE,
        )
    )
    description_match = re.search(
        r"^\s*description\s+(?P<description>.+)$",
        output,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    shutdown = bool(re.search(r"^\s*shutdown\s*$", output, flags=re.IGNORECASE | re.MULTILINE))
    return {
        "exists": has_interface,
        "description": description_match.group("description").strip() if description_match else None,
        "shutdown": shutdown,
    }


def _parse_cisco_existing_vlans(output: str) -> set[int]:
    vlan_ids: set[int] = set()
    for line in output.splitlines():
        match = re.match(r"^\s*(?P<vlan>\d+)\s+\S+", line)
        if not match:
            continue
        vlan_ids.add(int(match.group("vlan")))
    return vlan_ids


def _parse_cisco_mac_lines(output: str, *, wanted_interface: str | None = None) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        match = MAC_LINE_RE.match(line)
        if not match:
            continue
        interface = match.group("interface")
        if wanted_interface and normalize_cisco_interface(interface) != wanted_interface:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=match.group("mac"),
                interface=interface,
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries


def _collect_cisco_existing_vlans(session: SwitchSession) -> set[int]:
    output = session.run_show("show vlan brief")
    if _is_cisco_invalid_command_output(output):
        output = session.run_show("show vlan")
    return _parse_cisco_existing_vlans(output)


def _get_cisco_int_desc_output(session: SwitchSession) -> str:
    cache_attr = "_cisco_show_int_desc_cache"
    if hasattr(session, cache_attr):
        cached = getattr(session, cache_attr)
        if isinstance(cached, str):
            return cached

    output = session.run_show("show int desc")
    setattr(session, cache_attr, output)
    return output


def _is_cisco_invalid_command_output(output: str) -> bool:
    text = output.casefold()
    return "invalid input" in text or "incomplete command" in text or "ambiguous command" in text


def _parse_cisco_svi_rows(output: str) -> dict[int, dict[str, str | bool]]:
    rows: dict[int, dict[str, str | bool]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or not stripped.lower().startswith("vl"):
            continue

        parts = re.split(r"\s{2,}", stripped, maxsplit=3)
        if len(parts) < 3:
            continue

        interface = parts[0]
        vlan_match = re.match(r"^vl(?P<vlan>\d+)$", interface, re.IGNORECASE)
        if not vlan_match:
            continue

        status_text = parts[1].strip().casefold()
        description = parts[3].strip() if len(parts) > 3 else ""
        rows[int(vlan_match.group("vlan"))] = {
            "description": description,
            "shutdown": "admin down" in status_text,
        }
    return rows
