from __future__ import annotations

import re

from vlan_tool.provisioning.actions import normalize_snr_interface_local, to_snr_ethernet_name
from vlan_tool.provisioning.common import looks_like_invalid_command


def lookup_interface_description(
    *,
    statuses: dict[str, object],
    driver,
    interface: str | None,
) -> str | None:
    if not interface:
        return None
    normalized = driver.normalize_interface(interface)
    details = statuses.get(normalized)
    if not details:
        return None
    description = str(getattr(details, "description", "") or "").strip()
    return description or None


def discover_interface_description(*, session, driver, interface: str | None) -> str | None:
    if not interface:
        return None

    commands = build_interface_description_commands(driver.vendor_key, interface)
    for command in commands:
        output = run_vendor_show_command(session=session, vendor_key=driver.vendor_key, command=command)
        if not output or looks_like_invalid_command(output):
            continue
        match = re.search(
            r"^\s*description\s+(?P<description>.+)$",
            output,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        if not match:
            continue
        description = match.group("description").strip()
        if description:
            return description
    return None


def build_interface_description_commands(vendor_key: str, interface: str) -> list[str]:
    raw = interface.strip()
    if vendor_key == "snr":
        normalized = normalize_snr_interface_local(interface)
        return [
            f"show run int eth {normalized}",
            f"show run int eth{normalized}",
            f"show run int {to_snr_ethernet_name(interface)}",
        ]
    if vendor_key == "snr_s5xxx":
        compact = raw.lower().replace(" ", "")
        return [
            f"show running-config interface {compact}",
            f"show run interface {compact}",
            f"show run int {compact}",
            f"show run int {raw}",
        ]
    if vendor_key == "eltex_mes":
        return [f"show run int {raw.lower().replace(' ', '')}"]
    if vendor_key == "arista":
        return [f"show run int {raw.lower().replace(' ', '')}"]
    if vendor_key == "bdcom":
        compact = raw.lower().replace(" ", "")
        return [
            f"show running-config interface {compact}",
            f"show run interface {compact}",
            f"show run int {compact}",
        ]
    return [f"show run int {raw}"]


def run_vendor_show_command(*, session, vendor_key: str, command: str) -> str:
    if vendor_key in {"snr", "snr_s5xxx", "eltex_mes", "arista", "bdcom", "ltp"}:
        return session.run_timing(command)
    return session.run_show(command)
