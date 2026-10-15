"""Find things needed before/during a path walk: free VLAN, target MAC, L3 MAC, MAC-table picks.

Read-only discovery helpers — does not apply config changes.
"""

from __future__ import annotations

import ipaddress
import re

from vlan_tool import site
from vlan_tool.models import MacTableEntry, ProvisioningRequest, SwitchRecord, VlanRange
from vlan_tool.provisioning.common import MAC_RE, compact_mac, looks_like_control_plane_mac, looks_like_invalid_command
from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
from vlan_tool.trace_panel import ui_print
from vlan_tool.vendors import get_driver
from vlan_tool.vendors.bdcom import extract_bdcom_base_mac_from_version
from vlan_tool.vendors.snr_s5xxx import extract_snr_s5_vlan_mac_from_version


def select_vlan_for_plan(*, session, driver, vlan_ranges: list[VlanRange], requested_vlan: int | None) -> tuple[int, str]:
    if requested_vlan is not None:
        return requested_vlan, "requested-vlan"
    if not driver.capabilities.free_vlan_search:
        raise RuntimeError(
            f"Vendor driver '{driver.vendor_key}' cannot auto-find free VLANs on this L3. "
            "Pass --vlan explicitly."
        )
    result = driver.find_free_vlan(session, vlan_ranges)
    if result is None:
        raise RuntimeError(
            "No free VLAN found on L3 in configured ranges. "
            "Provide --vlan manually."
        )
    return result.vlan_id, result.reason


def discover_destination_mac_from_l3_arp(*, session, driver, destination_switch: SwitchRecord) -> str | None:
    if not site.is_ip_address(destination_switch.host):
        return None

    command = f"show ip arp {destination_switch.host}"
    output = session.run_show(command) if driver.vendor_key == "cisco_ios" else session.run_timing(command)
    if looks_like_invalid_command(output):
        return None
    return extract_arp_mac_for_ip(output=output, ip_address=destination_switch.host)


def extract_arp_mac_for_ip(*, output: str, ip_address: str) -> str | None:
    # Whole-address match: "10.20.1.1" must not hit the "10.20.1.10" row.
    ip_re = re.compile(rf"(?<![\d.]){re.escape(ip_address)}(?![\d.])")
    for line in output.splitlines():
        line_text = line.strip()
        if not line_text or not ip_re.search(line_text) or "incomplete" in line_text.casefold():
            continue
        mac_match = MAC_RE.search(line_text)
        if mac_match and not looks_like_control_plane_mac(compact_mac(mac_match.group(1))):
            return mac_match.group(1)
    return None


def extract_ip_for_mac(*, output: str, mac_address: str) -> str | None:
    wanted = compact_mac(mac_address)
    if len(wanted) != 12 or looks_like_control_plane_mac(wanted):
        return None
    for line in output.splitlines():
        mac_match = MAC_RE.search(line)
        if not mac_match or compact_mac(mac_match.group(1)) != wanted:
            continue
        for ip_match in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line):
            if site.is_ip_address(ip_match.group(1)):
                return ip_match.group(1)
    return None


def discover_l3_trace_mac(*, session, driver, switch: SwitchRecord | None = None) -> str | None:
    mgmt = site.MANAGEMENT_VLAN
    if driver.vendor_key == "cisco_ios":
        if looks_like_c9500_switch(switch):
            static_output = session.run_show("show mac address-table | i STATIC")
            if not looks_like_invalid_command(static_output):
                c9500_trace_mac = extract_c9500_static_mgmt_vlan_mac(static_output)
                if c9500_trace_mac:
                    return c9500_trace_mac
        output = session.run_show("show mac address-table | i Switch")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_show(f"show mac address-table vlan {mgmt}")
    elif driver.vendor_key in {"snr", "snr_s5xxx"}:
        table = "mac-address-table" if driver.vendor_key == "snr" else "mac address-table"
        output = session.run_timing(f"show {table} | i CPU")
        if looks_like_invalid_command(output):
            output = session.run_timing(f"show {table} vlan {mgmt}")
        if looks_like_invalid_command(output):
            output = session.run_timing(f"show {table}")
    elif driver.vendor_key in {"eltex_mes", "arista"}:
        output = session.run_timing(f"show mac address-table vlan {mgmt}")
        if looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
    else:
        return None

    candidates: list[tuple[int, str]] = []
    for line in output.splitlines():
        mac_match = MAC_RE.search(line)
        if not mac_match:
            continue
        lower = line.casefold()
        score = 0
        if any(word in lower for word in ("switch", "cpu", "self", "system")):
            score += 100
        if "static" in lower:
            score += 20
        if str(mgmt) in lower:
            score += 10
        candidates.append((score, mac_match.group(1)))

    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def looks_like_c9500_switch(switch: SwitchRecord | None) -> bool:
    if not switch:
        return False
    return any(re.search(r"\bc9500\b", str(name or "").casefold()) for name in switch.all_names)


def extract_c9500_static_mgmt_vlan_mac(output: str) -> str | None:
    mgmt = site.MANAGEMENT_VLAN
    pattern = re.compile(
        rf"^\s*{mgmt}\s+(?P<mac>{MAC_RE.pattern})\s+STATIC\b.*\bVl{mgmt}\b",
        flags=re.IGNORECASE,
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            return match.group("mac")
    return None


def _entry_score(entry: MacTableEntry, *, prefer_mgmt_vlan: bool) -> tuple[int, int]:
    entry_type = str(entry.entry_type or "").casefold()
    interface = str(entry.interface or "").casefold()
    vlan = entry.vlan_id if isinstance(entry.vlan_id, int) else 0
    points = 0
    if "dynamic" in entry_type:
        points += 80 if prefer_mgmt_vlan else 100
    if prefer_mgmt_vlan:
        if vlan == site.MANAGEMENT_VLAN:
            points += 100
    elif vlan not in {0, 1, site.MANAGEMENT_VLAN}:
        points += 40
    if interface in {"switch", "cpu", "self", "0"}:
        points -= 100 if prefer_mgmt_vlan else 80
    return points, vlan


def pick_downlink_entry(entries: list[MacTableEntry]) -> MacTableEntry | None:
    """Client-side MAC entry: dynamic, on a service VLAN, on a real port."""
    if not entries:
        return None
    return max(entries, key=lambda entry: _entry_score(entry, prefer_mgmt_vlan=False))


def pick_uplink_entry(entries: list[MacTableEntry]) -> MacTableEntry | None:
    """Uplink MAC entry: the L3 self-MAC is learned on the management VLAN."""
    if not entries:
        return None
    return max(entries, key=lambda entry: _entry_score(entry, prefer_mgmt_vlan=True))


def is_sensitive_olt_terminal_interface(
    interface: str | None,
    *,
    vendor_key: str | None = None,
) -> bool:
    if not interface:
        return False
    normalized = interface.strip().casefold().replace(" ", "")

    if vendor_key == "gr_ep_olt1":
        ge_match = re.match(r"^ge-?(\d+)$", normalized)
        if ge_match and int(ge_match.group(1)) > 4:
            return True

    return bool(re.match(r"^(?:epon|gpon|pon|ont)\d", normalized))


def discover_target_mac(
    config,
    request: ProvisioningRequest,
    *,
    debug: bool = True,
) -> tuple[str | None, str]:
    resolver = SwitchResolver(config)
    destination_switch = resolver.resolve(request.destination_switch)
    driver = get_driver(destination_switch.vendor)

    with open_switch_session(
        config,
        destination_switch,
        debug=debug,
    ) as session:
        driver.prepare_session(session)
        if request.destination_port:
            if not driver.capabilities.mac_lookup_by_interface:
                raise RuntimeError(
                    f"Vendor driver '{driver.vendor_key}' cannot auto-discover MACs by interface yet. "
                    "This platform needs interface MAC lookup support before plan/deploy can run automatically."
                )
            entries = driver.lookup_interface_macs(session, request.destination_port)
            ui_print(f"Session log (destination MAC discovery): {session.session_log}")
            if entries:
                selected = select_preferred_mac_entry(entries)
                return selected.mac_address, f"port {request.destination_port}"

            # Empty ONU/port is fine: keep destination_port for tagging, walk path via switch MAC.
            discovered = discover_switch_self_mac(
                session=session,
                driver=driver,
                switch=destination_switch,
            )
            ui_print(f"Session log (destination self-MAC fallback): {session.session_log}")
            if discovered:
                return (
                    discovered,
                    f"switch self MAC (no MAC on port {request.destination_port})",
                )
            return None, f"port {request.destination_port} (empty) and switch self MAC"

        discovered = discover_switch_self_mac(
            session=session,
            driver=driver,
            switch=destination_switch,
        )
        ui_print(f"Session log (destination self-MAC discovery): {session.session_log}")
        return discovered, "switch self MAC"


def discover_switch_self_mac(*, session, driver, switch: SwitchRecord) -> str | None:
    if driver.vendor_key in {"cisco_ios", "arista"}:
        return discover_l3_trace_mac(session=session, driver=driver, switch=switch)

    if driver.vendor_key == "snr":
        output = session.run_timing("show mac-address-table | i CPU")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac-address-table")
        return extract_preferred_switch_mac(output, require_any_keywords=("cpu", "system"))

    if driver.vendor_key == "snr_s5xxx":
        discovered_from_version = extract_snr_s5_vlan_mac_from_version(session.run_timing("show version"))
        if discovered_from_version:
            return discovered_from_version

        output = session.run_timing("show mac address-table | i CPU")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        return extract_preferred_switch_mac(
            output, require_any_keywords=("cpu", "system", "static")
        ) or extract_preferred_switch_mac(output, require_any_keywords=())

    if driver.vendor_key == "eltex_mes":
        output = session.run_timing("show mac address-table | i self")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        return extract_preferred_switch_mac(output, require_any_keywords=("self",))

    if driver.vendor_key in {"bdcom", "bdcom_gpon"}:
        discovered_from_version = extract_bdcom_base_mac_from_version(session.run_timing("show version"))
        if discovered_from_version:
            return discovered_from_version

        output = session.run_timing("show mac address-table static")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        return extract_preferred_switch_mac(output, require_any_keywords=("cpu", "static"))

    return None


def extract_preferred_switch_mac(
    output: str,
    *,
    require_any_keywords: tuple[str, ...],
) -> str | None:
    candidates: list[tuple[int, str]] = []
    for line in output.splitlines():
        lower = line.casefold()
        if require_any_keywords and not any(keyword in lower for keyword in require_any_keywords):
            continue
        mac_match = MAC_RE.search(line)
        if not mac_match or looks_like_control_plane_mac(compact_mac(mac_match.group(1))):
            continue

        score = 0
        if str(site.MANAGEMENT_VLAN) in lower:
            score += 40
        if "static" in lower:
            score += 20
        score += 50 * sum(keyword in lower for keyword in require_any_keywords)
        candidates.append((score, mac_match.group(1)))

    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def select_preferred_mac_entry(entries: list[MacTableEntry]) -> MacTableEntry:
    def _score(entry: MacTableEntry) -> tuple[int, int]:
        entry_type = str(entry.entry_type or "").casefold()
        vlan_id = entry.vlan_id
        score = 0
        if "dynamic" in entry_type:
            score += 100
        if isinstance(vlan_id, int) and vlan_id not in {1, site.MANAGEMENT_VLAN}:
            score += 20
        if isinstance(vlan_id, int) and 100 <= vlan_id <= 4094:
            score += 5
        return score, -(vlan_id if isinstance(vlan_id, int) else 0)

    return max(entries, key=_score)
