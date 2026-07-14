from __future__ import annotations

import ipaddress
import re

from vlan_tool.models import MacTableEntry, ProvisioningRequest, SwitchRecord, VlanRange
from vlan_tool.provisioning.common import looks_like_control_plane_mac, looks_like_invalid_command
from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
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
    if not is_ip_address_text(destination_switch.host):
        return None

    command = f"show ip arp {destination_switch.host}"
    output = session.run_show(command) if driver.vendor_key == "cisco_ios" else session.run_timing(command)
    if looks_like_invalid_command(output):
        return None
    return extract_arp_mac_for_ip(output=output, ip_address=destination_switch.host)


def extract_arp_mac_for_ip(*, output: str, ip_address: str) -> str | None:
    for line in output.splitlines():
        line_text = line.strip()
        if not line_text or ip_address not in line_text:
            continue
        lower = line_text.casefold()
        if "incomplete" in lower:
            continue
        mac_match = re.search(
            r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})",
            line_text,
        )
        if not mac_match:
            continue
        compact_mac = re.sub(r"[^0-9A-Fa-f]", "", mac_match.group(1)).casefold()
        if len(compact_mac) != 12 or looks_like_control_plane_mac(compact_mac):
            continue
        return mac_match.group(1)
    return None


def is_ip_address_text(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def discover_l3_trace_mac(*, session, driver, switch: SwitchRecord | None = None) -> str | None:
    if driver.vendor_key == "cisco_ios":
        if looks_like_c9500_switch(switch):
            static_output = session.run_show("show mac address-table | i STATIC")
            if not looks_like_invalid_command(static_output):
                c9500_trace_mac = extract_c9500_static_vlan111_mac(static_output)
                if c9500_trace_mac:
                    return c9500_trace_mac
        output = session.run_show("show mac address-table | i Switch")
        if not output.strip():
            output = session.run_show("show mac address-table vlan 111")
        elif looks_like_invalid_command(output):
            output = session.run_show("show mac address-table vlan 111")
    elif driver.vendor_key == "snr":
        output = session.run_timing("show mac-address-table | i CPU")
        if looks_like_invalid_command(output):
            output = session.run_timing("show mac-address-table vlan 111")
        if looks_like_invalid_command(output):
            output = session.run_timing("show mac-address-table")
    elif driver.vendor_key == "snr_s5xxx":
        output = session.run_timing("show mac address-table | i CPU")
        if looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table vlan 111")
        if looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
    elif driver.vendor_key == "eltex_mes":
        output = session.run_timing("show mac address-table vlan 111")
        if looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
    elif driver.vendor_key == "arista":
        output = session.run_timing("show mac address-table vlan 111")
        if looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
    else:
        return None

    candidates: list[tuple[int, str]] = []
    for line in output.splitlines():
        line_text = line.strip()
        if not line_text:
            continue
        mac_match = re.search(
            r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})",
            line_text,
        )
        if not mac_match:
            continue
        score = 0
        lower = line_text.casefold()
        if "switch" in lower or "cpu" in lower or "self" in lower or "system" in lower:
            score += 100
        if "static" in lower:
            score += 20
        if "111" in lower:
            score += 10
        candidates.append((score, mac_match.group(1)))

    if not candidates:
        return None
    return sorted(candidates, key=lambda item: item[0], reverse=True)[0][1]


def looks_like_c9500_switch(switch: SwitchRecord | None) -> bool:
    if not switch:
        return False
    names = [switch.name, *(switch.aliases or [])]
    for candidate in names:
        if re.search(r"\bc9500\b", str(candidate or "").casefold()):
            return True
    return False


def extract_c9500_static_vlan111_mac(output: str) -> str | None:
    pattern = re.compile(
        r"^\s*111\s+"
        r"(?P<mac>[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|"
        r"[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+"
        r"STATIC\b.*\bVl111\b",
        flags=re.IGNORECASE,
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            return match.group("mac")
    return None


def pick_downlink_entry(entries: list[MacTableEntry]) -> MacTableEntry | None:
    if not entries:
        return None

    def score(entry: MacTableEntry) -> tuple[int, int]:
        entry_type = str(entry.entry_type or "").casefold()
        interface = str(entry.interface or "").casefold()
        vlan = entry.vlan_id if isinstance(entry.vlan_id, int) else 0
        points = 0
        if "dynamic" in entry_type:
            points += 100
        if vlan not in {0, 1, 111}:
            points += 40
        if interface in {"switch", "cpu", "self", "0"}:
            points -= 80
        return points, vlan

    return sorted(entries, key=score, reverse=True)[0]


def pick_uplink_entry(entries: list[MacTableEntry]) -> MacTableEntry | None:
    if not entries:
        return None

    def score(entry: MacTableEntry) -> tuple[int, int]:
        entry_type = str(entry.entry_type or "").casefold()
        interface = str(entry.interface or "").casefold()
        vlan = entry.vlan_id if isinstance(entry.vlan_id, int) else 0
        points = 0
        if "dynamic" in entry_type:
            points += 80
        if vlan == 111:
            points += 100
        if interface in {"switch", "cpu", "self", "0"}:
            points -= 100
        return points, vlan

    return sorted(entries, key=score, reverse=True)[0]


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
    confirm_steps: bool,
    debug: bool,
) -> tuple[str | None, str]:
    resolver = SwitchResolver(config)
    destination_switch = resolver.resolve(request.destination_switch)
    driver = get_driver(destination_switch.vendor)

    with open_switch_session(
        config,
        destination_switch,
        confirm_connect=confirm_steps,
        confirm_commands=confirm_steps,
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
            print(f"Session log (destination MAC discovery): {session.session_log}")
            if not entries:
                return None, f"port {request.destination_port}"
            selected = select_preferred_mac_entry(entries)
            return selected.mac_address, f"port {request.destination_port}"

        discovered = discover_switch_self_mac(
            session=session,
            driver=driver,
            switch=destination_switch,
        )
        print(f"Session log (destination self-MAC discovery): {session.session_log}")
        return discovered, "switch self MAC"


def discover_switch_self_mac(*, session, driver, switch: SwitchRecord) -> str | None:
    if driver.vendor_key in {"cisco_ios", "arista"}:
        return discover_l3_trace_mac(session=session, driver=driver, switch=switch)

    if driver.vendor_key == "snr":
        output = session.run_timing("show mac-address-table | i CPU")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac-address-table")
        return extract_preferred_switch_mac(
            output,
            require_any_keywords=("cpu", "system"),
        )

    if driver.vendor_key == "snr_s5xxx":
        version_output = session.run_timing("show version")
        discovered_from_version = extract_snr_s5_vlan_mac_from_version(version_output)
        if discovered_from_version:
            return discovered_from_version

        output = session.run_timing("show mac address-table | i CPU")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        discovered = extract_preferred_switch_mac(
            output,
            require_any_keywords=("cpu", "system", "static"),
        )
        if discovered:
            return discovered
        return extract_preferred_switch_mac(
            output,
            require_any_keywords=(),
        )

    if driver.vendor_key == "eltex_mes":
        output = session.run_timing("show mac address-table | i self")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        return extract_preferred_switch_mac(
            output,
            require_any_keywords=("self",),
        )

    if driver.vendor_key == "bdcom":
        version_output = session.run_timing("show version")
        discovered_from_version = extract_bdcom_base_mac_from_version(version_output)
        if discovered_from_version:
            return discovered_from_version

        output = session.run_timing("show mac address-table static")
        if not output.strip() or looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        return extract_preferred_switch_mac(
            output,
            require_any_keywords=("cpu", "static"),
        )

    return None


def extract_preferred_switch_mac(
    output: str,
    *,
    require_any_keywords: tuple[str, ...],
) -> str | None:
    candidates: list[tuple[int, str]] = []
    for line in output.splitlines():
        line_text = line.strip()
        if not line_text:
            continue
        lower = line_text.casefold()
        if require_any_keywords and not any(keyword in lower for keyword in require_any_keywords):
            continue
        mac_match = re.search(
            r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})",
            line_text,
        )
        if not mac_match:
            continue
        compact_mac = re.sub(r"[^0-9A-Fa-f]", "", mac_match.group(1)).casefold()
        if len(compact_mac) != 12:
            continue
        if looks_like_control_plane_mac(compact_mac):
            continue

        score = 0
        if "111" in lower:
            score += 40
        if "static" in lower:
            score += 20
        for keyword in require_any_keywords:
            if keyword in lower:
                score += 50
        candidates.append((score, mac_match.group(1)))

    if not candidates:
        return None
    return sorted(candidates, key=lambda item: item[0], reverse=True)[0][1]


def select_preferred_mac_entry(entries: list[MacTableEntry]) -> MacTableEntry:
    def _score(entry: MacTableEntry) -> tuple[int, int]:
        entry_type = str(getattr(entry, "entry_type", "") or "").casefold()
        vlan_id = getattr(entry, "vlan_id", None)
        score = 0
        if "dynamic" in entry_type:
            score += 100
        if isinstance(vlan_id, int) and vlan_id not in {1, 111}:
            score += 20
        if isinstance(vlan_id, int) and 100 <= vlan_id <= 4094:
            score += 5
        return score, -(vlan_id if isinstance(vlan_id, int) else 0)

    return sorted(entries, key=_score, reverse=True)[0]


def select_vlan_ranges(config, switch: SwitchRecord) -> list[VlanRange]:
    if switch.site and switch.site in config.sites and config.sites[switch.site].vlan_ranges:
        return config.sites[switch.site].vlan_ranges
    return config.vlan_ranges


def looks_like_l3_ip(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return str(address).startswith("10.1.1.")
