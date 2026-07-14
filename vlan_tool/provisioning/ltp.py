"""LTP-specific hop handling (blanket VLAN tagging differs from normal trunk hops).

Only used when the current hop vendor is LTP; keeps that special case out of live_path.
"""

from __future__ import annotations

import re

from vlan_tool.models import SwitchRecord
from vlan_tool.provisioning.discovery import pick_downlink_entry, pick_uplink_entry
from vlan_tool.provisioning.executor import (
    is_benign_command_failure,
    looks_like_command_failure,
)
from vlan_tool.provisioning.neighbor import resolve_neighbor_from_description
from vlan_tool.provisioning.reports import HopReport
from vlan_tool.resolver import SwitchResolver


def process_ltp_destination_hop(
    *,
    session,
    switch: SwitchRecord,
    driver,
    chosen_vlan: int,
    l3_trace_mac: str,
    apply_changes: bool,
    debug: bool,
) -> tuple[HopReport, int]:
    running_config = session.run_timing("show running-config")
    vlan_block = extract_ltp_vlan_block(running_config=running_config, vlan_id=chosen_vlan)
    vlan_exists = vlan_block is not None
    tagged_interfaces = extract_ltp_tagged_interfaces_from_vlan_block(
        vlan_block=vlan_block or [],
        driver=driver,
    )
    expected_interfaces = expected_ltp_blanket_interfaces(switch=switch, driver=driver)
    blanket_tagged = expected_interfaces.issubset(tagged_interfaces)

    actions: list[str] = []
    applied_actions: list[str] = []
    executed_commands = 0
    blanket_action = build_ltp_blanket_action(vlan_id=chosen_vlan, switch=switch)
    if not blanket_tagged:
        actions.append(blanket_action)

    if apply_changes and actions:
        _debug_note(
            debug,
            f"Applying destination LTP blanket VLAN policy on {switch.name} for VLAN {chosen_vlan}.",
        )
        executed_commands += apply_ltp_blanket_vlan_policy(
            session=session,
            switch=switch,
            vlan_id=chosen_vlan,
            driver=driver,
        )
        applied_actions.extend(actions)
        running_config = session.run_timing("show running-config")
        vlan_block = extract_ltp_vlan_block(running_config=running_config, vlan_id=chosen_vlan)
        vlan_exists = vlan_block is not None
        tagged_interfaces = extract_ltp_tagged_interfaces_from_vlan_block(
            vlan_block=vlan_block or [],
            driver=driver,
        )

    uplink_entries = driver.lookup_mac(session, l3_trace_mac)
    uplink_entry = pick_uplink_entry(uplink_entries)
    uplink_interface = uplink_entry.interface if uplink_entry else None
    normalized_uplink = driver.normalize_interface(uplink_interface) if uplink_interface else None
    uplink_tagged = normalized_uplink in tagged_interfaces if normalized_uplink else None
    notes: list[str] = []
    if not uplink_interface:
        notes.append(f"Unable to find uplink interface by L3 MAC {l3_trace_mac}.")

    return (
        HopReport(
            switch=switch,
            role="destination",
            uplink_interface=uplink_interface,
            vlan_exists=vlan_exists,
            uplink_tagged=uplink_tagged,
            downlink_tagged=None,
            session_log=str(session.session_log),
            notes=notes,
            actions=actions,
            applied_actions=applied_actions,
        ),
        executed_commands,
    )


def process_ltp_intermediate_hop(
    *,
    session,
    resolver: SwitchResolver,
    switch: SwitchRecord,
    driver,
    chosen_vlan: int,
    target_mac: str,
    l3_trace_mac: str,
    apply_changes: bool,
    debug: bool,
) -> tuple[HopReport, int]:
    downlink_entries = driver.lookup_mac(session, target_mac)
    downlink_entry = pick_downlink_entry(downlink_entries)
    if not downlink_entry:
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): "
            f"destination MAC {target_mac} was not found. Continue manually."
        )

    downlink_interface = downlink_entry.interface
    normalized_downlink = driver.normalize_interface(downlink_interface)
    if is_ltp_sensitive_downlink_interface(normalized_downlink):
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): downlink {downlink_interface} "
            "is PON/ONT-facing and requires manual continuation."
        )
    if not is_ltp_front_uplink_interface(normalized_downlink):
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): unsupported downlink interface "
            f"{downlink_interface}. Continue manually."
        )

    running_config = session.run_timing("show running-config")
    vlan_block = extract_ltp_vlan_block(running_config=running_config, vlan_id=chosen_vlan)
    vlan_exists = vlan_block is not None
    tagged_interfaces = extract_ltp_tagged_interfaces_from_vlan_block(
        vlan_block=vlan_block or [],
        driver=driver,
    )
    expected_interfaces = expected_ltp_blanket_interfaces(switch=switch, driver=driver)
    blanket_tagged = expected_interfaces.issubset(tagged_interfaces)
    downlink_tagged = normalized_downlink in tagged_interfaces

    actions: list[str] = []
    applied_actions: list[str] = []
    executed_commands = 0
    blanket_action = build_ltp_blanket_action(vlan_id=chosen_vlan, switch=switch)
    if not blanket_tagged:
        actions.append(blanket_action)

    if apply_changes and actions:
        _debug_note(
            debug,
            f"Applying LTP blanket VLAN policy on {switch.name} for VLAN {chosen_vlan}.",
        )
        executed_commands += apply_ltp_blanket_vlan_policy(
            session=session,
            switch=switch,
            vlan_id=chosen_vlan,
            driver=driver,
        )
        applied_actions.extend(actions)
        running_config = session.run_timing("show running-config")
        vlan_block = extract_ltp_vlan_block(running_config=running_config, vlan_id=chosen_vlan)
        vlan_exists = vlan_block is not None
        tagged_interfaces = extract_ltp_tagged_interfaces_from_vlan_block(
            vlan_block=vlan_block or [],
            driver=driver,
        )
        downlink_tagged = normalized_downlink in tagged_interfaces

    downlink_description = extract_ltp_interface_description(
        running_config=running_config,
        interface=downlink_interface,
        driver=driver,
    )
    if not downlink_description:
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): no description found for {downlink_interface} "
            "in show running-config. Continue manually."
        )

    neighbor_switch = resolve_neighbor_from_description(
        resolver,
        downlink_description,
        source_switch=switch,
        debug=debug,
    )
    if not neighbor_switch:
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): description '{downlink_description}' "
            "did not resolve a confident next hop. Continue manually."
        )

    uplink_entries = driver.lookup_mac(session, l3_trace_mac)
    uplink_entry = pick_uplink_entry(uplink_entries)
    uplink_interface = uplink_entry.interface if uplink_entry else None
    notes: list[str] = []
    if not uplink_interface:
        notes.append(f"Unable to find uplink interface by L3 MAC {l3_trace_mac}.")

    return (
        HopReport(
            switch=switch,
            role="intermediate",
            uplink_interface=uplink_interface,
            downlink_interface=downlink_interface,
            neighbor_description=downlink_description,
            neighbor_switch=neighbor_switch,
            vlan_exists=vlan_exists,
            uplink_tagged=None,
            downlink_tagged=downlink_tagged,
            session_log=str(session.session_log),
            notes=notes,
            actions=actions,
            applied_actions=applied_actions,
        ),
        executed_commands,
    )


def is_ltp_sensitive_downlink_interface(normalized_interface: str) -> bool:
    if normalized_interface.startswith("pon-port "):
        return True
    return ":" in normalized_interface


def is_ltp_front_uplink_interface(normalized_interface: str) -> bool:
    return normalized_interface.startswith("front-port ") or normalized_interface.startswith("10g-front-port ")


def ltp_front_pon_max_port(switch: SwitchRecord) -> int:
    names = [switch.name, *(switch.aliases or [])]
    for name in names:
        match = re.search(r"\bltp-(?P<count>\d+)x\b", str(name or "").casefold())
        if not match:
            continue
        count = int(match.group("count"))
        if count <= 0:
            continue
        return count - 1
    # Conservative default for unknown LTP profile.
    return 7


def build_ltp_blanket_action(*, vlan_id: int, switch: SwitchRecord) -> str:
    max_port = ltp_front_pon_max_port(switch)
    return (
        f"configure terminal ; vlan {vlan_id} ; "
        f"tagged pon-port 0 - {max_port} ; "
        f"tagged front-port 0 - {max_port} ; "
        "tagged 10G-front-port 0 - 1 ; "
        "exit ; commit ; exit"
    )


def apply_ltp_blanket_vlan_policy(*, session, switch: SwitchRecord, vlan_id: int, driver) -> int:
    max_port = ltp_front_pon_max_port(switch)
    commands = [
        "configure terminal",
        f"vlan {vlan_id}",
        f"tagged pon-port 0 - {max_port}",
        f"tagged front-port 0 - {max_port}",
        "tagged 10G-front-port 0 - 1",
        "exit",
        "commit",
        "exit",
    ]
    executed = 0
    for command in commands:
        output = session.run_timing(command)
        if looks_like_command_failure(output) and not is_benign_command_failure(
            command=command,
            output=output,
            vendor_key=driver.vendor_key,
        ):
            raise RuntimeError(
                "Deployment failed on "
                f"{switch.name} ({switch.host}) while running '{command}'. "
                "Review session log for details."
            )
        executed += 1
    return executed


def extract_ltp_vlan_block(*, running_config: str, vlan_id: int) -> list[str] | None:
    lines = running_config.splitlines()
    start_index: int | None = None
    for index, line in enumerate(lines):
        if re.match(rf"^\s*vlan\s+{vlan_id}\b", line, flags=re.IGNORECASE):
            start_index = index
            break
    if start_index is None:
        return None

    block: list[str] = []
    for line in lines[start_index + 1 :]:
        if re.match(r"^\s*exit\s*$", line, flags=re.IGNORECASE):
            break
        block.append(line)
    return block


def extract_ltp_tagged_interfaces_from_vlan_block(*, vlan_block: list[str], driver) -> set[str]:
    tagged: set[str] = set()
    for line in vlan_block:
        match = re.match(r"^\s*tagged\s+(?P<ports>.+)$", line, flags=re.IGNORECASE)
        if not match:
            continue
        for part in match.group("ports").split(","):
            normalized = driver.normalize_interface(part)
            if normalized:
                tagged.add(normalized)
    return tagged


def expected_ltp_blanket_interfaces(*, switch: SwitchRecord, driver) -> set[str]:
    max_port = ltp_front_pon_max_port(switch)
    expected: set[str] = set()
    for index in range(0, max_port + 1):
        expected.add(driver.normalize_interface(f"pon-port {index}"))
        expected.add(driver.normalize_interface(f"front-port {index}"))
    expected.add(driver.normalize_interface("10G-front-port 0"))
    expected.add(driver.normalize_interface("10G-front-port 1"))
    return expected


def extract_ltp_interface_description(*, running_config: str, interface: str, driver) -> str | None:
    wanted = driver.normalize_interface(interface)
    current_interface: str | None = None
    for raw_line in running_config.splitlines():
        iface_match = re.match(r"^\s*interface\s+(?P<interface>.+)$", raw_line, flags=re.IGNORECASE)
        if iface_match:
            current_interface = driver.normalize_interface(iface_match.group("interface").strip())
            continue
        if current_interface != wanted:
            continue
        description_match = re.match(
            r"^\s*description\s+(?P<description>.+?)\s*$",
            raw_line,
            flags=re.IGNORECASE,
        )
        if not description_match:
            continue
        description = description_match.group("description").strip().strip("\"'`")
        if description:
            return description
    return None


def _debug_note(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[debug] {message}")
