from __future__ import annotations

from vlan_tool.models import ProvisioningRequest
from vlan_tool.provisioning.actions import (
    build_vlan_create_action as _build_vlan_create_action,
    build_vlan_tag_action as _build_vlan_tag_action,
)
from vlan_tool.provisioning.common import debug_note as _debug_note
from vlan_tool.provisioning.discovery import (
    discover_destination_mac_from_l3_arp as _discover_destination_mac_from_l3_arp,
    discover_l3_trace_mac as _discover_l3_trace_mac,
    discover_target_mac as _discover_target_mac,
    is_sensitive_olt_terminal_interface as _is_sensitive_olt_terminal_interface,
    pick_downlink_entry as _pick_downlink_entry,
    pick_uplink_entry as _pick_uplink_entry,
    select_vlan_for_plan as _select_vlan_for_plan,
    select_vlan_ranges as _select_vlan_ranges,
)
from vlan_tool.provisioning.executor import (
    execute_actions_in_current_session as _execute_actions_in_current_session,
    save_running_config_if_needed as _save_running_config_if_needed,
)
from vlan_tool.provisioning.interfaces import (
    discover_interface_description as _discover_interface_description,
    lookup_interface_description as _lookup_interface_description,
)
from vlan_tool.provisioning.ltp import (
    process_ltp_destination_hop as _process_ltp_destination_hop,
    process_ltp_intermediate_hop as _process_ltp_intermediate_hop,
)
from vlan_tool.provisioning.neighbor import resolve_neighbor_from_description as _resolve_neighbor_from_description
from vlan_tool.provisioning.reports import (
    HopReport as _HopReport,
    render_live_path_plan as _render_live_path_plan,
)
from vlan_tool.provisioning.vlan_state import (
    collect_vlan_snapshot as _collect_vlan_snapshot,
    snapshot_interface_tagged as _snapshot_interface_tagged,
    snapshot_vlan_exists as _snapshot_vlan_exists,
)
from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver


def execute_live_path_plan(
    config,
    request: ProvisioningRequest,
    *,
    apply_changes: bool,
    confirm_steps: bool,
    debug: bool,
) -> list[str]:
    resolver = SwitchResolver(config)
    destination_switch = resolver.resolve(request.destination_switch)
    destination_driver = get_driver(destination_switch.vendor)
    _debug_note(
        debug,
        f"Starting {'deploy' if apply_changes else 'plan'} for destination "
        f"{destination_switch.name} ({destination_switch.host}) "
        f"{f'port {request.destination_port}' if request.destination_port else '(L3-ARP MAC mode)'}",
    )

    if request.l3_switch:
        l3_switch = resolver.resolve(request.l3_switch)
        l3_source = f"user override ({request.l3_switch})"
        auto_l3_switch = None
        auto_l3_reason = None
    else:
        auto_l3_switch, auto_l3_reason = resolver.resolve_matched_l3(destination_switch)
        if not auto_l3_switch:
            raise LookupError(
                "Unable to auto-match L3 from destination switch. "
                "Provide --l3 explicitly for this topology."
            )
        l3_switch = auto_l3_switch
        l3_source = f"auto ({auto_l3_reason})"
    _debug_note(debug, f"Using L3 switch {l3_switch.name} ({l3_switch.host}) [{l3_source}]")

    l3_driver = get_driver(l3_switch.vendor)
    hop_reports: list[_HopReport] = []
    trace_stopped_at_sensitive = False
    chosen_vlan: int | None = None
    chosen_vlan_reason = ""
    l3_trace_mac: str | None = None
    target_mac: str | None = request.target_mac
    if request.target_mac:
        target_mac_source = "provided MAC"
    elif request.destination_port:
        target_mac_source = f"port {request.destination_port}"
    else:
        target_mac_source = "L3 ARP"
    executed_commands = 0

    with open_switch_session(
        config,
        l3_switch,
        confirm_connect=confirm_steps,
        confirm_commands=confirm_steps,
        debug=debug,
    ) as session:
        _debug_note(debug, f"Collecting L3 state on {l3_switch.name} ({l3_switch.host})")
        l3_driver.prepare_session(session)
        ranges = _select_vlan_ranges(config, l3_switch)
        chosen_vlan, chosen_vlan_reason = _select_vlan_for_plan(
            session=session,
            driver=l3_driver,
            vlan_ranges=ranges,
            requested_vlan=request.requested_vlan,
        )
        if not l3_trace_mac:
            l3_trace_mac = _discover_l3_trace_mac(
                session=session,
                driver=l3_driver,
                switch=l3_switch,
            )
        if not l3_trace_mac:
            raise RuntimeError(
                "Unable to discover L3 trace MAC on VLAN 111. "
                "Cannot determine uplink direction for hop-by-hop tracing."
            )

        if not target_mac:
            target_mac = _discover_destination_mac_from_l3_arp(
                session=session,
                driver=l3_driver,
                destination_switch=destination_switch,
            )
            if target_mac:
                target_mac_source = f"L3 ARP for {destination_switch.host}"
                _debug_note(
                    debug,
                    f"Resolved destination MAC from L3 ARP: {destination_switch.host} -> {target_mac}",
                )
            elif not is_destination:
                _debug_note(
                    debug,
                    f"L3 ARP did not return a usable MAC for {destination_switch.host}; trying destination self-MAC.",
                )
                target_mac, fallback_source = _discover_target_mac(
                    config,
                    request,
                    confirm_steps=confirm_steps,
                    debug=debug,
                )
                if target_mac:
                    target_mac_source = fallback_source

        if not target_mac:
            raise RuntimeError(
                "Unable to auto-discover destination MAC from L3 ARP or destination self-MAC. "
                "Provide a destination port or verify ARP/self-MAC visibility."
            )

        l3_target_entries = l3_driver.lookup_mac(session, target_mac)
        l3_downlink = _pick_downlink_entry(l3_target_entries)
        if not l3_downlink:
            raise RuntimeError(
                f"L3 {l3_switch.name} did not find destination MAC {target_mac} in MAC table."
            )

        l3_statuses = (
            l3_driver.get_interface_statuses(session) if l3_driver.capabilities.interface_inventory else {}
        )
        l3_description = _lookup_interface_description(
            statuses=l3_statuses,
            driver=l3_driver,
            interface=l3_downlink.interface,
        )
        if not l3_description:
            l3_description = _discover_interface_description(
                session=session,
                driver=l3_driver,
                interface=l3_downlink.interface,
            )
        l3_neighbor = _resolve_neighbor_from_description(
            resolver,
            l3_description,
            source_switch=l3_switch,
            debug=debug,
        )

        l3_snapshot = ""
        l3_exists = False
        if not apply_changes:
            l3_snapshot = _collect_vlan_snapshot(session=session, driver=l3_driver, vlan_id=chosen_vlan)
            l3_exists = _snapshot_vlan_exists(driver=l3_driver, vlan_id=chosen_vlan, snapshot=l3_snapshot)

        l3_hop = _HopReport(
            switch=l3_switch,
            role="l3",
            downlink_interface=l3_downlink.interface,
            neighbor_description=l3_description,
            neighbor_switch=l3_neighbor,
            vlan_exists=l3_exists,
            session_log=str(session.session_log),
        )

        create_l3_action: str | None = None
        if apply_changes:
            create_l3_action = _build_vlan_create_action(
                l3_driver.vendor_key,
                chosen_vlan,
            )
        elif request.requested_vlan is not None and not l3_exists:
            create_l3_action = _build_vlan_create_action(
                l3_driver.vendor_key,
                chosen_vlan,
            )
        elif request.requested_vlan is None and chosen_vlan_reason == "non-existent":
            create_l3_action = _build_vlan_create_action(
                l3_driver.vendor_key,
                chosen_vlan,
            )
        if create_l3_action:
            l3_hop.actions.append(create_l3_action)
            if apply_changes:
                _debug_note(debug, f"Creating VLAN {chosen_vlan} on L3 before trunk-tag checks.")
                executed_commands += _execute_actions_in_current_session(
                    session=session,
                    switch=l3_switch,
                    actions=[create_l3_action],
                )
                l3_hop.applied_actions.append(create_l3_action)

        if apply_changes:
            l3_snapshot = _collect_vlan_snapshot(
                session=session,
                driver=l3_driver,
                vlan_id=chosen_vlan,
            )
            l3_exists = _snapshot_vlan_exists(driver=l3_driver, vlan_id=chosen_vlan, snapshot=l3_snapshot)
        l3_hop.vlan_exists = l3_exists

        l3_tagged_down = _snapshot_interface_tagged(
            driver=l3_driver,
            vlan_id=chosen_vlan,
            interface=l3_downlink.interface,
            snapshot=l3_snapshot,
        )
        l3_hop.downlink_tagged = l3_tagged_down
        if not l3_tagged_down:
            l3_hop.actions.append(
                _build_vlan_tag_action(
                    vendor_key=l3_driver.vendor_key,
                    interface=l3_downlink.interface,
                    vlan_id=chosen_vlan,
                )
            )

        pending_l3_actions = [item for item in l3_hop.actions if item not in l3_hop.applied_actions]
        if apply_changes and pending_l3_actions:
            _debug_note(debug, f"Applying {len(pending_l3_actions)} action(s) on L3 {l3_switch.name}")
            executed_commands += _execute_actions_in_current_session(
                session=session,
                switch=l3_switch,
                actions=pending_l3_actions,
            )
            l3_hop.applied_actions.extend(pending_l3_actions)
        if not l3_neighbor:
            raise RuntimeError(
                f"Unable to resolve next-hop switch from L3 interface description '{l3_description or '-'}'."
            )
        hop_reports.append(l3_hop)

    visited_hosts = {l3_switch.host}
    current_switch = hop_reports[-1].neighbor_switch
    hop_limit = 24
    hop_count = 1
    while current_switch:
        if current_switch.host in visited_hosts:
            raise RuntimeError(
                f"Loop detected while tracing path. Switch {current_switch.name} ({current_switch.host}) was visited twice."
            )
        if hop_count > hop_limit:
            raise RuntimeError(f"Hop limit exceeded ({hop_limit}) while tracing VLAN path.")
        visited_hosts.add(current_switch.host)
        hop_count += 1

        current_driver = get_driver(current_switch.vendor)
        with open_switch_session(
            config,
            current_switch,
            confirm_connect=confirm_steps,
            confirm_commands=confirm_steps,
            debug=debug,
        ) as session:
            _debug_note(debug, f"Tracing hop on {current_switch.name} ({current_switch.host})")
            current_driver.prepare_session(session)
            current_statuses = (
                current_driver.get_interface_statuses(session)
                if current_driver.capabilities.interface_inventory
                else {}
            )
            is_destination = current_switch.host == destination_switch.host
            role = "destination" if is_destination else "intermediate"

            if current_driver.vendor_key == "ltp":
                if is_destination:
                    hop_report, ltp_command_count = _process_ltp_destination_hop(
                        session=session,
                        switch=current_switch,
                        driver=current_driver,
                        chosen_vlan=chosen_vlan,
                        l3_trace_mac=l3_trace_mac,
                        apply_changes=apply_changes,
                        debug=debug,
                    )
                    executed_commands += ltp_command_count
                    hop_reports.append(hop_report)
                    break

                hop_report, ltp_command_count = _process_ltp_intermediate_hop(
                    session=session,
                    resolver=resolver,
                    switch=current_switch,
                    driver=current_driver,
                    chosen_vlan=chosen_vlan,
                    target_mac=target_mac,
                    l3_trace_mac=l3_trace_mac,
                    apply_changes=apply_changes,
                    debug=debug,
                )
                executed_commands += ltp_command_count
                hop_reports.append(hop_report)
                if not hop_report.neighbor_switch:
                    raise RuntimeError(
                        f"Stopping on LTP {current_switch.name} ({current_switch.host}): "
                        "unable to determine next hop automatically. Continue manually."
                    )
                current_switch = hop_report.neighbor_switch
                continue

            snapshot = ""
            vlan_exists = False
            if not apply_changes:
                snapshot = _collect_vlan_snapshot(session=session, driver=current_driver, vlan_id=chosen_vlan)
                vlan_exists = _snapshot_vlan_exists(driver=current_driver, vlan_id=chosen_vlan, snapshot=snapshot)

            downlink_interface = None
            downlink_description = None
            downlink_tagged = None
            neighbor_switch = None
            notes: list[str] = []
            actions: list[str] = []
            applied_actions: list[str] = []
            sensitive_stop = False

            if apply_changes or not vlan_exists:
                create_action = _build_vlan_create_action(
                    current_driver.vendor_key,
                    chosen_vlan,
                )
                if create_action:
                    actions.append(create_action)
                if apply_changes and create_action:
                    _debug_note(
                        debug,
                        f"Creating VLAN {chosen_vlan} on {current_switch.name} before trunk-tag checks.",
                    )
                    executed_commands += _execute_actions_in_current_session(
                        session=session,
                        switch=current_switch,
                        actions=[create_action],
                    )
                    applied_actions.append(create_action)

            if apply_changes:
                snapshot = _collect_vlan_snapshot(
                    session=session,
                    driver=current_driver,
                    vlan_id=chosen_vlan,
                )
                vlan_exists = _snapshot_vlan_exists(driver=current_driver, vlan_id=chosen_vlan, snapshot=snapshot)

            uplink_entries = current_driver.lookup_mac(session, l3_trace_mac)
            uplink_entry = _pick_uplink_entry(uplink_entries)
            uplink_interface = uplink_entry.interface if uplink_entry else None
            uplink_tagged = (
                _snapshot_interface_tagged(
                    driver=current_driver,
                    vlan_id=chosen_vlan,
                    interface=uplink_interface,
                    snapshot=snapshot,
                )
                if uplink_interface
                else None
            )

            if not uplink_interface:
                notes.append(
                    f"Unable to find uplink interface by L3 MAC {l3_trace_mac}."
                )
            elif uplink_tagged is False:
                actions.append(
                    _build_vlan_tag_action(
                        vendor_key=current_driver.vendor_key,
                        interface=uplink_interface,
                        vlan_id=chosen_vlan,
                    )
                )

            if is_destination and request.destination_port:
                target_entries = current_driver.lookup_mac(session, target_mac)
                destination_entry = _pick_downlink_entry(target_entries)
                if destination_entry:
                    if current_driver.normalize_interface(
                        destination_entry.interface
                    ) != current_driver.normalize_interface(request.destination_port):
                        notes.append(
                            f"Destination MAC currently appears on {destination_entry.interface}, "
                            f"not requested port {request.destination_port}."
                        )
                else:
                    notes.append("Destination MAC was not visible on destination switch during this trace.")
            elif not is_destination:
                downlink_entries = current_driver.lookup_mac(session, target_mac)
                downlink_entry = _pick_downlink_entry(downlink_entries)
                if not downlink_entry:
                    raise RuntimeError(
                        f"{current_switch.name} did not find destination MAC {target_mac} in MAC table."
                    )
                downlink_interface = downlink_entry.interface
                if _is_sensitive_olt_terminal_interface(
                    downlink_interface,
                    vendor_key=current_driver.vendor_key,
                ):
                    sensitive_stop = True
                    trace_stopped_at_sensitive = True
                    notes.append(
                        "Stopping trace at sensitive ONU terminal downlink "
                        f"{downlink_interface}. Continue manually with ONU-safe workflow."
                    )
                else:
                    downlink_tagged = _snapshot_interface_tagged(
                        driver=current_driver,
                        vlan_id=chosen_vlan,
                        interface=downlink_interface,
                        snapshot=snapshot,
                    )
                    if downlink_tagged is False:
                        actions.append(
                            _build_vlan_tag_action(
                                vendor_key=current_driver.vendor_key,
                                interface=downlink_interface,
                                vlan_id=chosen_vlan,
                            )
                        )
                    downlink_description = _lookup_interface_description(
                        statuses=current_statuses,
                        driver=current_driver,
                        interface=downlink_interface,
                    )
                    if not downlink_description:
                        downlink_description = _discover_interface_description(
                            session=session,
                            driver=current_driver,
                            interface=downlink_interface,
                        )
                    neighbor_switch = _resolve_neighbor_from_description(
                        resolver,
                        downlink_description,
                        source_switch=current_switch,
                        debug=debug,
                    )
                    if not neighbor_switch:
                        raise RuntimeError(
                            f"Unable to resolve next-hop from {current_switch.name} "
                            f"interface {downlink_interface} description '{downlink_description or '-'}'."
                        )

            hop_report = _HopReport(
                switch=current_switch,
                role=role,
                uplink_interface=uplink_interface,
                downlink_interface=downlink_interface,
                neighbor_description=downlink_description,
                neighbor_switch=neighbor_switch,
                vlan_exists=vlan_exists,
                uplink_tagged=uplink_tagged,
                downlink_tagged=downlink_tagged,
                session_log=str(session.session_log),
                notes=notes,
                actions=actions,
                applied_actions=applied_actions,
            )
            pending_hop_actions = [item for item in hop_report.actions if item not in hop_report.applied_actions]
            if apply_changes and pending_hop_actions:
                _debug_note(
                    debug,
                    f"Applying {len(pending_hop_actions)} action(s) on {current_switch.name} ({current_switch.host})",
                )
                executed_commands += _execute_actions_in_current_session(
                    session=session,
                    switch=current_switch,
                    actions=pending_hop_actions,
                )
                hop_report.applied_actions.extend(pending_hop_actions)
            if apply_changes and hop_report.applied_actions:
                executed_commands += _save_running_config_if_needed(
                    session=session,
                    switch=current_switch,
                    debug=debug,
                )
            hop_reports.append(hop_report)

            if sensitive_stop:
                break
            if is_destination:
                break
            current_switch = neighbor_switch

    lines = _render_live_path_plan(
        destination_switch=destination_switch,
        destination_driver=destination_driver.vendor_key,
        destination_port=request.destination_port,
        l3_switch=l3_switch,
        l3_driver=l3_driver.vendor_key,
        l3_source=l3_source,
        auto_l3_switch=auto_l3_switch if request.l3_switch is None else None,
        auto_l3_reason=auto_l3_reason if request.l3_switch is None else None,
        chosen_vlan=chosen_vlan,
        chosen_vlan_reason=chosen_vlan_reason,
        target_mac=target_mac or "",
        target_mac_source=target_mac_source,
        l3_trace_mac=l3_trace_mac,
        hop_reports=hop_reports,
        apply_requested=apply_changes,
        executed_commands=executed_commands,
    )
    if trace_stopped_at_sensitive:
        lines.append("")
        lines.append(
            "Trace stopped at sensitive ONU terminal downlink. "
            "Upstream VLAN/tag actions above are included; continue manually from the ONU port."
        )
    return lines
