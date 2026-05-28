from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import ipaddress
import re

from vlan_tool.config import load_config
from vlan_tool.models import MacTableEntry, ProvisioningRequest, SwitchRecord, VlanRange
from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver
from vlan_tool.vendors.bdcom import extract_bdcom_base_mac_from_version
from vlan_tool.vendors.snr_s5xxx import extract_snr_s5_vlan_mac_from_version

try:
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
        ReadTimeout,
    )
except ImportError:  # pragma: no cover - optional until dependencies are installed
    class _NetmikoPlaceholderException(Exception):
        pass

    NetmikoAuthenticationException = _NetmikoPlaceholderException
    NetmikoTimeoutException = _NetmikoPlaceholderException
    ReadTimeout = _NetmikoPlaceholderException


@dataclass(slots=True)
class _HopReport:
    switch: SwitchRecord
    role: str
    uplink_interface: str | None = None
    downlink_interface: str | None = None
    neighbor_description: str | None = None
    neighbor_switch: SwitchRecord | None = None
    vlan_exists: bool | None = None
    uplink_tagged: bool | None = None
    downlink_tagged: bool | None = None
    session_log: str | None = None
    notes: list[str] = None
    actions: list[str] = None
    applied_actions: list[str] = None

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []
        if self.actions is None:
            self.actions = []
        if self.applied_actions is None:
            self.applied_actions = []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Terminal tool for VLAN tunnel automation across mixed-vendor switches."
    )
    parser.add_argument(
        "--confirm-steps",
        action="store_true",
        help=(
            "Interactive safety mode: ask for confirmation before opening each switch session "
            "and before every command sent to the switch."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print live debug output for connections and commands while running.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve_parser = subparsers.add_parser("resolve", help="Resolve a switch name or IP.")
    resolve_parser.add_argument("query", help="Switch name, alias, or IP.")

    probe_parser = subparsers.add_parser(
        "probe",
        help="Open a Telnet session, run vendor probe commands, and save a full session log.",
    )
    probe_parser.add_argument("switch", help="Switch name, alias, or IP.")
    probe_parser.add_argument(
        "--l3",
        dest="l3_switch",
        help=(
            "Optional L3 override for special topologies. "
            "If omitted, the tool derives L3 as 10.7.X.Y -> 10.1.1.X."
        ),
    )
    probe_parser.add_argument(
        "--debug",
        dest="probe_debug",
        action="store_true",
        help="Print live debug output while probing.",
    )

    mac_parser = subparsers.add_parser(
        "trace-mac",
        help="Look up a MAC address on a switch when the vendor driver supports it.",
    )
    mac_parser.add_argument("switch", help="Switch name, alias, or IP.")
    mac_parser.add_argument("mac", help="MAC address to search for.")

    free_vlan_parser = subparsers.add_parser(
        "find-vlan",
        help="Find the first free VLAN on an L3 switch using vendor-specific rules.",
    )
    free_vlan_parser.add_argument("switch", help="L3 switch name, alias, or IP.")
    free_vlan_parser.add_argument(
        "--debug",
        dest="find_vlan_debug",
        action="store_true",
        help="Print live debug output while finding a VLAN.",
    )

    plan_parser = subparsers.add_parser(
        "plan",
        help="Trace VLAN path live (destination-first) and report required changes (dry-run).",
    )
    _add_plan_arguments(plan_parser)
    # Accept --confirm-steps after subcommand as well (same behavior as global flag).
    plan_parser.add_argument(
        "--confirm-steps",
        dest="plan_confirm_steps",
        action="store_true",
        help="Ask before connecting/commands during live tracing.",
    )
    plan_parser.add_argument(
        "--debug",
        dest="plan_debug",
        action="store_true",
        help="Print live debug output while tracing.",
    )

    deploy_parser = subparsers.add_parser(
        "deploy",
        help="Trace VLAN path live and apply required VLAN/tagging changes hop-by-hop.",
    )
    _add_plan_arguments(deploy_parser)
    deploy_parser.add_argument(
        "--confirm-steps",
        dest="deploy_confirm_steps",
        action="store_true",
        help="Ask before connecting/commands during deployment.",
    )
    deploy_parser.add_argument(
        "--debug",
        dest="deploy_debug",
        action="store_true",
        help="Print live debug output while deploying.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    try:
        args = parser.parse_args()

        config = load_config()

        if args.command == "resolve":
            return _run_resolve(config, args.query)
        if args.command == "probe":
            debug = args.debug or getattr(args, "probe_debug", False)
            return _run_probe(
                config,
                args.switch,
                args.l3_switch,
                confirm_steps=args.confirm_steps,
                debug=debug,
            )
        if args.command == "trace-mac":
            return _run_trace_mac(
                config,
                args.switch,
                args.mac,
                confirm_steps=args.confirm_steps,
            )
        if args.command == "find-vlan":
            debug = args.debug or getattr(args, "find_vlan_debug", False)
            return _run_find_free_vlan(
                config,
                args.switch,
                confirm_steps=args.confirm_steps,
                debug=debug,
            )
        if args.command == "plan":
            confirm_steps = args.confirm_steps or getattr(args, "plan_confirm_steps", False)
            debug = args.debug or getattr(args, "plan_debug", False)
            request = ProvisioningRequest(
                l3_switch=args.l3_switch,
                destination_switch=args.destination_switch,
                destination_port=args.destination_port,
                requested_vlan=args.vlan,
            )
            return _run_plan(config, request, confirm_steps=confirm_steps, debug=debug)
        if args.command == "deploy":
            confirm_steps = args.confirm_steps or getattr(args, "deploy_confirm_steps", False)
            debug = args.debug or getattr(args, "deploy_debug", False)
            request = ProvisioningRequest(
                l3_switch=args.l3_switch,
                destination_switch=args.destination_switch,
                destination_port=args.destination_port,
                requested_vlan=args.vlan,
            )
            return _run_deploy(config, request, confirm_steps=confirm_steps, debug=debug)

        parser.error(f"Unsupported command: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("Operation cancelled by user.")
        return 130
    except (NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout) as exc:
        print(
            "Error: Telnet command failed due to authentication/prompt timeout. "
            "Check credentials and review session log for prompt flow details."
        )
        print(f"Details: {exc}")
        return 1
    except (FileNotFoundError, LookupError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1


def _run_resolve(config, query: str) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(query)
    print(f"Resolved: {switch.name}")
    print(f"Host: {switch.host}")
    print(f"Vendor: {switch.vendor}")
    print(f"Device type: {switch.device_type or 'auto'}")
    print(f"Site: {switch.site or 'n/a'}")
    print(f"Role: {switch.role or 'n/a'}")
    matched_l3, l3_reason = resolver.resolve_matched_l3(switch)
    if matched_l3:
        print(f"Matched L3: {matched_l3.name} ({matched_l3.host})")
        print(f"L3 match rule: {l3_reason}")
    else:
        print("Matched L3: not found")
        print(f"L3 match rule: {l3_reason}")
    return 0


def _run_probe(
    config,
    switch_query: str,
    l3_override: str | None = None,
    *,
    confirm_steps: bool = False,
    debug: bool = False,
) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(switch_query)
    matched_l3, l3_reason = resolver.resolve_matched_l3(switch, override=l3_override)
    driver = get_driver(switch.vendor)

    with open_switch_session(
        config,
        switch,
        confirm_connect=confirm_steps,
        confirm_commands=confirm_steps,
        debug=debug,
    ) as session:
        driver.prepare_session(session)
        print(f"Connected to {switch.name} ({switch.host})")
        print(f"Driver: {driver.summary()}")
        if matched_l3:
            print(f"Matched L3: {matched_l3.name} ({matched_l3.host})")
            print(f"L3 match rule: {l3_reason}")
        else:
            print("Matched L3: not found")
            print(f"L3 match rule: {l3_reason}")
        print(f"Session log: {session.session_log}")
        for command in driver.probe_commands():
            print("")
            print(f"$ {command}")
            if driver.vendor_key in {"generic_telnet", "snr", "snr_s5xxx", "eltex_mes", "arista"}:
                output = session.run_timing(command)
                if _looks_like_login_output(output):
                    raise RuntimeError(
                        "Device is still requesting Username/Password during probe. "
                        "Credentials likely rejected or prompt flow is non-standard."
                    )
            else:
                try:
                    output = session.run_show(command)
                except ReadTimeout:
                    # Some telnet prompts are noisy; timing mode is a safe fallback for probe output.
                    output = session.run_timing(command)
            print(output.rstrip())

    return 0


def _run_trace_mac(config, switch_query: str, mac_address: str, *, confirm_steps: bool = False) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(switch_query)
    driver = get_driver(switch.vendor)

    if not driver.capabilities.mac_lookup:
        print(
            f"Vendor driver '{driver.vendor_key}' does not support MAC lookup yet. "
            "Add command samples for this platform first."
        )
        return 1

    with open_switch_session(
        config,
        switch,
        confirm_connect=confirm_steps,
        confirm_commands=confirm_steps,
    ) as session:
        driver.prepare_session(session)
        interface_statuses = {}
        if driver.capabilities.interface_inventory:
            interface_statuses = driver.get_interface_statuses(session)
        entries = driver.lookup_mac(session, mac_address)
        print(f"Session log: {session.session_log}")
        if not entries:
            print(f"No entries found for {mac_address} on {switch.name}.")
            return 1

        for entry in entries:
            vlan_text = entry.vlan_id if entry.vlan_id is not None else "n/a"
            line = f"VLAN {vlan_text} -> {entry.interface} ({entry.entry_type or 'unknown'})"
            details = interface_statuses.get(driver.normalize_interface(entry.interface))
            if details:
                extras: list[str] = []
                if details.mode == "access" and details.access_vlan is not None:
                    extras.append(f"access vlan {details.access_vlan}")
                elif details.mode:
                    extras.append(details.mode)
                if details.link_state:
                    extras.append(f"link {details.link_state}")
                if details.description:
                    extras.append(details.description)
                if extras:
                    line = f"{line} | {' | '.join(extras)}"
            print(line)
        return 0


def _run_plan(
    config,
    request: ProvisioningRequest,
    *,
    confirm_steps: bool = False,
    debug: bool = False,
) -> int:
    effective_request = request
    if not request.target_mac:
        discovered, discovery_source = _discover_target_mac(
            config,
            request,
            confirm_steps=confirm_steps,
            debug=debug,
        )
        if not discovered:
            raise RuntimeError(
                "Unable to auto-discover destination MAC. "
                "Provide a destination port or verify switch self-MAC visibility."
            )
        effective_request = replace(request, target_mac=discovered)
        print(f"Auto-discovered target MAC ({discovery_source}): {discovered}")

    for line in _execute_live_path_plan(
        config,
        effective_request,
        apply_changes=False,
        confirm_steps=confirm_steps,
        debug=debug,
    ):
        print(line)
    return 0


def _run_deploy(
    config,
    request: ProvisioningRequest,
    *,
    confirm_steps: bool = False,
    debug: bool = False,
) -> int:
    effective_request = request
    if not request.target_mac:
        discovered, discovery_source = _discover_target_mac(
            config,
            request,
            confirm_steps=confirm_steps,
            debug=debug,
        )
        if not discovered:
            raise RuntimeError(
                "Unable to auto-discover destination MAC. "
                "Provide a destination port or verify switch self-MAC visibility."
            )
        effective_request = replace(request, target_mac=discovered)
        print(f"Auto-discovered target MAC ({discovery_source}): {discovered}")

    for line in _execute_live_path_plan(
        config,
        effective_request,
        apply_changes=True,
        confirm_steps=confirm_steps,
        debug=debug,
    ):
        print(line)
    return 0


def _execute_live_path_plan(
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
        f"{f'port {request.destination_port}' if request.destination_port else '(switch-self-MAC mode)'}",
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

    if apply_changes and not confirm_steps:
        if not _confirm_yes_no_local(
            "[confirm] Deploy mode without --confirm-steps will execute commands immediately. Continue? [y/N]: "
        ):
            raise RuntimeError("Operation cancelled by user before deployment run.")

    l3_driver = get_driver(l3_switch.vendor)
    hop_reports: list[_HopReport] = []
    chosen_vlan: int | None = None
    chosen_vlan_reason = ""
    l3_trace_mac: str | None = None
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

        l3_target_entries = l3_driver.lookup_mac(session, request.target_mac or "")
        l3_downlink = _pick_downlink_entry(l3_target_entries)
        if not l3_downlink:
            raise RuntimeError(
                f"L3 {l3_switch.name} did not find destination MAC {request.target_mac} in MAC table."
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

            if current_driver.vendor_key == "ltp" and not is_destination:
                hop_report, ltp_command_count = _process_ltp_intermediate_hop(
                    session=session,
                    resolver=resolver,
                    switch=current_switch,
                    driver=current_driver,
                    chosen_vlan=chosen_vlan,
                    target_mac=request.target_mac or "",
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

            if apply_changes or not vlan_exists:
                create_action = _build_vlan_create_action(
                    current_driver.vendor_key,
                    chosen_vlan,
                )
                actions.append(create_action)
                if apply_changes:
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

            if is_destination:
                target_entries = current_driver.lookup_mac(session, request.target_mac or "")
                destination_entry = _pick_downlink_entry(target_entries)
                if destination_entry:
                    if request.destination_port:
                        if current_driver.normalize_interface(
                            destination_entry.interface
                        ) != current_driver.normalize_interface(request.destination_port):
                            notes.append(
                                f"Destination MAC currently appears on {destination_entry.interface}, "
                                f"not requested port {request.destination_port}."
                            )
                else:
                    notes.append("Destination MAC was not visible on destination switch during this trace.")
            else:
                downlink_entries = current_driver.lookup_mac(session, request.target_mac or "")
                downlink_entry = _pick_downlink_entry(downlink_entries)
                if not downlink_entry:
                    raise RuntimeError(
                        f"{current_switch.name} did not find destination MAC {request.target_mac} in MAC table."
                    )
                downlink_interface = downlink_entry.interface
                if _is_sensitive_olt_terminal_interface(downlink_interface):
                    raise RuntimeError(
                        "Aborting automatic deploy on sensitive ONU terminal interface "
                        f"{downlink_interface} at {current_switch.name} ({current_switch.host}). "
                        "This endpoint type requires dedicated ONU-safe workflow."
                    )
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
        target_mac=request.target_mac or "",
        l3_trace_mac=l3_trace_mac,
        hop_reports=hop_reports,
        apply_requested=apply_changes,
        executed_commands=executed_commands,
    )
    return lines


def _render_live_path_plan(
    *,
    destination_switch: SwitchRecord,
    destination_driver: str,
    destination_port: str | None,
    l3_switch: SwitchRecord,
    l3_driver: str,
    l3_source: str,
    auto_l3_switch: SwitchRecord | None,
    auto_l3_reason: str | None,
    chosen_vlan: int,
    chosen_vlan_reason: str,
    target_mac: str,
    l3_trace_mac: str,
    hop_reports: list[_HopReport],
    apply_requested: bool,
    executed_commands: int,
) -> list[str]:
    lines = [
        f"L3 switch: {l3_switch.name} ({l3_switch.host}) via {l3_driver}",
        f"L3 selection source: {l3_source}",
        f"Destination switch: {destination_switch.name} ({destination_switch.host}) via {destination_driver}",
        f"Destination MAC source: {f'port {destination_port}' if destination_port else 'switch self MAC'}",
        f"Destination MAC: {target_mac}",
        f"L3 trace MAC: {l3_trace_mac}",
        f"Selected VLAN: {chosen_vlan} ({chosen_vlan_reason})",
        f"Execution mode: {'deploy' if apply_requested else 'dry-run'}",
    ]
    if auto_l3_switch and auto_l3_reason:
        lines.append(
            f"Auto-matched L3 reference: {auto_l3_switch.name} ({auto_l3_switch.host}) [{auto_l3_reason}]"
        )

    missing_actions = 0
    for index, hop in enumerate(hop_reports, start=1):
        lines.append("")
        lines.append(
            f"Hop {index} [{hop.role}] {hop.switch.name} ({hop.switch.host})"
        )
        if hop.session_log:
            lines.append(f"Session log: {hop.session_log}")
        if hop.uplink_interface:
            lines.append(f"Uplink interface (by L3 MAC): {hop.uplink_interface}")
        if hop.downlink_interface:
            lines.append(f"Downlink interface (by destination MAC): {hop.downlink_interface}")
        if hop.neighbor_description:
            lines.append(f"Downlink description: {hop.neighbor_description}")
        if hop.neighbor_switch:
            lines.append(f"Resolved next switch: {hop.neighbor_switch.name} ({hop.neighbor_switch.host})")
        if hop.vlan_exists is not None:
            lines.append(f"VLAN exists: {'yes' if hop.vlan_exists else 'no'}")
        if hop.uplink_tagged is not None:
            lines.append(f"VLAN tagged on uplink: {'yes' if hop.uplink_tagged else 'no'}")
        if hop.downlink_tagged is not None:
            lines.append(f"VLAN tagged on downlink: {'yes' if hop.downlink_tagged else 'no'}")
        for note in hop.notes:
            lines.append(f"Note: {note}")
        if hop.actions:
            missing_actions += len(hop.actions)
            for action in hop.actions:
                if apply_requested and action in hop.applied_actions:
                    lines.append(f"Applied change: {action}")
                else:
                    lines.append(f"Needs change: {action}")

    lines.append("")
    lines.append(f"Trace completed with {len(hop_reports)} hops.")
    if apply_requested:
        if missing_actions:
            lines.append(f"Deployment actions planned: {missing_actions}")
            lines.append(f"Deploy completed: {executed_commands} commands executed inline.")
        else:
            lines.append("No VLAN/tagging changes detected for traced path.")
    elif missing_actions:
        lines.append(f"Pending config actions detected: {missing_actions}")
    else:
        lines.append("No VLAN/tagging changes detected for traced path.")
    return lines


def _execute_actions_in_current_session(*, session, switch: SwitchRecord, actions: list[str]) -> int:
    """
    Execute action bundles in the current switch session in a single config pass.
    This keeps the workflow hop-local and avoids repeated config-mode enter/exit churn.
    """
    if not actions:
        return 0

    commands, used_config = _flatten_actions_for_single_config_session(actions, switch.vendor)
    executed = 0
    if used_config:
        if not commands:
            return 0
        enter_command = commands[0]
        payload = commands[1:]
        executed += _enter_config_mode_with_retry(
            session=session,
            switch=switch,
            enter_command=enter_command,
        )
        for command in payload:
            output = session.run_timing(command)
            if _looks_like_command_failure(output) and not _is_benign_command_failure(
                command=command,
                output=output,
                vendor_key=switch.vendor,
            ):
                raise RuntimeError(
                    "Deployment failed on "
                    f"{switch.name} ({switch.host}) while running '{command}'. "
                    "Review session log for details."
                )
            executed += 1
    else:
        for command in commands:
            output = session.run_timing(command)
            if _looks_like_command_failure(output) and not _is_benign_command_failure(
                command=command,
                output=output,
                vendor_key=switch.vendor,
            ):
                raise RuntimeError(
                    "Deployment failed on "
                    f"{switch.name} ({switch.host}) while running '{command}'. "
                    "Review session log for details."
                )
            executed += 1

    # Some devices silently drop config context. Count only commands actually sent.
    if used_config and executed == 0:
        raise RuntimeError(
            f"Deployment on {switch.name} ({switch.host}) produced no executable commands."
        )
    return executed


def _enter_config_mode_with_retry(*, session, switch: SwitchRecord, enter_command: str) -> int:
    attempts = _build_config_entry_attempts(switch.vendor, enter_command)
    executed = 0
    for command in attempts:
        output = session.run_timing(command)
        executed += 1
        if _looks_like_command_failure(output):
            continue
        if _output_or_prompt_is_config_mode(session, output):
            return executed

    raise RuntimeError(
        "Deployment failed on "
        f"{switch.name} ({switch.host}): unable to enter configuration mode "
        f"using {', '.join(repr(item) for item in attempts)}. Review session log for details."
    )


def _build_config_entry_attempts(vendor_key: str, preferred: str) -> list[str]:
    preferred_text = preferred.strip()
    attempts: list[str] = [preferred_text]
    candidates = {
        "cisco_ios": ["conf t", "configure terminal"],
        "arista": ["conf t", "configure terminal"],
        "snr": ["config terminal", "configure terminal"],
        "snr_s5xxx": ["conf", "config", "configure terminal", "conf t", "config terminal"],
        "eltex_mes": ["configure terminal", "config terminal", "conf t"],
        "ltp": ["configure terminal", "config terminal", "conf t", "conf"],
        "bdcom": ["conf", "configure terminal", "config terminal", "conf t"],
    }.get(vendor_key, ["configure terminal", "conf t", "config terminal"])
    for candidate in candidates:
        if candidate.casefold() == preferred_text.casefold():
            continue
        attempts.append(candidate)
    return attempts


def _output_or_prompt_is_config_mode(session, output: str) -> bool:
    if _looks_like_config_prompt(output):
        return True
    try:
        prompt = session.connection.find_prompt()
    except Exception:
        return False
    return _looks_like_config_prompt(prompt)


def _looks_like_config_prompt(text: str) -> bool:
    if not text:
        return False
    return bool(
        re.search(
            r"(?:\(config(?:-[^)]+)?\)|_config(?:_[^#>\s]+)?)\s*[>#]\s*$",
            text.strip(),
            flags=re.IGNORECASE | re.MULTILINE,
        )
    )


def _flatten_actions_for_single_config_session(actions: list[str], vendor_key: str) -> tuple[list[str], bool]:
    payloads: list[str] = []
    enter_config: str | None = None
    for action in actions:
        commands = _split_action_commands(action)
        if not commands:
            continue
        payload, action_enter = _extract_action_payload(commands)
        if action_enter and enter_config is None:
            enter_config = action_enter
        payloads.extend(payload)

    if enter_config is None:
        return payloads, False

    # For most vendors, trailing "exit" before final "end" is redundant and noisy.
    if vendor_key != "bdcom":
        while payloads and payloads[-1].strip().casefold() == "exit":
            payloads.pop()

    result = [enter_config, *payloads]
    if vendor_key == "bdcom":
        # BDCOM does not support "end"; leave config hierarchy with "exit".
        result.append("exit")
    else:
        result.append("end")
    return result, True


def _extract_action_payload(commands: list[str]) -> tuple[list[str], str | None]:
    if not commands:
        return [], None

    payload = [item.strip() for item in commands if item.strip()]
    if not payload:
        return [], None

    enter_config: str | None = None
    if _is_config_enter_command(payload[0]):
        enter_config = payload.pop(0)

    while payload and payload[-1].casefold() == "end":
        payload.pop()

    # Keep submode exits, but trim one trailing config exit only when action already has double-exit.
    if (
        enter_config
        and len(payload) >= 2
        and payload[-1].casefold() == "exit"
        and payload[-2].casefold() == "exit"
    ):
        payload.pop()

    return payload, enter_config


def _is_config_enter_command(command: str) -> bool:
    text = command.strip().casefold()
    return text in {"conf", "conf t", "configure terminal", "config terminal"}


def _split_action_commands(action: str) -> list[str]:
    return [item.strip() for item in action.split(";") if item.strip()]


def _looks_like_command_failure(output: str) -> bool:
    text = output.casefold()
    failure_markers = (
        "invalid input",
        "unknown command",
        "unrecognized command",
        "incomplete command",
        "ambiguous command",
        "% invalid",
        "% incomplete",
        "% ambiguous",
        "error:",
    )
    return any(marker in text for marker in failure_markers)


def _is_benign_vlan_exists_output(command: str, output: str) -> bool:
    cmd = command.strip().casefold()
    if not cmd.startswith("vlan "):
        return False
    text = output.casefold()
    benign_markers = (
        "already exist",
        "already configured",
        "has been configured",
        "vlan exists",
        "already created",
    )
    return any(marker in text for marker in benign_markers)


def _is_benign_command_failure(*, command: str, output: str, vendor_key: str) -> bool:
    if _is_benign_vlan_exists_output(command, output):
        return True

    text = output.casefold()
    cmd = command.strip().casefold()
    if vendor_key == "eltex_mes" and cmd == "vlan database":
        return "unrecognized command" in text or "unknown command" in text

    return False


def _save_running_config_if_needed(*, session, switch: SwitchRecord, debug: bool) -> int:
    if switch.vendor not in {"eltex_mes", "snr", "snr_s5xxx", "bdcom"}:
        return 0

    _debug_note(debug, f"Saving running-config on {switch.name} ({switch.host})")
    executed = 0

    if switch.vendor == "bdcom":
        save_commands = ["wr all", "write all", "wr", "write"]
    else:
        save_commands = ["write", "wr"]

    output = ""
    success = False
    for command in save_commands:
        output = session.run_timing(command)
        executed += 1
        if _looks_like_command_failure(output):
            continue
        success = True
        break

    if not success:
        raise RuntimeError(
            "Deployment failed on "
            f"{switch.name} ({switch.host}) while running save command "
            f"({', '.join(repr(cmd) for cmd in save_commands)}). "
            "Review session log for details."
        )

    if _looks_like_write_confirmation_prompt(output):
        confirm_output = session.run_timing("y", confirm_label="confirm write")
        executed += 1
        if _looks_like_command_failure(confirm_output):
            raise RuntimeError(
                "Deployment failed on "
                f"{switch.name} ({switch.host}) while confirming save operation with 'y'. "
                "Review session log for details."
            )

    return executed


def _looks_like_write_confirmation_prompt(output: str) -> bool:
    if not output:
        return False
    text = output.casefold()
    return bool(
        re.search(
            r"(overwrite|confirm\s+to\s+overwrite|\[\s*y\s*/\s*n\s*\]|\(\s*y\s*/\s*n\s*\))",
            text,
        )
    )


def _confirm_yes_no_local(prompt: str) -> bool:
    answer = input(prompt).strip().casefold()
    return answer in {"y", "yes"}


def _debug_note(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[debug] {message}")


def _select_vlan_for_plan(*, session, driver, vlan_ranges: list[VlanRange], requested_vlan: int | None) -> tuple[int, str]:
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


def _discover_l3_trace_mac(*, session, driver, switch: SwitchRecord | None = None) -> str | None:
    if driver.vendor_key == "cisco_ios":
        if _looks_like_c9500_switch(switch):
            static_output = session.run_show("show mac address-table | i STATIC")
            if not _looks_like_invalid_command(static_output):
                c9500_trace_mac = _extract_c9500_static_vlan111_mac(static_output)
                if c9500_trace_mac:
                    return c9500_trace_mac
        output = session.run_show("show mac address-table | i Switch")
        if not output.strip():
            output = session.run_show("show mac address-table vlan 111")
        elif _looks_like_invalid_command(output):
            output = session.run_show("show mac address-table vlan 111")
    elif driver.vendor_key == "snr":
        output = session.run_timing("show mac-address-table | i CPU")
        if _looks_like_invalid_command(output):
            output = session.run_timing("show mac-address-table vlan 111")
        if _looks_like_invalid_command(output):
            output = session.run_timing("show mac-address-table")
    elif driver.vendor_key == "snr_s5xxx":
        output = session.run_timing("show mac address-table | i CPU")
        if _looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table vlan 111")
        if _looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
    elif driver.vendor_key == "eltex_mes":
        output = session.run_timing("show mac address-table vlan 111")
        if _looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
    elif driver.vendor_key == "arista":
        output = session.run_timing("show mac address-table vlan 111")
        if _looks_like_invalid_command(output):
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


def _looks_like_c9500_switch(switch: SwitchRecord | None) -> bool:
    if not switch:
        return False
    names = [switch.name, *(switch.aliases or [])]
    for candidate in names:
        if re.search(r"\bc9500\b", str(candidate or "").casefold()):
            return True
    return False


def _extract_c9500_static_vlan111_mac(output: str) -> str | None:
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


def _pick_downlink_entry(entries: list[MacTableEntry]) -> MacTableEntry | None:
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


def _pick_uplink_entry(entries: list[MacTableEntry]) -> MacTableEntry | None:
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


def _is_sensitive_olt_terminal_interface(interface: str | None) -> bool:
    if not interface:
        return False
    normalized = interface.strip().casefold().replace(" ", "")
    return bool(re.match(r"^(?:epon|gpon)\d+/\d+:\d+$", normalized))


def _process_ltp_intermediate_hop(
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
) -> tuple[_HopReport, int]:
    downlink_entries = driver.lookup_mac(session, target_mac)
    downlink_entry = _pick_downlink_entry(downlink_entries)
    if not downlink_entry:
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): "
            f"destination MAC {target_mac} was not found. Continue manually."
        )

    downlink_interface = downlink_entry.interface
    normalized_downlink = driver.normalize_interface(downlink_interface)
    if _is_ltp_sensitive_downlink_interface(normalized_downlink):
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): downlink {downlink_interface} "
            "is PON/ONT-facing and requires manual continuation."
        )
    if not _is_ltp_front_uplink_interface(normalized_downlink):
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): unsupported downlink interface "
            f"{downlink_interface}. Continue manually."
        )

    running_config = session.run_timing("show running-config")
    vlan_block = _extract_ltp_vlan_block(running_config=running_config, vlan_id=chosen_vlan)
    vlan_exists = vlan_block is not None
    tagged_interfaces = _extract_ltp_tagged_interfaces_from_vlan_block(
        vlan_block=vlan_block or [],
        driver=driver,
    )
    expected_interfaces = _expected_ltp_blanket_interfaces(switch=switch, driver=driver)
    blanket_tagged = expected_interfaces.issubset(tagged_interfaces)
    downlink_tagged = normalized_downlink in tagged_interfaces

    actions: list[str] = []
    applied_actions: list[str] = []
    executed_commands = 0
    blanket_action = _build_ltp_blanket_action(vlan_id=chosen_vlan, switch=switch)
    if not blanket_tagged:
        actions.append(blanket_action)

    if apply_changes and actions:
        _debug_note(
            debug,
            f"Applying LTP blanket VLAN policy on {switch.name} for VLAN {chosen_vlan}.",
        )
        executed_commands += _apply_ltp_blanket_vlan_policy(
            session=session,
            switch=switch,
            vlan_id=chosen_vlan,
            driver=driver,
        )
        applied_actions.extend(actions)
        running_config = session.run_timing("show running-config")
        vlan_block = _extract_ltp_vlan_block(running_config=running_config, vlan_id=chosen_vlan)
        vlan_exists = vlan_block is not None
        tagged_interfaces = _extract_ltp_tagged_interfaces_from_vlan_block(
            vlan_block=vlan_block or [],
            driver=driver,
        )
        downlink_tagged = normalized_downlink in tagged_interfaces

    downlink_description = _extract_ltp_interface_description(
        running_config=running_config,
        interface=downlink_interface,
        driver=driver,
    )
    if not downlink_description:
        raise RuntimeError(
            f"Stopping on LTP {switch.name} ({switch.host}): no description found for {downlink_interface} "
            "in show running-config. Continue manually."
        )

    neighbor_switch = _resolve_neighbor_from_description(
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
    uplink_entry = _pick_uplink_entry(uplink_entries)
    uplink_interface = uplink_entry.interface if uplink_entry else None
    notes: list[str] = []
    if not uplink_interface:
        notes.append(f"Unable to find uplink interface by L3 MAC {l3_trace_mac}.")

    return (
        _HopReport(
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


def _is_ltp_sensitive_downlink_interface(normalized_interface: str) -> bool:
    if normalized_interface.startswith("pon-port "):
        return True
    return ":" in normalized_interface


def _is_ltp_front_uplink_interface(normalized_interface: str) -> bool:
    return normalized_interface.startswith("front-port ") or normalized_interface.startswith("10g-front-port ")


def _ltp_front_pon_max_port(switch: SwitchRecord) -> int:
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


def _build_ltp_blanket_action(*, vlan_id: int, switch: SwitchRecord) -> str:
    max_port = _ltp_front_pon_max_port(switch)
    return (
        f"configure terminal ; vlan {vlan_id} ; "
        f"tagged pon-port 0 - {max_port} ; "
        f"tagged front-port 0 - {max_port} ; "
        "tagged 10G-front-port 0 - 1 ; "
        "exit ; commit ; exit"
    )


def _apply_ltp_blanket_vlan_policy(*, session, switch: SwitchRecord, vlan_id: int, driver) -> int:
    max_port = _ltp_front_pon_max_port(switch)
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
        if _looks_like_command_failure(output) and not _is_benign_command_failure(
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


def _extract_ltp_vlan_block(*, running_config: str, vlan_id: int) -> list[str] | None:
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


def _extract_ltp_tagged_interfaces_from_vlan_block(*, vlan_block: list[str], driver) -> set[str]:
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


def _expected_ltp_blanket_interfaces(*, switch: SwitchRecord, driver) -> set[str]:
    max_port = _ltp_front_pon_max_port(switch)
    expected: set[str] = set()
    for index in range(0, max_port + 1):
        expected.add(driver.normalize_interface(f"pon-port {index}"))
        expected.add(driver.normalize_interface(f"front-port {index}"))
    expected.add(driver.normalize_interface("10G-front-port 0"))
    expected.add(driver.normalize_interface("10G-front-port 1"))
    return expected


def _extract_ltp_interface_description(*, running_config: str, interface: str, driver) -> str | None:
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


def _lookup_interface_description(
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


def _discover_interface_description(*, session, driver, interface: str | None) -> str | None:
    if not interface:
        return None

    commands = _build_interface_description_commands(driver.vendor_key, interface)
    for command in commands:
        output = _run_vendor_show_command(session=session, vendor_key=driver.vendor_key, command=command)
        if not output or _looks_like_invalid_command(output):
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


def _build_interface_description_commands(vendor_key: str, interface: str) -> list[str]:
    raw = interface.strip()
    if vendor_key == "snr":
        normalized = normalize_snr_interface_local(interface)
        return [
            f"show run int eth {normalized}",
            f"show run int eth{normalized}",
            f"show run int {_to_snr_ethernet_name(interface)}",
        ]
    if vendor_key == "snr_s5xxx":
        compact = raw.lower().replace(" ", "")
        return [
            f"show running-config interface {compact}",
            f"show run interface {compact}",
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


def _run_vendor_show_command(*, session, vendor_key: str, command: str) -> str:
    if vendor_key in {"snr", "snr_s5xxx", "eltex_mes", "arista", "bdcom", "ltp"}:
        return session.run_timing(command)
    return session.run_show(command)


def _resolve_neighbor_from_description(
    resolver: SwitchResolver,
    description: str | None,
    *,
    source_switch: SwitchRecord | None = None,
    debug: bool = False,
) -> SwitchRecord | None:
    if not description:
        return None
    base = description.strip().strip("\"'`")
    if not base:
        return None

    candidates = _build_neighbor_resolution_candidates(base)
    best: tuple[int, str, SwitchRecord] | None = None
    for candidate in candidates:
        try:
            resolved = resolver.resolve(candidate)
        except LookupError:
            continue
        score = _score_neighbor_match(
            description=base,
            switch=resolved,
            source_switch=source_switch,
        )
        if score < 100:
            if debug:
                _debug_note(
                    debug,
                    "Rejected weak neighbor candidate "
                    f"'{candidate}' -> {resolved.name} ({resolved.host}) score={score}",
                )
            continue
        if best is None or score > best[0]:
            best = (score, candidate, resolved)

    if best and debug:
        _, candidate, resolved = best
        _debug_note(
            debug,
            "Resolved next hop from description "
            f"'{base}' via candidate '{candidate}' -> {resolved.name} ({resolved.host})",
        )
    return best[2] if best else None


def _build_neighbor_resolution_candidates(description: str) -> list[str]:
    candidates: list[str] = []

    def _add(value: str | None) -> None:
        if not value:
            return
        text = value.strip().strip("\"'`")
        if text and text not in candidates:
            candidates.append(text)

    _add(description)
    primary = re.split(r"[\s,;]+", description, maxsplit=1)[0]
    _add(primary)

    id_token = _extract_id_token(description)
    if id_token:
        _add(id_token)

    if primary and "." in primary:
        _, _, tail = primary.partition(".")
        _add(tail)

    return candidates


def _is_confident_neighbor_match(description: str, switch: SwitchRecord) -> bool:
    blob_parts = [switch.name, switch.host, *(switch.aliases or [])]
    blob = " ".join(part for part in blob_parts if part).casefold()
    probe = description.casefold()

    if probe and (probe == switch.host.casefold() or probe in blob):
        return True

    id_token = _extract_id_token(probe)
    if id_token:
        return id_token in blob

    tokens = _description_tokens_for_match(probe)
    if not tokens:
        return False
    matched = [token for token in tokens if token in blob]
    if len(matched) >= 2:
        return True
    if len(matched) == 1 and len(matched[0]) >= 8:
        return True
    return False


def _score_neighbor_match(
    *,
    description: str,
    switch: SwitchRecord,
    source_switch: SwitchRecord | None,
) -> int:
    if not _is_confident_neighbor_match(description, switch):
        return 0

    blob_parts = [switch.name, switch.host, *(switch.aliases or [])]
    blob = " ".join(part for part in blob_parts if part).casefold()
    probe = description.casefold()
    score = 100

    if probe == switch.host.casefold():
        score += 500
    elif probe in blob:
        score += 240

    id_token = _extract_id_token(probe)
    if id_token:
        if id_token in blob:
            score += 360
        else:
            return 0

    tokens = _description_tokens_for_match(probe)
    matched = [token for token in tokens if token in blob]
    score += 45 * len(matched)
    if matched:
        score += max(len(token) for token in matched)

    if source_switch:
        if _looks_like_map_mismatch(
            source_switch=source_switch,
            candidate_switch=switch,
            description=probe,
            has_id_token=bool(id_token),
        ):
            # Fail-safe bias: avoid silent jumps to unrelated map names.
            score -= 320
        if _in_same_switch_pool(source_switch.host, switch.host):
            score += 40

    return score


def _looks_like_map_mismatch(
    *,
    source_switch: SwitchRecord,
    candidate_switch: SwitchRecord,
    description: str,
    has_id_token: bool,
) -> bool:
    if has_id_token:
        return False

    source_tokens = _switch_identity_tokens(source_switch)
    candidate_tokens = _switch_identity_tokens(candidate_switch)
    if not source_tokens or not candidate_tokens:
        return False
    if source_tokens.intersection(candidate_tokens):
        return False

    description_tokens = set(_description_tokens_for_match(description))
    if description_tokens and description_tokens.intersection(candidate_tokens):
        return False

    # No source/candidate map-token overlap and description doesn't reinforce candidate:
    # likely stale/wrong description match from resolver search fuzziness.
    return True


def _switch_identity_tokens(switch: SwitchRecord) -> set[str]:
    text = " ".join(
        part for part in [switch.name, *(switch.aliases or [])] if isinstance(part, str) and part.strip()
    ).casefold()
    tokens: set[str] = set()
    for token in re.findall(r"[a-z0-9]+", text):
        if token in {"snr", "mes", "cisco", "switch", "olt", "gpon", "epon"}:
            continue
        if token.startswith("id") and token[2:].isdigit():
            continue
        if token.isdigit():
            continue
        if len(token) < 4:
            continue
        if re.match(r"^(?:c\d{3,5}[a-z0-9]*|s\d{3,5}[a-z0-9]*)$", token):
            continue
        tokens.add(token)
    return tokens


def _in_same_switch_pool(left_host: str, right_host: str) -> bool:
    left_pool = _extract_10_7_pool(left_host)
    right_pool = _extract_10_7_pool(right_host)
    if left_pool is None or right_pool is None:
        return True
    return left_pool == right_pool


def _extract_10_7_pool(host: str) -> int | None:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not isinstance(parsed, ipaddress.IPv4Address):
        return None
    octets = host.split(".")
    if len(octets) != 4:
        return None
    if octets[0] != "10" or octets[1] != "7":
        return None
    if not octets[2].isdigit():
        return None
    return int(octets[2])


def _extract_id_token(text: str) -> str | None:
    match = re.search(r"\bid\d{3,}\b", text.casefold())
    if not match:
        return None
    return match.group(0)


def _description_tokens_for_match(text: str) -> list[str]:
    ignored = {
        "snr",
        "mes",
        "switch",
        "uplink",
        "downlink",
        "trunk",
        "port",
        "ethernet",
        "gigabit",
        "tengigabit",
    }
    tokens: list[str] = []
    for token in re.findall(r"[a-z0-9]+", text.casefold()):
        if token in ignored:
            continue
        if token.startswith("id") and token[2:].isdigit():
            tokens.append(token)
            continue
        if token.isdigit():
            continue
        if len(token) < 4:
            continue
        tokens.append(token)
    return tokens


def _collect_vlan_snapshot(*, session, driver, vlan_id: int) -> str:
    if driver.vendor_key == "cisco_ios":
        return session.run_show(f"show vlan id {vlan_id}")
    if driver.vendor_key == "snr":
        return session.run_timing(f"show vlan id {vlan_id}")
    if driver.vendor_key == "snr_s5xxx":
        return session.run_timing(f"show vlan {vlan_id}")
    if driver.vendor_key == "eltex_mes":
        return session.run_timing(f"show vlan tag {vlan_id}")
    if driver.vendor_key == "bdcom":
        return session.run_timing(f"show vlan id {vlan_id}")
    if driver.vendor_key == "ltp":
        return session.run_timing("show running-config")
    if driver.vendor_key == "arista":
        return session.run_timing(f"show vlan id {vlan_id}")
    return session.run_timing(f"show vlan id {vlan_id}")


def _snapshot_vlan_exists(*, driver, vlan_id: int, snapshot: str) -> bool:
    text = snapshot.casefold()
    if driver.vendor_key == "cisco_ios":
        missing_markers = (
            "not found in current vlan database",
            "vlan id not found",
            "invalid input",
            "incomplete command",
        )
        if any(marker in text for marker in missing_markers):
            return False
    if driver.vendor_key == "snr":
        if "invalid" in text and "input" in text:
            return False
    if driver.vendor_key == "snr_s5xxx":
        missing_markers = (
            "not found in current vlan database",
            "vlan id not found",
            "invalid input",
            "incomplete command",
        )
        if any(marker in text for marker in missing_markers):
            return False
        if re.search(rf"^\s*\S+\s+{vlan_id}\s+\S+", snapshot, flags=re.IGNORECASE | re.MULTILINE):
            return True
    if driver.vendor_key == "eltex_mes":
        if "invalid" in text and "input" in text:
            return False
    if driver.vendor_key == "bdcom":
        if "invalid" in text and "input" in text:
            return False
        if re.search(rf"vlan\s+id\s*:\s*{vlan_id}\b", text, flags=re.IGNORECASE):
            return True
    if driver.vendor_key == "ltp":
        return _extract_ltp_vlan_block(running_config=snapshot, vlan_id=vlan_id) is not None
    return bool(re.search(rf"^\s*{vlan_id}\s+", snapshot, flags=re.IGNORECASE | re.MULTILINE))


def _snapshot_interface_tagged(*, driver, vlan_id: int, interface: str | None, snapshot: str) -> bool | None:
    if not interface:
        return None
    if not _snapshot_vlan_exists(driver=driver, vlan_id=vlan_id, snapshot=snapshot):
        return False

    wanted = driver.normalize_interface(interface)
    if driver.vendor_key == "snr_s5xxx":
        for match in re.finditer(
            r"(?P<intf>[A-Za-z]+[0-9]+(?:/[0-9]+)*)\((?P<mode>[TtUu])\)",
            snapshot,
        ):
            if driver.normalize_interface(match.group("intf")) != wanted:
                continue
            return match.group("mode").casefold() == "t"

    if driver.vendor_key == "snr":
        full = _to_snr_ethernet_name(interface)
        return bool(re.search(rf"{re.escape(full)}\s*\(T\)", snapshot, flags=re.IGNORECASE))

    if driver.vendor_key == "eltex_mes":
        # Parse interfaces from the full VLAN snapshot.
        # Splitting on "UnTagged Ports" cuts off the table data itself because
        # that phrase appears in the header line.
        tagged_section = snapshot
        tokens = re.findall(
            r"(?:gi|te|fa)\d+/\d+/\d+(?:-\d+)?|po\d+(?:-\d+)?",
            tagged_section,
            flags=re.IGNORECASE,
        )
        expanded: list[str] = []
        for token in tokens:
            expanded.extend(_expand_eltex_interface_token(token))
        return any(driver.normalize_interface(token) == wanted for token in expanded)

    if driver.vendor_key == "bdcom":
        for line in snapshot.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parts = re.split(r"\s+", stripped, maxsplit=1)
            if len(parts) < 2:
                continue
            interface_token = parts[0]
            if driver.normalize_interface(interface_token) != wanted:
                continue
            attributes = parts[1].casefold()
            return "tagged" in attributes
    if driver.vendor_key == "ltp":
        vlan_block = _extract_ltp_vlan_block(running_config=snapshot, vlan_id=vlan_id)
        if vlan_block is None:
            return False
        tagged = _extract_ltp_tagged_interfaces_from_vlan_block(vlan_block=vlan_block, driver=driver)
        return wanted in tagged

    tokens = re.findall(r"(?:[A-Za-z]+[0-9]+(?:/[0-9]+)*)", snapshot)
    return any(driver.normalize_interface(token) == wanted for token in tokens)


def _expand_eltex_interface_token(token: str) -> list[str]:
    stripped = token.strip()
    range_match = re.match(
        r"^(?P<prefix>[A-Za-z]+)(?P<a>\d+)/(?P<b>\d+)/(?P<start>\d+)-(?P<end>\d+)$",
        stripped,
    )
    if range_match:
        start = int(range_match.group("start"))
        end = int(range_match.group("end"))
        if end >= start and end - start <= 96:
            base = f"{range_match.group('prefix')}{range_match.group('a')}/{range_match.group('b')}/"
            return [f"{base}{port}" for port in range(start, end + 1)]

    po_range_match = re.match(r"^(?P<prefix>po)(?P<start>\d+)-(?P<end>\d+)$", stripped, flags=re.IGNORECASE)
    if po_range_match:
        start = int(po_range_match.group("start"))
        end = int(po_range_match.group("end"))
        if end >= start and end - start <= 256:
            prefix = po_range_match.group("prefix")
            return [f"{prefix}{index}" for index in range(start, end + 1)]
    return [stripped]


def _build_vlan_create_action(
    vendor_key: str,
    vlan_id: int,
) -> str:
    if vendor_key == "arista":
        return f"conf t ; vlan {vlan_id} ; exit"
    if vendor_key == "cisco_ios":
        return f"conf t ; vlan {vlan_id} ; exit"
    if vendor_key == "snr":
        return f"config terminal ; vlan {vlan_id} ; exit"
    if vendor_key == "snr_s5xxx":
        return f"conf ; vlan {vlan_id} ; exit"
    if vendor_key == "eltex_mes":
        return f"configure terminal ; vlan database ; vlan {vlan_id} ; exit ; exit"
    if vendor_key == "ltp":
        return f"configure terminal ; vlan {vlan_id} ; exit ; commit ; exit"
    if vendor_key == "bdcom":
        return f"conf ; vlan {vlan_id} ; exit"
    return f"create VLAN {vlan_id} (vendor-specific command required)"


def _build_vlan_tag_action(*, vendor_key: str, interface: str, vlan_id: int) -> str:
    if vendor_key == "arista":
        return (
            f"conf t ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "cisco_ios":
        return (
            f"conf t ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "snr":
        return (
            f"config terminal ; interface {_to_snr_config_interface(interface)} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "snr_s5xxx":
        return (
            f"conf ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "eltex_mes":
        return (
            f"configure terminal ; interface {interface} ; "
            f"switchport trunk allowed vlan add {vlan_id} ; exit"
        )
    if vendor_key == "ltp":
        return (
            f"configure terminal ; vlan {vlan_id} ; "
            f"tagged {interface} ; exit ; commit ; exit"
        )
    if vendor_key == "bdcom":
        return (
            f"conf ; interface {interface} ; "
            f"switchport trunk vlan-allowed add {vlan_id} ; exit"
        )
    return f"allow VLAN {vlan_id} on {interface} (vendor-specific command required)"


def _to_snr_ethernet_name(interface: str) -> str:
    normalized = interface.strip()
    lowered = normalized.casefold().replace(" ", "")
    if lowered.startswith("ethernet"):
        suffix = lowered[len("ethernet") :]
        return f"Ethernet{suffix}"
    if lowered.startswith("eth"):
        suffix = lowered[len("eth") :]
        return f"Ethernet{suffix}"
    if re.match(r"^\d+/\d+/\d+$", lowered):
        return f"Ethernet{lowered}"
    return normalized


def normalize_snr_interface_local(interface: str) -> str:
    raw = interface.strip().casefold().replace(" ", "")
    if raw.startswith("ethernet"):
        raw = raw[len("ethernet") :]
    elif raw.startswith("eth"):
        raw = raw[len("eth") :]
    return raw


def _to_snr_config_interface(interface: str) -> str:
    lowered = interface.strip().casefold().replace(" ", "")
    if lowered.startswith("ethernet"):
        suffix = lowered[len("ethernet") :]
        return f"eth{suffix}"
    if lowered.startswith("eth"):
        suffix = lowered[len("eth") :]
        return f"eth{suffix}"
    if re.match(r"^\d+/\d+/\d+$", lowered):
        return f"eth{lowered}"
    return interface.strip()


def _looks_like_invalid_command(output: str) -> bool:
    lowered = output.casefold()
    return "invalid input" in lowered or "unknown command" in lowered or "incomplete command" in lowered


def _run_find_free_vlan(
    config,
    switch_query: str,
    *,
    confirm_steps: bool = False,
    debug: bool = False,
) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(switch_query)
    driver = get_driver(switch.vendor)
    if not driver.capabilities.free_vlan_search:
        print(
            f"Vendor driver '{driver.vendor_key}' does not support free VLAN search yet."
        )
        return 1

    ranges = _select_vlan_ranges(config, switch)
    if not ranges:
        print("No VLAN ranges configured. Add 'vlan_ranges' in config.yaml.")
        return 1

    if not _looks_like_l3_ip(switch.host):
        print(
            f"Warning: {switch.host} does not match expected L3 pattern 10.1.1.X. Continuing anyway."
        )

    with open_switch_session(
        config,
        switch,
        confirm_connect=confirm_steps,
        confirm_commands=confirm_steps,
        debug=debug,
    ) as session:
        driver.prepare_session(session)
        result = driver.find_free_vlan(session, ranges)
        print(f"Session log: {session.session_log}")
        if result is None:
            print("No free VLAN found in configured ranges.")
            return 1
        print(f"Found free VLAN: {result.vlan_id}")
        print(f"Reason: {result.reason}")
        print(f"Details: {result.details}")
        return 0


def _add_plan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "destination_switch",
        help="Destination switch name or IP.",
    )
    parser.add_argument(
        "destination_port",
        nargs="?",
        default=None,
        help=(
            "Optional destination switch port for client-MAC discovery. "
            "If omitted, tool uses destination switch self-MAC."
        ),
    )
    parser.add_argument(
        "--l3",
        dest="l3_switch",
        help=(
            "Optional name/IP of L3 switch. "
            "If omitted, L3 is auto-matched from destination IP using 10.7.X.Y -> 10.1.1.X."
        ),
    )
    parser.add_argument(
        "--vlan",
        dest="vlan",
        type=int,
        help="Optional fixed VLAN ID (if omitted, tool auto-selects free VLAN).",
    )


def _discover_target_mac(
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
            selected = _select_preferred_mac_entry(entries)
            return selected.mac_address, f"port {request.destination_port}"

        discovered = _discover_switch_self_mac(
            session=session,
            driver=driver,
            switch=destination_switch,
        )
        print(f"Session log (destination self-MAC discovery): {session.session_log}")
        return discovered, "switch self MAC"


def _discover_switch_self_mac(*, session, driver, switch: SwitchRecord) -> str | None:
    if driver.vendor_key in {"cisco_ios", "arista"}:
        return _discover_l3_trace_mac(session=session, driver=driver, switch=switch)

    if driver.vendor_key == "snr":
        output = session.run_timing("show mac-address-table | i CPU")
        if not output.strip() or _looks_like_invalid_command(output):
            output = session.run_timing("show mac-address-table")
        return _extract_preferred_switch_mac(
            output,
            require_any_keywords=("cpu", "system"),
        )

    if driver.vendor_key == "snr_s5xxx":
        version_output = session.run_timing("show version")
        discovered_from_version = extract_snr_s5_vlan_mac_from_version(version_output)
        if discovered_from_version:
            return discovered_from_version

        output = session.run_timing("show mac address-table | i CPU")
        if not output.strip() or _looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        discovered = _extract_preferred_switch_mac(
            output,
            require_any_keywords=("cpu", "system", "static"),
        )
        if discovered:
            return discovered
        return _extract_preferred_switch_mac(
            output,
            require_any_keywords=(),
        )

    if driver.vendor_key == "eltex_mes":
        output = session.run_timing("show mac address-table | i self")
        if not output.strip() or _looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        return _extract_preferred_switch_mac(
            output,
            require_any_keywords=("self",),
        )

    if driver.vendor_key == "bdcom":
        version_output = session.run_timing("show version")
        discovered_from_version = extract_bdcom_base_mac_from_version(version_output)
        if discovered_from_version:
            return discovered_from_version

        output = session.run_timing("show mac address-table static")
        if not output.strip() or _looks_like_invalid_command(output):
            output = session.run_timing("show mac address-table")
        return _extract_preferred_switch_mac(
            output,
            require_any_keywords=("cpu", "static"),
        )

    return None


def _extract_preferred_switch_mac(
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
        if _looks_like_control_plane_mac(compact_mac):
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


def _looks_like_control_plane_mac(compact_mac: str) -> bool:
    if compact_mac in {"000000000000", "ffffffffffff"}:
        return True
    if compact_mac.startswith("00000000"):
        return True
    control_prefixes = (
        "01000ccc",
        "0180c2",
        "3333",
    )
    return any(compact_mac.startswith(prefix) for prefix in control_prefixes)


def _select_preferred_mac_entry(entries: list[MacTableEntry]) -> MacTableEntry:
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


def _select_vlan_ranges(config, switch: SwitchRecord) -> list[VlanRange]:
    if switch.site and switch.site in config.sites and config.sites[switch.site].vlan_ranges:
        return config.sites[switch.site].vlan_ranges
    return config.vlan_ranges


def _looks_like_l3_ip(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return str(address).startswith("10.1.1.")


def _looks_like_login_output(output: str) -> bool:
    if not output:
        return False
    return bool(re.search(r"\b(username|password|user access verification|login)\b", output.casefold()))
