"""Orchestrate live client check steps on an access switch and matched L3."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack

from vlan_tool import site
from vlan_tool.diagnostics.bdcom import run_bdcom_onu_check
from vlan_tool.diagnostics.fd160 import run_fd160_onu_check
from vlan_tool.diagnostics.l3 import run_l3_stage
from vlan_tool.diagnostics.ltp import run_ltp_ont_check
from vlan_tool.diagnostics.physical import check_physical_link
from vlan_tool.diagnostics.port import (
    collect_interface_detail,
    parse_error_counters,
    port_link_summary,
    resolve_port_context,
    scan_port_log_flap,
)
from vlan_tool.diagnostics.report import CheckLine, ClientCheckReport, derive_verdict
from vlan_tool.diagnostics.vlan_policy import expected_vlans_for_port
from vlan_tool.provisioning.common import compact_mac, looks_like_control_plane_mac
from vlan_tool.provisioning.discovery import select_preferred_mac_entry
from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver

# OLT platforms with their own ONT-oriented check flow (exec-mode shows only).
_ONT_CHECKS = {
    "bdcom_gpon": run_bdcom_onu_check,
    "fd160": run_fd160_onu_check,
    "ltp": run_ltp_ont_check,
}


def run_client_check(
    config,
    *,
    switch_query: str,
    port: str,
    client_ip: str | None = None,
    l3_override: str | None = None,
    vlan_alt: int | None = None,
    debug: bool = True,
    on_ready: Callable[[ClientCheckReport], None] | None = None,
    on_step: Callable[[str], None] | None = None,
    on_line: Callable[[CheckLine], None] | None = None,
) -> ClientCheckReport:
    if vlan_alt is None:
        vlan_alt = site.F_PORT_ALT_VLAN
    start_step = on_step or (lambda _label: None)
    start_step("Port link: resolving access switch")
    resolver = SwitchResolver(config)
    access_switch = resolver.resolve(switch_query)
    driver = get_driver(access_switch.vendor)
    report = ClientCheckReport(
        switch_name=access_switch.name,
        switch_host=access_switch.host,
        port=port,
        line_callback=on_line,
    )
    if on_ready:
        on_ready(report)

    start_step("Connection: access switch")
    try:
        stack = ExitStack()
        session = stack.enter_context(open_switch_session(config, access_switch, debug=debug))
    except RuntimeError as exc:
        report.add("FAIL", f"Connection: access switch {access_switch.name} ({access_switch.host}) — {exc}")
        report.verdict = "Access switch unreachable or not answering on Telnet"
        return report

    with stack:
        report.session_logs.append(str(session.session_log))
        ont_check = _ONT_CHECKS.get(driver.vendor_key)
        if ont_check:
            if driver.vendor_key == "bdcom_gpon":
                # BDCOM prepare_session is pager-off only (safe); FD160/LTP prepare enters deploy modes.
                driver.prepare_session(session)
            return ont_check(
                config=config,
                session=session,
                resolver=resolver,
                access_switch=access_switch,
                report=report,
                port=port,
                client_ip=client_ip,
                l3_override=l3_override,
                vlan_alt=vlan_alt,
                debug=debug,
                start_step=start_step,
            )
        driver.prepare_session(session)

        inventory_skip: str | None = None
        if not driver.capabilities.interface_inventory:
            inventory_skip = (
                f"Port status: vendor '{driver.vendor_key}' has no interface inventory parser"
            )
            statuses = {}
        else:
            statuses = driver.get_interface_statuses(session)

        details, description = resolve_port_context(
            session=session,
            driver=driver,
            interface=port,
            statuses=statuses,
        )
        report.description = description

        if inventory_skip:
            report.add("SKIP", inventory_skip)
            start_step("Port link: reading state")

        if details:
            admin = (details.admin_state or "").casefold()
            link = (details.link_state or "").casefold()
            if "down" in admin or "down" in link:
                report.add("FAIL", f"Port link: {port_link_summary(details)}")
            else:
                report.add("PASS", f"Port link: {port_link_summary(details)}")
        else:
            report.add("WARN", f"Port {port} not found in interface status output")

        start_step("Interface error counters")
        detail_output = collect_interface_detail(session=session, driver=driver, interface=port)
        counters = parse_error_counters(detail_output)
        if counters:
            nonzero = {key: value for key, value in counters.items() if value > 0}
            if nonzero:
                parts = ", ".join(f"{key}={value}" for key, value in sorted(nonzero.items()))
                report.add("WARN", f"Interface error counters: {parts}")
            else:
                report.add("PASS", "Interface error counters: all zero")
        else:
            report.add("SKIP", "Interface error counters: could not collect (vendor/command)")

        link_up = bool(
            details
            and "down" not in (details.admin_state or "").casefold()
            and "down" not in (details.link_state or "").casefold()
        )
        start_step("Physical layer")
        physical = check_physical_link(
            session=session,
            driver=driver,
            interface=port,
            link_up=link_up,
            raw_status_line=details.raw_line if details else "",
            interface_detail=detail_output,
        )
        report.add(physical.status, physical.summary)
        for detail in physical.details:
            report.add(physical.status, f"  {detail}")

        start_step("VLAN policy")
        expected_vlans, vlan_rule = expected_vlans_for_port(
            description,
            access_vlan=details.access_vlan if details else None,
            vlan_alt=vlan_alt,
        )
        report.add("SKIP" if expected_vlans is None else "PASS", f"VLAN policy: {vlan_rule}")

        start_step("MAC on port")
        client_mac: str | None = None
        if not driver.capabilities.mac_lookup_by_interface:
            report.add("SKIP", "MAC on port: vendor has no interface MAC lookup")
        else:
            entries = driver.lookup_interface_macs(session, port)
            usable = [entry for entry in entries if not looks_like_control_plane_mac(compact_mac(entry.mac_address))]
            if not usable:
                report.add("FAIL", f"No client MAC learned on port {port}")
            else:
                selected = select_preferred_mac_entry(usable)
                client_mac = selected.mac_address
                vlan_ids = {entry.vlan_id for entry in usable if entry.vlan_id is not None}
                if expected_vlans is None:
                    report.add(
                        "PASS",
                        f"MAC on port: {client_mac} (VLAN(s) {sorted(vlan_ids) or ['n/a']})",
                    )
                elif vlan_ids & expected_vlans:
                    matched = sorted(vlan_ids & expected_vlans)
                    report.add(
                        "PASS",
                        f"MAC on port: {client_mac} in expected VLAN(s) {matched}",
                    )
                else:
                    report.add(
                        "FAIL",
                        f"MAC on port: {client_mac} in VLAN(s) {sorted(vlan_ids) or ['n/a']}, "
                        f"expected {sorted(expected_vlans)}",
                    )

        start_step("Port logs")
        log_scan = scan_port_log_flap(
            session=session,
            driver=driver,
            interface=port,
            interface_detail=detail_output,
        )
        report.add(log_scan.status, log_scan.summary)
        for detail in log_scan.details:
            report.add(log_scan.status, f"  {detail}")

    run_l3_stage(
        config=config,
        report=report,
        resolver=resolver,
        access_switch=access_switch,
        client_mac=client_mac,
        client_ip=client_ip,
        l3_override=l3_override,
        debug=debug,
        start_step=start_step,
    )
    report.verdict = derive_verdict(report)
    return report
