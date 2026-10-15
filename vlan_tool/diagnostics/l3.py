"""L3 visibility checks: MAC on L3 and ARP (by IP or discovered from MAC)."""

from __future__ import annotations

from collections.abc import Callable
import re

from vlan_tool.diagnostics.mgmt import probe_cpe_management
from vlan_tool.diagnostics.report import ClientCheckReport
from vlan_tool.models import SwitchRecord
from vlan_tool.provisioning.common import compact_mac, looks_like_invalid_command
from vlan_tool.provisioning.discovery import extract_arp_mac_for_ip, extract_ip_for_mac, pick_downlink_entry
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver


def run_l3_stage(
    *,
    config,
    report: ClientCheckReport,
    resolver,
    access_switch: SwitchRecord,
    client_mac: str | None,
    client_ip: str | None,
    l3_override: str | None,
    debug: bool,
    start_step: Callable[[str], None],
    mac_source: str = "port",
) -> None:
    """Shared tail of every client check: L3 target -> MAC table -> ARP -> CPE management."""
    start_step("L3 target")
    l3_switch, l3_reason = resolver.resolve_matched_l3(access_switch, override=l3_override)
    if not l3_switch:
        report.add("SKIP", f"L3 visibility: {l3_reason}")
        return
    if not client_mac:
        report.add("SKIP", f"L3 visibility: no {mac_source} MAC to trace")
        return
    report.add("PASS", f"L3 target: {l3_switch.name} ({l3_switch.host}) [{l3_reason}]")
    start_step("L3 MAC table")
    try:
        _, _, arp_status, arp_message, l3_log, resolved_ip = check_l3_client_visibility(
            config=config,
            l3_switch=l3_switch,
            mac_address=client_mac,
            client_ip=client_ip,
            debug=debug,
            on_mac_result=lambda status, message: report.add(status, f"L3 MAC table: {message}"),
            on_arp_start=lambda: start_step("L3 ARP"),
        )
    except RuntimeError as exc:
        report.add("FAIL", f"Connection: L3 switch {l3_switch.name} ({l3_switch.host}) — {exc}")
        return
    if l3_log:
        report.session_logs.append(l3_log)
    report.add(arp_status, f"L3 ARP: {arp_message}")
    if resolved_ip and arp_status in {"PASS", "WARN"}:
        start_step("CPE management")
        mgmt = probe_cpe_management(resolved_ip)
        report.add(mgmt.status, mgmt.summary)


def check_l3_client_visibility(
    *,
    config,
    l3_switch: SwitchRecord,
    mac_address: str,
    client_ip: str | None = None,
    debug: bool,
    on_mac_result: Callable[[str, str], None] | None = None,
    on_arp_start: Callable[[], None] | None = None,
) -> tuple[str, str, str, str, str | None, str | None]:
    """One L3 session: MAC + ARP. Returns mac_status, mac_msg, arp_status, arp_msg, log_path, client_ip."""
    def emit_mac(status: str, message: str) -> None:
        if on_mac_result:
            on_mac_result(status, message)

    def start_arp() -> None:
        if on_arp_start:
            on_arp_start()

    driver = get_driver(l3_switch.vendor)
    if not driver.capabilities.mac_lookup:
        mac_message = f"L3 vendor '{driver.vendor_key}' has no MAC lookup support"
        emit_mac("FAIL", mac_message)
        start_arp()
        return (
            "FAIL",
            mac_message,
            "SKIP",
            "ARP not checked",
            None,
            None,
        )

    with open_switch_session(config, l3_switch, debug=debug) as session:
        driver.prepare_session(session)
        log_path = str(session.session_log)

        entries = driver.lookup_mac(session, mac_address)
        if not entries:
            mac_message = f"MAC {mac_address} not found on L3 {l3_switch.name}"
            emit_mac("FAIL", mac_message)
            start_arp()
            return (
                "FAIL",
                mac_message,
                "SKIP",
                "ARP not checked (MAC missing on L3)",
                log_path,
                None,
            )
        entry = pick_downlink_entry(entries) or entries[0]
        mac_message = (
            f"MAC {mac_address} on L3 {entry.interface} (VLAN {entry.vlan_id or 'n/a'})"
        )
        emit_mac("PASS", mac_message)
        start_arp()

        resolved_ip = client_ip
        ip_source = "provided"
        if not resolved_ip:
            resolved_ip = _lookup_ip_from_arp_by_mac(
                session=session,
                driver=driver,
                mac_address=mac_address,
            )
            ip_source = "discovered from MAC"

        if not resolved_ip:
            return "PASS", mac_message, "FAIL", "No ARP entry for client MAC on L3", log_path, None

        arp_status, arp_message = _verify_arp_entry(
            session=session,
            driver=driver,
            client_ip=resolved_ip,
            expected_mac=mac_address,
            ip_source=ip_source,
        )
        return "PASS", mac_message, arp_status, arp_message, log_path, resolved_ip


def _lookup_ip_from_arp_by_mac(*, session, driver, mac_address: str) -> str | None:
    for command in _arp_by_mac_commands(driver.vendor_key, mac_address):
        output = session.run_show(command) if driver.vendor_key == "cisco_ios" else session.run_timing(command)
        if not output or looks_like_invalid_command(output):
            continue
        ip = extract_ip_for_mac(output=output, mac_address=mac_address)
        if ip:
            return ip
    return None


def _arp_by_mac_commands(vendor_key: str, mac_address: str) -> list[str]:
    compact = compact_mac(mac_address)
    if len(compact) != 12:
        return [f"show ip arp | include {mac_address}"]
    dashed = "-".join(compact[index : index + 2] for index in range(0, 12, 2))
    dotted = ".".join(compact[index : index + 4] for index in range(0, 12, 4))
    colon = ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    tail = compact[-6:]
    commands = [
        f"show ip arp | include {dashed}",
        f"show ip arp | include {dotted}",
        f"show ip arp | include {colon}",
        f"show ip arp | include {tail}",
        f"show arp | include {dashed}",
    ]
    if vendor_key == "cisco_ios":
        commands.insert(0, f"show ip arp {dotted}")
    return commands


def _verify_arp_entry(
    *,
    session,
    driver,
    client_ip: str,
    expected_mac: str,
    ip_source: str,
) -> tuple[str, str]:
    command = f"show ip arp {client_ip}"
    output = session.run_show(command) if driver.vendor_key == "cisco_ios" else session.run_timing(command)
    if looks_like_invalid_command(output):
        return "SKIP", "ARP lookup command not supported on L3"

    arp_mac = extract_arp_mac_for_ip(output=output, ip_address=client_ip)
    if not arp_mac:
        if "incomplete" in output.casefold():
            return "FAIL", f"ARP for {client_ip} ({ip_source}) is incomplete on L3"
        return "FAIL", f"No ARP entry for {client_ip} ({ip_source}) on L3"

    if compact_mac(arp_mac) != compact_mac(expected_mac):
        return (
            "WARN",
            f"ARP {client_ip} -> {arp_mac} ({ip_source}), port MAC was {expected_mac}",
        )
    return "PASS", f"ARP {client_ip} -> {arp_mac} ({ip_source})"
