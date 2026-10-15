"""Eltex LTP ONT checks for `check`. Isolated from LTP deploy/path (`switch` mode)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re

from vlan_tool.diagnostics.l3 import run_l3_stage
from vlan_tool.diagnostics.report import ONT_OFFLINE_VERDICT, ClientCheckReport, derive_verdict
from vlan_tool.diagnostics.vlan_policy import expected_vlans_for_port
from vlan_tool.models import MacTableEntry
from vlan_tool.provisioning.common import compact_mac, looks_like_control_plane_mac, looks_like_invalid_command
from vlan_tool.provisioning.discovery import select_preferred_mac_entry

_RSSI_WARN_DBM = -30.0
_FLAP_EVENT_WARN = 2

_ONT_ROW_RE = re.compile(
    r"^\s*\d+\s+"
    r"(?P<serial>\S+)\s+"
    r"(?P<ont_id>\d+)\s+"
    r"(?P<gpon>\d+)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<rssi>\S+)\s+"
    r"(?P<version>\S+)\s+"
    r"(?P<equip>\S+)\s+"
    r"(?P<desc>.*\S)?\s*$"
)
_INET_VLAN_RE = re.compile(r'cross-connect\s+"inet(?P<vlan>\d+)"', re.IGNORECASE)
_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_EVENT_BLOCK_RE = re.compile(
    r"Serial number:\s*(?P<serial>\S+).*?"
    r"LinkUp\s*:\s*(?P<link_up>\S+(?:\s+\S+)?).*?"
    r"LinkDown\s*:\s*(?P<link_down>\S+(?:\s+\S+)?).*?"
    r"Last state\s*:\s*(?P<state>\S+)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(slots=True)
class LtpOntRow:
    serial: str
    ont_id: int
    gpon_port: int
    status: str
    rssi_dbm: float | None
    version: str | None
    equipment_id: str | None
    description: str | None

    @property
    def ont_ref(self) -> str:
        return f"{self.gpon_port}/{self.ont_id}"


@dataclass(slots=True)
class LtpOntEvent:
    serial: str
    link_up: str
    link_down: str
    last_state: str


def ont_cli_id(port: str) -> str:
    text = port.strip()
    lowered = text.casefold()
    if lowered.startswith("interface ont "):
        return text[len("interface ont ") :].strip()
    if lowered.startswith("ont "):
        return text[4:].strip()
    return text


def parse_ont_configured(output: str) -> LtpOntRow | None:
    if looks_like_invalid_command(output):
        return None
    for line in output.splitlines():
        match = _ONT_ROW_RE.match(line.rstrip())
        if not match:
            continue
        rssi_raw = match.group("rssi")
        if rssi_raw.casefold() in {"n/a", "na", "-"}:
            rssi: float | None = None
        else:
            try:
                rssi = float(rssi_raw)
            except ValueError:
                rssi = None
        desc = (match.group("desc") or "").strip() or None
        version = match.group("version")
        equip = match.group("equip")
        return LtpOntRow(
            serial=match.group("serial"),
            ont_id=int(match.group("ont_id")),
            gpon_port=int(match.group("gpon")),
            status=match.group("status"),
            rssi_dbm=rssi,
            version=None if version.casefold() in {"n/a", "na"} else version,
            equipment_id=None if equip.casefold() in {"n/a", "na"} else equip,
            description=desc,
        )
    return None


def parse_ont_inet_vlan(output: str) -> int | None:
    match = _INET_VLAN_RE.search(output)
    if not match:
        return None
    return int(match.group("vlan"))


def parse_ont_macs(output: str, *, ont_ref: str) -> list[MacTableEntry]:
    if looks_like_invalid_command(output):
        return []
    if "ont not found" in output.casefold():
        return []
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        mac_match = _MAC_RE.search(line)
        if not mac_match:
            continue
        if "serial" in line.casefold():
            continue
        vlan_id: int | None = None
        ints = re.findall(r"\b(\d+)\b", line[: mac_match.start()])
        if ints:
            vlan_id = int(ints[-1])
        entries.append(
            MacTableEntry(
                vlan_id=vlan_id,
                mac_address=mac_match.group(1),
                interface=f"ont {ont_ref}",
                entry_type=None,
                raw_line=line,
            )
        )
    return entries


def parse_ont_events(output: str) -> list[LtpOntEvent]:
    events: list[LtpOntEvent] = []
    for match in _EVENT_BLOCK_RE.finditer(output):
        events.append(
            LtpOntEvent(
                serial=match.group("serial"),
                link_up=match.group("link_up").strip(),
                link_down=match.group("link_down").strip(),
                last_state=match.group("state").strip(),
            )
        )
    return events


def summarize_ont_events(events: list[LtpOntEvent]) -> tuple[str, str]:
    if not events:
        return "SKIP", "ONT events: no LinkUp/LinkDown records"
    latest = events[-1]
    down_count = sum(1 for event in events if event.link_down and event.link_down != "------")
    state = latest.last_state.casefold()
    detail = (
        f"last state {latest.last_state}; LinkUp {latest.link_up}; LinkDown {latest.link_down}"
    )
    if state not in {"working", "ok"}:
        return "FAIL", f"ONT events: {detail}"
    if len(events) >= _FLAP_EVENT_WARN and down_count >= 1:
        return "WARN", f"ONT events: {down_count} LinkDown records; {detail}"
    return "PASS", f"ONT events: {detail}"


def run_ltp_ont_check(
    *,
    config,
    session,
    resolver,
    access_switch,
    report: ClientCheckReport,
    port: str,
    client_ip: str | None,
    l3_override: str | None,
    vlan_alt: int,
    debug: bool,
    start_step: Callable[[str], None],
) -> ClientCheckReport:
    """GPON ONT path: stay in OLT exec (do not enter `switch`)."""
    ont_query = ont_cli_id(port)
    start_step("ONT status")
    configured = session.run_timing(f"show interface ont {ont_query} configured")
    ont = parse_ont_configured(configured)
    if not ont:
        report.add("FAIL", f"ONT {ont_query}: not found in configured list")
        report.verdict = "ONT not found on this LTP"
        return report

    report.description = ont.description
    ont_ref = ont.ont_ref
    status = ont.status.casefold()
    if status in {"ok", "online", "working"}:
        extra = f", {ont.equipment_id}" if ont.equipment_id else ""
        report.add("PASS", f"ONT {ont_ref}: {ont.status}, serial {ont.serial}{extra}")
        ont_down = False
    elif status == "offline":
        report.add("FAIL", f"ONT {ont_ref}: OFFLINE, serial {ont.serial}")
        ont_down = True
    else:
        report.add("WARN", f"ONT {ont_ref}: status {ont.status}, serial {ont.serial}")
        ont_down = False

    start_step("ONT RSSI")
    if ont.rssi_dbm is None:
        report.add("SKIP", "ONT RSSI: n/a")
    elif ont.rssi_dbm < _RSSI_WARN_DBM:
        report.add("WARN", f"ONT RSSI: {ont.rssi_dbm:.2f} dBm (below {_RSSI_WARN_DBM:.0f} dBm)")
    else:
        report.add("PASS", f"ONT RSSI: {ont.rssi_dbm:.2f} dBm")

    start_step("VLAN policy")
    run_cfg = session.run_timing(f"show running-config interface ont {ont_ref}")
    inet_vlan = parse_ont_inet_vlan(run_cfg)
    expected_vlans, vlan_rule = expected_vlans_for_port(
        ont.description,
        access_vlan=inet_vlan,
        vlan_alt=vlan_alt,
    )
    extra = f", inet{inet_vlan}" if inet_vlan is not None else ""
    if expected_vlans is None and inet_vlan is not None:
        report.add("PASS", f"VLAN policy: service VLAN {inet_vlan} from inet{inet_vlan}")
    else:
        report.add("SKIP" if expected_vlans is None else "PASS", f"VLAN policy: {vlan_rule}{extra}")

    start_step("MAC on ONT")
    client_mac: str | None = None
    mac_output = session.run_timing(f"show mac interface ont {ont_ref}")
    entries = parse_ont_macs(mac_output, ont_ref=ont_ref)
    usable = [entry for entry in entries if not looks_like_control_plane_mac(compact_mac(entry.mac_address))]
    if not usable:
        report.add("FAIL", f"No client MAC learned on ONT {ont_ref}")
    else:
        selected = select_preferred_mac_entry(usable)
        client_mac = selected.mac_address
        vlan_ids = {entry.vlan_id for entry in usable if entry.vlan_id is not None}
        report.add(
            "PASS",
            f"MAC on ONT: {client_mac} (VLAN(s) {sorted(vlan_ids) or ['n/a']})",
        )

    start_step("ONT events")
    conn_output = session.run_timing(f"show interface ont {ont_ref} connections")
    event_status, event_summary = summarize_ont_events(parse_ont_events(conn_output))
    report.add(event_status, event_summary)

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
        mac_source="ONT",
    )
    report.verdict = ONT_OFFLINE_VERDICT if ont_down else derive_verdict(report)
    return report
