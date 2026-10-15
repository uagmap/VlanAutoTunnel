"""BDCOM GP3600 GPON ONT checks for `check`. Isolated from BDCOM deploy (conf/save)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re

from vlan_tool.diagnostics.l3 import run_l3_stage
from vlan_tool.diagnostics.report import ONT_OFFLINE_VERDICT, ClientCheckReport, derive_verdict
from vlan_tool.diagnostics.vlan_policy import expected_vlans_for_port
from vlan_tool.provisioning.common import compact_mac, looks_like_control_plane_mac, looks_like_invalid_command
from vlan_tool.vendors.bdcom import _parse_bdcom_mac_lines, normalize_bdcom_interface

_RX_WARN_DBM = -30.0
_STABLE_ONLINE_SECONDS = 300

_ONU_COLON_RE = re.compile(
    r"^(?:gpon\s*)?(?P<slot>\d+)/(?P<pon>\d+):(?P<onu>\d+)$",
    re.IGNORECASE,
)
# Same shorthand as LTP/FD160: pon/ont → gpon0/<pon>:<ont>
_ONU_SLASH_RE = re.compile(
    r"^(?:gpon\s*)?(?:(?P<slot>\d+)/)?(?P<pon>\d+)/(?P<onu>\d+)$",
    re.IGNORECASE,
)
_FIELD_RE = {
    "serial": re.compile(r"^Serial number\s+(?P<value>\S+)", re.IGNORECASE | re.MULTILINE),
    "admin": re.compile(r"^Admin state\s+(?P<value>\S+)", re.IGNORECASE | re.MULTILINE),
    "oper": re.compile(r"^Operational state\s+(?P<value>\S+)", re.IGNORECASE | re.MULTILINE),
    "config": re.compile(r"^ONU Config\s+(?P<value>\S+)", re.IGNORECASE | re.MULTILINE),
    "description": re.compile(r"^ONU Description\s+(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "distance": re.compile(
        r"^Distance\s+(?P<value>\d+(?:\.\d+)?)\s*m",
        re.IGNORECASE | re.MULTILINE,
    ),
    "online": re.compile(
        r"^Online Duration\s+"
        r"(?:(?P<days>\d+)d\s*)?"
        r"(?:(?P<hours>\d+)h\s*)?"
        r"(?:(?P<minutes>\d+)m\s*)?"
        r"(?:(?P<seconds>\d+)s)?",
        re.IGNORECASE | re.MULTILINE,
    ),
}
_RX_POWER_RE = re.compile(
    r"gpon\s*\d+/\d+:\d+\s+(?P<value>-?\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
_HISTORY_RE = re.compile(
    r"^\s*\d+\s+"
    r"(?P<active>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\s+(?P<deactive>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<reason>.+?))?\s*$"
)


@dataclass(slots=True)
class BdcomOnuRef:
    slot: int
    pon: int
    onu_id: int

    @property
    def compact(self) -> str:
        return f"gpon{self.slot}/{self.pon}:{self.onu_id}"

    @property
    def cli(self) -> str:
        return f"gpon {self.slot}/{self.pon}:{self.onu_id}"


@dataclass(slots=True)
class BdcomOnuInfo:
    ref: BdcomOnuRef
    serial: str | None
    admin_state: str | None
    operational_state: str | None
    onu_config: str | None
    description: str | None
    distance_m: float | None
    online_seconds: int | None
    history: list[tuple[str, str | None, str | None]]


def onu_cli_ref(port: str) -> BdcomOnuRef:
    """Normalize ONT id. Accepts 2/52, 0/2/52, 0/2:52, gpon0/2:52 → gpon0/2:52."""
    text = port.strip()
    lowered = text.casefold().replace(" ", "")
    if lowered.startswith("interface"):
        text = text.split(None, 1)[-1]
    compact = text.strip().casefold().replace(" ", "")
    match = _ONU_COLON_RE.match(compact) or _ONU_SLASH_RE.match(compact)
    if not match:
        raise ValueError(
            f"BDCOM GPON ONT expects pon/ont (e.g. 2/52 → gpon0/2:52), got: {port}"
        )
    slot = match.groupdict().get("slot")
    return BdcomOnuRef(
        int(slot) if slot is not None else 0,
        int(match.group("pon")),
        int(match.group("onu")),
    )


def _field(output: str, name: str) -> str | None:
    match = _FIELD_RE[name].search(output)
    if not match:
        return None
    return match.group("value").strip()


def _online_seconds(output: str) -> int | None:
    match = _FIELD_RE["online"].search(output)
    if not match:
        return None
    days = int(match.group("days") or 0)
    hours = int(match.group("hours") or 0)
    minutes = int(match.group("minutes") or 0)
    seconds = int(match.group("seconds") or 0)
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def parse_onu_basic_info(output: str, *, ref: BdcomOnuRef) -> BdcomOnuInfo | None:
    if not output or looks_like_invalid_command(output):
        return None
    oper = _field(output, "oper")
    if not oper:
        return None
    desc = _field(output, "description")
    if desc in {"", "N/A"}:
        desc = None
    distance_raw = _field(output, "distance")
    history: list[tuple[str, str | None, str | None]] = []
    for line in output.splitlines():
        match = _HISTORY_RE.match(line.rstrip())
        if not match:
            continue
        reason = (match.group("reason") or "").strip() or None
        history.append((match.group("active"), match.group("deactive"), reason))
    return BdcomOnuInfo(
        ref=ref,
        serial=_field(output, "serial"),
        admin_state=_field(output, "admin"),
        operational_state=oper,
        onu_config=_field(output, "config"),
        description=desc,
        distance_m=float(distance_raw) if distance_raw else None,
        online_seconds=_online_seconds(output),
        history=history,
    )


def parse_onu_rx_dbm(output: str) -> float | None:
    if not output or looks_like_invalid_command(output):
        return None
    match = _RX_POWER_RE.search(output)
    if not match:
        return None
    try:
        return float(match.group("value"))
    except ValueError:
        return None


def summarize_onu_history(
    history: list[tuple[str, str | None, str | None]],
    *,
    online_seconds: int | None,
) -> tuple[str, str]:
    if not history:
        return "PASS", "ONU events: no active/deactive history"
    last_active, last_deactive, last_reason = history[-1]
    closed = [(a, d, r) for a, d, r in history if d]
    last_closed_reason = closed[-1][2] if closed else None
    if last_deactive is None:
        detail = f"online since {last_active}"
        if last_closed_reason:
            detail += f"; last down {last_closed_reason}"
    else:
        detail = f"last down {last_reason or '?'} at {last_deactive}"
    stable = online_seconds is not None and online_seconds >= _STABLE_ONLINE_SECONDS
    if stable:
        return "PASS", f"ONU events: {len(history)} record(s); stable per Online Duration; {detail}"
    bad_reasons = {"losi", "dying gasp", "dying-gasp", "los"}
    if last_closed_reason and last_closed_reason.casefold() in bad_reasons:
        return "WARN", f"ONU events: recent {last_closed_reason}; {detail}"
    if len(closed) >= 2:
        return "WARN", f"ONU events: {len(closed)} deactivations in history; {detail}"
    return "PASS", f"ONU events: {detail}"


def run_bdcom_onu_check(
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
    """GPON ONT path: exec show commands only; do not enter deploy conf/save."""
    try:
        ref = onu_cli_ref(port)
    except ValueError as exc:
        report.add("FAIL", f"ONT port: {exc}")
        report.verdict = "ONT not found on this OLT"
        return report

    start_step("ONT status")
    basic = session.run_timing(f"show gpon int {ref.cli} onu basic-info")
    ont = parse_onu_basic_info(basic, ref=ref)
    if not ont:
        report.add("FAIL", f"ONT {ref.compact}: could not parse onu basic-info")
        report.verdict = "ONT not found on this OLT"
        return report

    report.description = ont.description
    extras: list[str] = []
    if ont.serial:
        extras.append(f"serial {ont.serial}")
    if ont.distance_m is not None:
        extras.append(f"{ont.distance_m:g}m")
    if ont.onu_config:
        extras.append(f"config {ont.onu_config}")
    extra_text = f" ({', '.join(extras)})" if extras else ""
    oper = (ont.operational_state or "").casefold()
    ont_down = False
    if oper == "enabled":
        report.add("PASS", f"ONT {ref.compact}: Enabled{extra_text}")
    elif oper in {"disabled", "disable"}:
        report.add("FAIL", f"ONT {ref.compact}: OFFLINE ({ont.operational_state}){extra_text}")
        ont_down = True
    else:
        report.add("WARN", f"ONT {ref.compact}: state {ont.operational_state}{extra_text}")

    if ont.onu_config and ont.onu_config.casefold() != "success":
        report.add("WARN", f"ONT config: {ont.onu_config}")

    start_step("ONT optics")
    rx_dbm = parse_onu_rx_dbm(session.run_timing(f"show gpon opt int {ref.cli}"))
    if rx_dbm is None:
        report.add("SKIP", "ONT optics: Rx power n/a")
    elif rx_dbm < _RX_WARN_DBM:
        report.add("WARN", f"ONT optics: Rx {rx_dbm:.1f} dBm (below {_RX_WARN_DBM:.0f} dBm)")
    else:
        report.add("PASS", f"ONT optics: Rx {rx_dbm:.1f} dBm")

    start_step("ONU events")
    event_status, event_summary = summarize_onu_history(
        ont.history,
        online_seconds=ont.online_seconds,
    )
    report.add(event_status, event_summary)

    start_step("MAC on ONT")
    client_mac: str | None = None
    mac_vlan: int | None = None
    mac_output = session.run_timing(f"show mac address-table int {ref.cli}")
    entries = _parse_bdcom_mac_lines(
        mac_output,
        wanted_interface=normalize_bdcom_interface(ref.compact),
    )
    usable = [entry for entry in entries if not looks_like_control_plane_mac(compact_mac(entry.mac_address))]
    if not usable:
        report.add("FAIL", f"No client MAC learned on ONT {ref.compact}")
    else:
        selected = usable[0]
        client_mac = selected.mac_address
        mac_vlan = selected.vlan_id
        vlan_ids = sorted({entry.vlan_id for entry in usable if entry.vlan_id is not None})
        report.add("PASS", f"MAC on ONT: {client_mac} (VLAN(s) {vlan_ids or ['n/a']})")

    start_step("VLAN policy")
    expected_vlans, vlan_rule = expected_vlans_for_port(
        ont.description,
        access_vlan=mac_vlan,
        vlan_alt=vlan_alt,
    )
    vlan_extra = f", MAC VLAN {mac_vlan}" if mac_vlan is not None else ""
    if expected_vlans is None and mac_vlan is not None:
        report.add("PASS", f"VLAN policy: service VLAN {mac_vlan}{vlan_extra}")
    else:
        report.add(
            "SKIP" if expected_vlans is None else "PASS",
            f"VLAN policy: {vlan_rule}{vlan_extra}",
        )

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
