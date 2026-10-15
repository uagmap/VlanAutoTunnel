"""FD160 GPON ONT checks for `check`. Isolated from FD160 deploy (config/save path)."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
import re

from vlan_tool.diagnostics.l3 import run_l3_stage
from vlan_tool.diagnostics.report import ONT_OFFLINE_VERDICT, ClientCheckReport, derive_verdict
from vlan_tool.diagnostics.vlan_policy import expected_vlans_for_port
from vlan_tool.provisioning.common import compact_mac, looks_like_control_plane_mac, looks_like_invalid_command

_RX_WARN_DBM = -30.0
_STABLE_ONLINE_SECONDS = 300
_FLAP_EVENT_WARN = 2

# ponytail: async OLT lines and pager text interleave with show output; strip before parse.
_NOISE_LINE_RE = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+PON\s+",
    re.IGNORECASE,
)
_MORE_RE = re.compile(r"--More", re.IGNORECASE)

_FS_PON_ONT_RE = re.compile(r"^(?P<fs>\d+/\d+)/(?P<pon>\d+)/(?P<ont>\d+)$")
_PON_ONT_RE = re.compile(r"^(?P<pon>\d+)/(?P<ont>\d+)$")
_SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,}$")

_ALL_ROW_RE = re.compile(
    r"(?P<fs>\d+/\d+)\s+"
    r"(?P<pon>\d+)\s+"
    r"(?P<ont_id>\d+)\s+"
    r"(?P<sn>\S+)\s+"
    r"(?P<control>\S+)\s+"
    r"(?P<run>\S+)\s+"
    r"(?P<config>\S+)\s+"
    r"(?P<match>\S+)\s+"
    r"(?P<last_down>\S+)\s*"
    r"(?P<desc>.*)?\s*$"
)
_FIELD_RE = {
    "run_state": re.compile(r"Run state\s*:\s*(?P<value>.+)", re.IGNORECASE),
    "config_state": re.compile(r"Config state\s*:\s*(?P<value>\S+)", re.IGNORECASE),
    "description": re.compile(r"Description\s*:\s*(?P<value>.+)", re.IGNORECASE),
    "last_down": re.compile(r"Last down cause\s*:\s*(?P<value>\S+)", re.IGNORECASE),
    "sn": re.compile(r"^\s*SN\s*:\s*(?P<value>\S+)", re.IGNORECASE | re.MULTILINE),
    "distance": re.compile(r"Distance\(m\)\s*:\s*(?P<value>\d+)", re.IGNORECASE),
    "online_time": re.compile(
        r"Online\s+time\s*:\s*(?:(?P<days>\d+)days?\s+)?(?P<hours>\d+)h:(?P<minutes>\d+)m",
        re.IGNORECASE,
    ),
}
_RX_POWER_RE = re.compile(r"Rx optical power\(dBm\)\s*:\s*(?P<value>-?\d+(?:\.\d+)?)", re.IGNORECASE)
_NATIVE_VLAN_RE = re.compile(
    r"^\s*ETH\s+\d+\s+\d+\s+\d+\s+(?P<vlan>\d+)\s+",
    re.MULTILINE,
)
_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_EVENT_RE = re.compile(
    r"^\s*\d+\s+"
    r"(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+"
    r"(?P<instance>.+?)\s{2,}"
    r"(?P<name>The ONT (?:online|offline))\s*$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Fd160OntRef:
    frame_slot: str
    pon_port: int
    ont_id: int

    @property
    def label(self) -> str:
        return f"{self.frame_slot}/{self.pon_port}/{self.ont_id}"


@dataclass(slots=True)
class Fd160OntInfo:
    ref: Fd160OntRef
    serial: str | None
    run_state: str
    config_state: str | None
    description: str | None
    last_down_cause: str | None
    distance_m: int | None
    online_seconds: int | None
    native_vlan: int | None


@dataclass(slots=True)
class Fd160OntSummaryRow:
    ref: Fd160OntRef
    serial: str
    run_state: str
    last_down_cause: str | None
    description: str | None


@dataclass(slots=True)
class Fd160Event:
    time: str
    name: str
    instance: str


def ont_cli_ref(port: str, *, default_frame_slot: str = "0/0") -> Fd160OntRef | str:
    """Return ONT coordinates or a serial string to resolve from `show ont info … all`."""
    text = port.strip()
    lowered = text.casefold().replace(" ", "")
    if lowered.startswith("gpon"):
        text = text[4:].strip()
        lowered = text.casefold().replace(" ", "")

    match = _FS_PON_ONT_RE.match(text)
    if match:
        return Fd160OntRef(match.group("fs"), int(match.group("pon")), int(match.group("ont")))

    match = _PON_ONT_RE.match(text)
    if match:
        return Fd160OntRef(default_frame_slot, int(match.group("pon")), int(match.group("ont")))

    if _SERIAL_RE.match(text):
        return text.upper()
    return text


def strip_fd160_noise(output: str) -> str:
    if not output:
        return ""
    kept: list[str] = []
    for line in output.splitlines():
        text = line.rstrip()
        if not text.strip():
            continue
        if _NOISE_LINE_RE.match(text):
            continue
        if _MORE_RE.search(text):
            # pager line often embeds a table row after the notification
            trimmed = _MORE_RE.sub("", text).strip()
            if trimmed:
                kept.append(trimmed)
            continue
        kept.append(text)
    return "\n".join(kept)


def _field_value(output: str, name: str) -> str | None:
    match = _FIELD_RE[name].search(output)
    if not match:
        return None
    return match.group("value").strip()


def _online_seconds(output: str) -> int | None:
    match = _FIELD_RE["online_time"].search(output)
    if not match:
        return None
    days = int(match.group("days") or 0)
    hours = int(match.group("hours"))
    minutes = int(match.group("minutes"))
    return ((days * 24 + hours) * 60 + minutes) * 60


def parse_ont_info(output: str, *, ref: Fd160OntRef) -> Fd160OntInfo | None:
    cleaned = strip_fd160_noise(output)
    if looks_like_invalid_command(cleaned):
        return None
    run_state = _field_value(cleaned, "run_state")
    if not run_state:
        return None
    desc = _field_value(cleaned, "description") or None
    if desc in {"--", ""}:
        desc = None
    last_down = _field_value(cleaned, "last_down")
    if last_down in {"--", ""}:
        last_down = None
    distance_raw = _field_value(cleaned, "distance")
    vlan_match = _NATIVE_VLAN_RE.search(cleaned)
    return Fd160OntInfo(
        ref=ref,
        serial=_field_value(cleaned, "sn"),
        run_state=run_state,
        config_state=_field_value(cleaned, "config_state"),
        description=desc,
        last_down_cause=last_down,
        distance_m=int(distance_raw) if distance_raw else None,
        online_seconds=_online_seconds(cleaned),
        native_vlan=int(vlan_match.group("vlan")) if vlan_match else None,
    )


def parse_ont_all_rows(output: str) -> list[Fd160OntSummaryRow]:
    rows: list[Fd160OntSummaryRow] = []
    for line in strip_fd160_noise(output).splitlines():
        text = line.strip()
        if not text:
            continue
        match = _ALL_ROW_RE.search(text)
        if not match:
            continue
        if not re.match(r"[A-Za-z0-9]", match.group("sn")):
            continue
        last_down = match.group("last_down")
        if last_down in {"--", ""}:
            last_down = None
        desc = (match.group("desc") or "").strip() or None
        rows.append(
            Fd160OntSummaryRow(
                ref=Fd160OntRef(
                    match.group("fs"),
                    int(match.group("pon")),
                    int(match.group("ont_id")),
                ),
                serial=match.group("sn"),
                run_state=match.group("run"),
                last_down_cause=last_down,
                description=desc,
            )
        )
    return rows


def resolve_ont_ref(rows: list[Fd160OntSummaryRow], query: str) -> Fd160OntRef | None:
    wanted = query.strip().upper()
    for row in rows:
        if row.serial.upper().startswith(wanted) or wanted in row.serial.upper():
            return row.ref
    return None


def parse_ont_rx_dbm(output: str) -> float | None:
    cleaned = strip_fd160_noise(output)
    match = _RX_POWER_RE.search(cleaned)
    if not match:
        return None
    try:
        return float(match.group("value"))
    except ValueError:
        return None


def parse_ont_learned_mac(output: str) -> str | None:
    cleaned = strip_fd160_noise(output)
    if looks_like_invalid_command(cleaned):
        return None
    for line in cleaned.splitlines():
        if "mac-address" in line.casefold():
            continue
        mac_match = _MAC_RE.search(line)
        if mac_match:
            return mac_match.group(1)
    return None


def parse_ont_events(output: str, *, ont_id: int, serial: str | None = None) -> list[Fd160Event]:
    events: list[Fd160Event] = []
    serial_key = (serial or "").upper()
    for line in strip_fd160_noise(output).splitlines():
        match = _EVENT_RE.match(line.rstrip())
        if not match:
            continue
        instance = match.group("instance")
        if f"ONU: {ont_id}" not in instance and (
            not serial_key or serial_key not in instance.upper()
        ):
            continue
        events.append(
            Fd160Event(
                time=match.group("time"),
                name=match.group("name"),
                instance=instance.strip(),
            )
        )
    return events


def summarize_pon_port(rows: list[Fd160OntSummaryRow], *, pon_port: int) -> tuple[str, str]:
    on_pon = [row for row in rows if row.ref.pon_port == pon_port]
    if not on_pon:
        return "SKIP", f"PON {pon_port}: could not read ONT list"
    online = sum(1 for row in on_pon if row.run_state.casefold() == "online")
    offline = len(on_pon) - online
    summary = f"PON {pon_port}: {online}/{len(on_pon)} ONTs online"
    if offline >= 3 and offline * 100 // len(on_pon) >= 20:
        return "WARN", f"{summary} ({offline} offline on this PON)"
    return "PASS", summary


def summarize_ont_events(
    events: list[Fd160Event],
    *,
    online_seconds: int | None,
) -> tuple[str, str]:
    if not events:
        return "PASS", "OLT events: no recent online/offline records for this ONT"
    offline_events = [event for event in events if "offline" in event.name.casefold()]
    online_events = [event for event in events if "online" in event.name.casefold()]
    latest = events[0]
    detail = f"latest {latest.name} at {latest.time}"
    stable = online_seconds is not None and online_seconds >= _STABLE_ONLINE_SECONDS
    if stable:
        return "PASS", f"OLT events: {len(events)} record(s); stable per ONT uptime; {detail}"
    toggles = min(len(offline_events), len(online_events))
    if toggles >= _FLAP_EVENT_WARN or len(offline_events) >= _FLAP_EVENT_WARN:
        return "WARN", f"OLT events: {len(offline_events)} offline / {len(online_events)} online; {detail}"
    return "PASS", f"OLT events: {detail}"


@contextmanager
def _fd160_gpon_context(session, frame_slot: str):
    """Enter `(config-gpon-…)` for show commands; always return to exec."""
    try:
        prompt = session.connection.find_prompt()
        if prompt.rstrip().endswith(">"):
            session.run_timing("en")
    except Exception:
        pass
    session.run_timing("conf")
    session.run_timing(f"int gpon {frame_slot}")
    try:
        yield
    finally:
        session.run_timing("exit")
        session.run_timing("exit")


def run_fd160_onu_check(
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
    """GPON ONT path: config-gpon show commands only; do not run deploy save path."""
    parsed = ont_cli_ref(port)
    default_fs = "0/0"
    ref: Fd160OntRef | None = parsed if isinstance(parsed, Fd160OntRef) else None
    serial_query = parsed if isinstance(parsed, str) else None

    with _fd160_gpon_context(session, ref.frame_slot if ref else default_fs):
        frame_slot = ref.frame_slot if ref else default_fs
        if ref is None:
            start_step("ONT lookup")
            all_output = session.run_timing(f"show ont info 1 all")
            rows = parse_ont_all_rows(all_output)
            ref = resolve_ont_ref(rows, serial_query or "")
            if not ref:
                report.add("FAIL", f"ONT {serial_query}: not found on PON 1 list")
                report.verdict = "ONT not found on this FD160"
                return report
        else:
            rows = parse_ont_all_rows(session.run_timing(f"show ont info {ref.pon_port} all"))

        pon, ont_id = ref.pon_port, ref.ont_id
        start_step("ONT status")
        info_output = session.run_timing(f"show ont info {pon} {ont_id}")
        ont = parse_ont_info(info_output, ref=ref)
        if not ont:
            report.add("FAIL", f"ONT {ref.label}: could not parse show ont info")
            report.verdict = "ONT not found on this FD160"
            return report

        report.description = ont.description
        extras: list[str] = []
        if ont.serial:
            extras.append(f"serial {ont.serial}")
        if ont.distance_m is not None:
            extras.append(f"{ont.distance_m}m")
        if ont.last_down_cause:
            extras.append(f"last down {ont.last_down_cause}")
        extra_text = f" ({', '.join(extras)})" if extras else ""
        run = ont.run_state.casefold()
        ont_down = False
        if run == "online":
            report.add("PASS", f"ONT {ref.label}: Online{extra_text}")
        elif run == "offline":
            report.add("FAIL", f"ONT {ref.label}: OFFLINE{extra_text}")
            ont_down = True
        else:
            report.add("WARN", f"ONT {ref.label}: run state {ont.run_state}{extra_text}")

        start_step("PON health")
        pon_status, pon_summary = summarize_pon_port(rows, pon_port=pon)
        report.add(pon_status, pon_summary)

        start_step("ONT optics")
        rx_dbm = parse_ont_rx_dbm(session.run_timing(f"show ont optical-info {pon} {ont_id}"))
        if rx_dbm is None:
            report.add("SKIP", "ONT optics: Rx power n/a")
        elif rx_dbm < _RX_WARN_DBM:
            report.add("WARN", f"ONT optics: Rx {rx_dbm:.2f} dBm (below {_RX_WARN_DBM:.0f} dBm)")
        else:
            report.add("PASS", f"ONT optics: Rx {rx_dbm:.2f} dBm")

        if ont.last_down_cause and ont.last_down_cause.casefold() in {"los", "dying-gasp"}:
            report.add("WARN", f"ONT last down cause: {ont.last_down_cause}")

        start_step("VLAN policy")
        expected_vlans, vlan_rule = expected_vlans_for_port(
            ont.description,
            access_vlan=ont.native_vlan,
            vlan_alt=vlan_alt,
        )
        vlan_extra = f", native VLAN {ont.native_vlan}" if ont.native_vlan is not None else ""
        if expected_vlans is None and ont.native_vlan is not None:
            report.add("PASS", f"VLAN policy: service VLAN {ont.native_vlan}{vlan_extra}")
        else:
            report.add(
                "SKIP" if expected_vlans is None else "PASS",
                f"VLAN policy: {vlan_rule}{vlan_extra}",
            )

        start_step("MAC on ONT")
        client_mac: str | None = None
        mac_output = session.run_timing(f"show ont port learned-mac {pon} {ont_id} eth 1")
        learned_mac = parse_ont_learned_mac(mac_output)
        if not learned_mac:
            report.add("FAIL", f"No client MAC learned on ONT {ref.label} eth 1")
        else:
            client_mac = learned_mac
            if looks_like_control_plane_mac(compact_mac(learned_mac)):
                report.add("WARN", f"MAC on ONT: {learned_mac} (control-plane MAC?)")
            else:
                report.add("PASS", f"MAC on ONT: {learned_mac}")

    start_step("OLT events")
    events = parse_ont_events(
        session.run_timing("show event history all"),
        ont_id=ont_id,
        serial=ont.serial,
    )
    event_status, event_summary = summarize_ont_events(events, online_seconds=ont.online_seconds)
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
