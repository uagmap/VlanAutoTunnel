"""Port link state and error counter collection (read-only show commands)."""

from __future__ import annotations

from datetime import datetime
import re

from dataclasses import dataclass

from vlan_tool.models import InterfaceStatus
from vlan_tool.provisioning.common import looks_like_invalid_command
from vlan_tool.provisioning.neighbor import discover_interface_description, lookup_interface_description


def resolve_port_context(*, session, driver, interface: str, statuses: dict[str, InterfaceStatus]) -> tuple[InterfaceStatus | None, str | None]:
    normalized = driver.normalize_interface(interface)
    details = statuses.get(normalized)
    description = lookup_interface_description(statuses=statuses, driver=driver, interface=interface)
    if not description:
        description = discover_interface_description(session=session, driver=driver, interface=interface)
    return details, description


def collect_interface_detail(*, session, driver, interface: str) -> str:
    raw = interface.strip()
    vendor = driver.vendor_key
    commands: list[str]
    if vendor == "cisco_ios":
        commands = [f"show interfaces {raw}", f"show interfaces {raw.replace(' ', '')}"]
    elif vendor in {"snr", "snr_s2970"}:
        commands = [
            f"show interface ethernet {raw}",
            f"show interfaces ethernet {raw}",
            f"show interfaces {raw}",
        ]
    elif vendor == "snr_s5xxx":
        compact = raw.lower().replace(" ", "")
        commands = [f"show interfaces {compact}", f"show interface {compact}"]
    elif vendor == "eltex_mes":
        compact = raw.lower().replace(" ", "")
        commands = [f"show interfaces {compact}", f"show interface {compact}"]
    elif vendor == "arista":
        commands = [f"show interfaces {raw}"]
    else:
        commands = [f"show interfaces {raw}", f"show interface {raw}"]

    for command in commands:
        output = (
            session.run_show(command)
            if vendor == "cisco_ios"
            else session.run_timing(command)
        )
        if output and not looks_like_invalid_command(output):
            return output
    return ""


def parse_error_counters(output: str) -> dict[str, int]:
    counters: dict[str, int] = {}
    patterns = {
        "input_errors": r"\b(\d+)\s+input errors\b",
        "output_errors": r"\b(\d+)\s+output errors\b",
        "crc": r"\b(\d+)\s+CRC\b",
        "giants": r"\b(\d+)\s+giants\b",
        "runts": r"\b(\d+)\s+runts\b",
    }
    for name, pattern in patterns.items():
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            counters[name] = int(match.group(1))
    return counters


_STATE_CHANGE_RE = re.compile(
    r"line protocol on .+ changed state to\s+(UP|DOWN)"
    r"|changed state to\s+(UP|DOWN)"
    r"|%LINK-[A-Z]-?(UP|DOWN)\b"
    r"|%LINK-[A-Z]-(Up|Down)\b",
    re.IGNORECASE,
)
_LOG_TS_SNIPPET_RE = re.compile(
    r"%\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}[:.]\d{3}\s+\d{4}",
    re.IGNORECASE,
)
_LOG_TS_TEXT_RE = re.compile(
    r"(?P<day>\d{1,2})-(?P<month>[A-Za-z]{3})-(?P<year>\d{4})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})",
    re.IGNORECASE,
)
_STATUS_CHANGE_AGE_RE = re.compile(
    r"Time since last status change:\s*(?P<dhms>\d+w-\d+d-\d+h-\d+m-\d+s)\s*(?:\(\s*(?P<secs>\d+)\s*seconds\s*\))?",
    re.IGNORECASE,
)
_ELTEX_LINK_AGE_RE = re.compile(
    r"Link is (?:up|down) for\s+"
    r"(?:(?P<days>\d+)\s+days?,\s+)?"
    r"(?P<hours>\d+)\s+hours?,\s+"
    r"(?P<minutes>\d+)\s+minutes?\s+and\s+"
    r"(?P<seconds>\d+)\s+seconds",
    re.IGNORECASE,
)
_RECENT_CHANGE_WARN_SECONDS = 300
_FLAP_BURST_WINDOW_SECONDS = 300
_FLAP_BURST_MIN_EVENTS = 4
_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


@dataclass(slots=True)
class PortLogScan:
    status: str
    summary: str
    details: list[str]


def scan_port_log_flap(*, session, driver, interface: str, interface_detail: str = "") -> PortLogScan:
    """Summarize link UP/DOWN log lines; rely on switch timestamps, not local datetime math."""
    raw = interface.strip()
    vendor = driver.vendor_key
    state_changes: list[str] = []

    log_commands: list[str] = []
    if vendor == "cisco_ios":
        log_commands = [f"show logging | include {raw}"]
    elif vendor == "snr_s2970":
        log_commands = [
            f"show logging | include {raw}",
            f"show logging buffered level warnings | i {raw}",
        ]
    elif vendor in {"snr", "snr_s5xxx"}:
        # Some SNR trains reject "show log"; buffered warnings is the working form.
        log_commands = [
            f"show log | include {raw}",
            f"show logging buffered level warnings | i {raw}",
        ]
    elif vendor == "eltex_mes":
        log_commands = [f"show log | include {raw}"]
    elif vendor == "arista":
        log_commands = [f"show logging | include {raw}"]

    for command in log_commands:
        output = session.run_show(command) if vendor == "cisco_ios" else session.run_timing(command)
        if not output or looks_like_invalid_command(output):
            continue
        for line in output.splitlines():
            text = line.strip()
            if not text or raw.casefold() not in text.casefold():
                continue
            if not _STATE_CHANGE_RE.search(text):
                continue
            state_changes.append(text)
        # First supported log command wins; do not merge aliases.
        break

    stable_text = format_status_change_age(interface_detail)
    stable_seconds = parse_status_change_seconds(interface_detail)

    if not state_changes:
        if stable_text:
            return PortLogScan("PASS", f"Port logs: no link state changes in log; stable {stable_text} per switch", [])
        return PortLogScan("PASS", "Port logs: no link state changes in recent log", [])

    # ponytail: historical log buffer can span months; only warn on live instability from show interface.
    if stable_seconds is not None and stable_seconds < _RECENT_CHANGE_WARN_SECONDS:
        return PortLogScan(
            "WARN",
            f"Port link unstable: last state change {stable_text or f'{stable_seconds}s ago'} per switch",
            [],
        )
    burst = _recent_flap_burst(state_changes)
    # Historical clusters stay in the buffer; only warn if the port still looks freshly unstable.
    if burst is not None and (stable_seconds is None or stable_seconds < _RECENT_CHANGE_WARN_SECONDS):
        return PortLogScan(
            "WARN",
            f"Port link unstable: {burst} link events in {format_duration_seconds(_FLAP_BURST_WINDOW_SECONDS)} log window",
            [],
        )

    parts = [f"{len(state_changes)} link events in log buffer"]
    if stable_text:
        parts.append(f"stable {stable_text} per switch")
    else:
        # No stability reading: still surface a flap burst the log timestamps prove directly.
        burst = _recent_flap_burst(state_changes)
        if burst is not None:
            return PortLogScan(
                "WARN",
                f"Port link unstable: {burst} link events in {format_duration_seconds(_FLAP_BURST_WINDOW_SECONDS)} log window",
                [],
            )

    last_down = _last_state_line(state_changes, "DOWN")
    last_up = _last_state_line(state_changes, "UP")
    if last_down:
        parts.append(f"last DOWN {_log_timestamp_snippet(last_down)}")
    if last_up:
        parts.append(f"last UP {_log_timestamp_snippet(last_up)}")

    return PortLogScan("PASS", "Port logs: " + "; ".join(parts), [])


def parse_status_change_seconds(output: str) -> int | None:
    match = _STATUS_CHANGE_AGE_RE.search(output)
    if match:
        if match.group("secs"):
            return int(match.group("secs"))
        return _dhms_to_seconds(match.group("dhms"))

    eltex_match = _ELTEX_LINK_AGE_RE.search(output)
    if not eltex_match:
        return None
    return (
        int(eltex_match.group("days") or 0) * 86400
        + int(eltex_match.group("hours")) * 3600
        + int(eltex_match.group("minutes")) * 60
        + int(eltex_match.group("seconds"))
    )


def format_status_change_age(output: str) -> str | None:
    seconds = parse_status_change_seconds(output)
    if seconds is None:
        return None
    return _format_duration(seconds)


def _dhms_to_seconds(dhms: str) -> int:
    weeks = days = hours = minutes = seconds = 0
    for amount, unit in re.findall(r"(\d+)([wdhms])", dhms.casefold()):
        value = int(amount)
        if unit == "w":
            weeks = value
        elif unit == "d":
            days = value
        elif unit == "h":
            hours = value
        elif unit == "m":
            minutes = value
        elif unit == "s":
            seconds = value
    return (((weeks * 7 + days) * 24 + hours) * 60 + minutes) * 60 + seconds


def _format_duration(total_seconds: int) -> str:
    minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{seconds}s"


def _last_state_line(lines: list[str], state: str) -> str | None:
    pattern = re.compile(
        rf"changed state to\s+{state}\b|%LINK-[A-Z]-?{state}\b",
        re.IGNORECASE,
    )
    for line in lines:
        if pattern.search(line):
            return line
    return None


def _log_timestamp_snippet(line: str) -> str:
    match = _LOG_TS_SNIPPET_RE.search(line)
    if match:
        return match.group(0)
    text_match = _LOG_TS_TEXT_RE.search(line)
    if text_match:
        return text_match.group(0)
    trimmed = line.strip()
    return trimmed[:80] + ("..." if len(trimmed) > 80 else "")


def _recent_flap_burst(lines: list[str]) -> int | None:
    timestamps = sorted(
        (stamp for line in lines if (stamp := _parse_log_timestamp(line)) is not None),
        reverse=True,
    )
    if len(timestamps) < _FLAP_BURST_MIN_EVENTS:
        return None
    newest = timestamps[0]
    events = sum(1 for stamp in timestamps if (newest - stamp).total_seconds() <= _FLAP_BURST_WINDOW_SECONDS)
    return events if events >= _FLAP_BURST_MIN_EVENTS else None


def _parse_log_timestamp(line: str) -> datetime | None:
    match = _LOG_TS_TEXT_RE.search(line)
    if not match:
        return None
    month = _MONTHS.get(match.group("month").casefold())
    if month is None:
        return None
    return datetime(
        year=int(match.group("year")),
        month=month,
        day=int(match.group("day")),
        hour=int(match.group("hour")),
        minute=int(match.group("minute")),
        second=int(match.group("second")),
    )


def format_duration_seconds(total_seconds: int) -> str:
    return _format_duration(total_seconds)


def port_link_summary(details: InterfaceStatus | None) -> str:
    if not details:
        return "unknown (interface not in status table)"
    admin = details.admin_state or "?"
    link = details.link_state or "?"
    mode = details.mode or "?"
    vlan = details.access_vlan
    vlan_text = f", access VLAN {vlan}" if vlan is not None else ""
    return f"admin {admin}, link {link}, mode {mode}{vlan_text}"
