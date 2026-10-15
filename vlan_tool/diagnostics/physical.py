"""Copper/fiber physical layer checks (SNR, Eltex MES)."""

from __future__ import annotations

import re

from dataclasses import dataclass

from vlan_tool.provisioning.common import looks_like_invalid_command
from vlan_tool.vendors.snr import normalize_snr_interface


@dataclass(slots=True)
class PhysicalCheck:
    status: str
    summary: str
    details: list[str]


_VCT_PAIR_RE = re.compile(
    r"\(\s*(?P<a>\d+)\s*,\s*(?P<b>\d+)\s*\)\s+(?P<status>\S+)(?:\s+(?P<length>\d+))?",
    re.IGNORECASE,
)
_MES_PAIR_RE = re.compile(
    r"(?P<pair>\d-\d|\d,\d)\s+(?P<status>\S+)(?:\s+(?P<length>\d+))?",
    re.IGNORECASE,
)
# MES2324 cable-length: gi1/0/21  51  1-2  A  normal  0
_MES_CABLE_PAIR_RE = re.compile(
    r"(?P<pair>\d-\d)\s+(?P<channel>[A-D])\s+(?P<polarity>\S+)(?:\s+(?P<skew>\d+))?",
    re.IGNORECASE,
)
_MES_SKEW_WARN_NS = 50
_MES_LENGTH_RE = re.compile(
    r"^\s*(?P<iface>(?:fa|gi|te|twe|hu)\S*)\s+(?P<length>\d+)\b",
    re.IGNORECASE | re.MULTILINE,
)
_RX_POWER_RE = re.compile(r"(?:RX Power|Input Power)[^\n-]*?(?P<value>-?\d+(?:\.\d+)?)", re.IGNORECASE)
# ponytail: only SNR/Eltex DOM alarm tags like (A+)/(W-); bare \bW\b/\bE\b false-positives on headers.
_ALARM_TAG_RE = re.compile(r"\([AW][+-]\)|\bLOS\b", re.IGNORECASE)
_SNR_DOM_NA_RE = re.compile(
    r"^\s*\S+\s+(?:N/?A\s+){3,}N/?A\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def check_physical_link(
    *,
    session,
    driver,
    interface: str,
    link_up: bool,
    raw_status_line: str = "",
    interface_detail: str = "",
) -> PhysicalCheck:
    vendor = driver.vendor_key
    if vendor in {"snr", "snr_s2970", "snr_s5xxx"}:
        return _check_snr_physical(
            session=session,
            interface=interface,
            link_up=link_up,
            raw_status_line=raw_status_line,
            interface_detail=interface_detail,
        )
    if vendor == "eltex_mes":
        return _check_mes_physical(
            session=session,
            interface=interface,
            link_up=link_up,
            interface_detail=interface_detail,
        )
    return PhysicalCheck("SKIP", "Physical layer: not supported for this vendor", [])


def _is_fiber_port(*, raw_status_line: str, interface_detail: str) -> bool:
    text = f"{raw_status_line}\n{interface_detail}".casefold()
    if "sfp" in text or "fiber" in text or "optical" in text:
        return True
    if "g-tx" in text or "gigabit-tx" in text or "twisted" in text:
        return False
    return False


def _check_snr_physical(
    *,
    session,
    interface: str,
    link_up: bool,
    raw_status_line: str,
    interface_detail: str,
) -> PhysicalCheck:
    eth = normalize_snr_interface(interface)
    if _is_fiber_port(raw_status_line=raw_status_line, interface_detail=interface_detail):
        return _parse_snr_transceiver(
            _first_output(
                session,
                [
                    f"show transceiver int eth {eth}",
                    f"show transceiver interface ethernet {eth}",
                    f"show transceiver interface ethernet {eth} detail",
                ],
            )
        )

    output = _first_output(
        session,
        [
            f"virtual-cable-test int eth {eth}",
            f"virtual-cable-test interface ethernet {eth}",
        ],
    )
    return _parse_snr_vct(output, link_up=link_up, interface_detail=interface_detail)


def _check_mes_physical(
    *,
    session,
    interface: str,
    link_up: bool,
    interface_detail: str,
) -> PhysicalCheck:
    mes_if = _mes_cli_interface(interface)
    if _is_fiber_port(raw_status_line="", interface_detail=interface_detail):
        output = _first_output(
            session,
            [
                f"show fiber-ports optical-transceiver detailed interface {mes_if}",
                f"show fiber-ports optical-transceiver interface {mes_if}",
            ],
        )
        return _parse_mes_optical(output)

    output = _first_output(
        session,
        [
            f"show cable-diagnostics cable-length interface {mes_if}",
            f"show cable-diagnostics tdr interface {mes_if}",
        ],
    )
    return _parse_mes_copper(output, link_up=link_up)


def _first_output(session, commands: list[str]) -> str:
    for command in commands:
        output = session.run_timing(command)
        if output and not looks_like_invalid_command(output):
            return output
    return ""


def _mes_cli_interface(interface: str) -> str:
    normalized = interface.strip().lower().replace(" ", "")
    if re.match(r"^(gi|te|fa|twe|hu)\d", normalized):
        return normalized
    if re.match(r"^\d+/\d+/\d+$", normalized):
        return f"gi{normalized}"
    return normalized


def _parse_snr_vct(output: str, *, link_up: bool, interface_detail: str) -> PhysicalCheck:
    if not output:
        return PhysicalCheck("SKIP", "Cable test: command not available on switch", [])

    pairs: dict[tuple[int, int], tuple[str, int | None]] = {}
    for match in _VCT_PAIR_RE.finditer(output):
        pair = (int(match.group("a")), int(match.group("b")))
        status = match.group("status").casefold()
        length = int(match.group("length")) if match.group("length") else None
        pairs[pair] = (status, length)

    if not pairs:
        return PhysicalCheck("SKIP", "Cable test: could not parse virtual-cable-test output", [])

    speed_100m = "100m" in interface_detail.casefold() or re.search(
        r"\b100\s*m\b|\b100m\b", interface_detail, re.IGNORECASE
    )
    active_pairs = {(1, 2), (3, 6)} if speed_100m else set(pairs)

    bad: list[str] = []
    notes: list[str] = []
    for pair, (status, length) in sorted(pairs.items()):
        if active_pairs and pair not in active_pairs:
            continue
        label = f"({pair[0]}, {pair[1]})"
        if status in {"well", "ok"}:
            notes.append(f"{label} {status}")
            continue
        if status == "open" and link_up:
            # ponytail: on 100M, unused pairs often read open while link is up.
            notes.append(f"{label} open (likely unused pair)")
            continue
        length_text = f", {length}m" if length is not None else ""
        bad.append(f"{label} {status}{length_text}")

    if bad:
        return PhysicalCheck(
            "WARN",
            f"Cable test: fault on {', '.join(bad)}",
            bad,
        )
    summary = "Cable test: " + (", ".join(notes) if notes else "pairs OK")
    return PhysicalCheck("PASS", summary, [])


def _parse_snr_transceiver(output: str) -> PhysicalCheck:
    if not output:
        return PhysicalCheck("SKIP", "Optics: show transceiver not available", [])

    # Combo/SFP ports often return N/A for all DOM fields when the optic does not expose monitoring.
    if _SNR_DOM_NA_RE.search(output) and not _RX_POWER_RE.search(output):
        return PhysicalCheck(
            "SKIP",
            "Optics: transceiver DOM unavailable (N/A)",
            [],
        )

    if _ALARM_TAG_RE.search(output):
        return PhysicalCheck("WARN", "Optics: transceiver threshold alarm/warning", _interesting_lines(output))

    rx_match = _RX_POWER_RE.search(output)
    if rx_match:
        try:
            rx_dbm = float(rx_match.group("value"))
        except ValueError:
            rx_dbm = None
        if rx_dbm is not None and rx_dbm <= -30:
            return PhysicalCheck(
                "WARN",
                f"Optics: low RX power ({rx_dbm} dBm)",
                _interesting_lines(output),
            )
        if rx_dbm is not None:
            return PhysicalCheck("PASS", f"Optics: RX {rx_dbm} dBm, no threshold alarms", [])

    if re.search(r"transceiver|rx power|tx power", output, re.IGNORECASE):
        return PhysicalCheck("PASS", "Optics: transceiver present, no threshold alarms", [])

    return PhysicalCheck("SKIP", "Optics: could not parse transceiver output", [])


def _parse_mes_copper(output: str, *, link_up: bool) -> PhysicalCheck:
    if not output:
        return PhysicalCheck("SKIP", "Cable diagnostics: command not available", [])

    channel_pairs = list(_MES_CABLE_PAIR_RE.finditer(output))
    if channel_pairs:
        length_match = _MES_LENGTH_RE.search(output)
        length = int(length_match.group("length")) if length_match else None
        polarities = [match.group("polarity").casefold() for match in channel_pairs]
        skews = [int(match.group("skew")) for match in channel_pairs if match.group("skew") is not None]
        length_text = f"~{length}m" if length is not None else "length n/a"
        polarity_set = set(polarities)
        bad: list[str] = []
        if len(polarity_set) > 1:
            mixed = ", ".join(f"{match.group('pair')} {match.group('polarity').casefold()}" for match in channel_pairs)
            bad.append(f"mixed polarity ({mixed})")
        high_skew = [skew for skew in skews if skew >= _MES_SKEW_WARN_NS]
        if high_skew:
            bad.append(f"pair skew {max(high_skew)}ns")
        if bad:
            return PhysicalCheck("WARN", f"Cable diagnostics: {length_text}, {'; '.join(bad)}", bad)
        polarity_text = polarities[0] if len(polarity_set) == 1 else "ok"
        skew_text = f", skew {max(skews)}ns" if skews else ""
        return PhysicalCheck(
            "PASS",
            f"Cable length: {length_text}, polarity {polarity_text}{skew_text}",
            [],
        )

    pairs: list[tuple[str, str, int | None]] = []
    for match in _MES_PAIR_RE.finditer(output):
        status = match.group("status").casefold()
        if status in {"a", "b", "c", "d"}:
            continue
        length = int(match.group("length")) if match.group("length") else None
        pairs.append((match.group("pair"), status, length))

    if pairs:
        bad = []
        notes = []
        for pair, status, length in pairs:
            if status in {"ok", "well"}:
                notes.append(f"{pair} OK")
            elif status == "open" and link_up:
                notes.append(f"{pair} open (likely unused pair)")
            else:
                length_text = f" @ {length}m" if length is not None else ""
                bad.append(f"{pair} {status}{length_text}")
        if bad:
            return PhysicalCheck("WARN", f"Cable diagnostics: {', '.join(bad)}", bad)
        return PhysicalCheck("PASS", f"Cable diagnostics: {', '.join(notes)}", [])

    length_match = _MES_LENGTH_RE.search(output)
    if length_match:
        return PhysicalCheck(
            "PASS",
            f"Cable length: ~{length_match.group('length')}m on {length_match.group('iface')}",
            [],
        )

    return PhysicalCheck("SKIP", "Cable diagnostics: could not parse output", [])


def _parse_mes_optical(output: str) -> PhysicalCheck:
    if not output:
        return PhysicalCheck("SKIP", "Optics: fiber transceiver command not available", [])

    if re.search(r"\bLOS\b.*\bYes\b", output, re.IGNORECASE):
        return PhysicalCheck("WARN", "Optics: loss of signal (LOS)", _interesting_lines(output))

    if _ALARM_TAG_RE.search(output):
        return PhysicalCheck("WARN", "Optics: transceiver alarm/warning", _interesting_lines(output))

    rx_match = _RX_POWER_RE.search(output)
    if rx_match:
        rx_dbm = float(rx_match.group("value"))
        if rx_dbm <= -30:
            return PhysicalCheck("WARN", f"Optics: low RX power ({rx_dbm} dBm)", _interesting_lines(output))
        return PhysicalCheck("PASS", f"Optics: RX {rx_dbm} dBm, no LOS", [])

    if re.search(r"optical|transceiver|input power", output, re.IGNORECASE):
        return PhysicalCheck("PASS", "Optics: transceiver data present, no LOS", [])

    return PhysicalCheck("SKIP", "Optics: could not parse fiber transceiver output", [])


def _interesting_lines(output: str, limit: int = 3) -> list[str]:
    keywords = ("alarm", "warning", "los", "power", "open", "short", "fail", "error")
    lines = []
    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        if any(word in text.casefold() for word in keywords):
            lines.append(text)
        if len(lines) >= limit:
            break
    return lines
