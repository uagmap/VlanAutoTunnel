"""Ticket-style PASS/WARN/FAIL lines for the client check."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(slots=True)
class CheckLine:
    status: str  # PASS, WARN, FAIL, SKIP
    message: str


@dataclass(slots=True)
class ClientCheckReport:
    switch_name: str
    switch_host: str
    port: str
    description: str | None = None
    lines: list[CheckLine] = field(default_factory=list)
    session_logs: list[str] = field(default_factory=list)
    verdict: str | None = None
    line_callback: Callable[[CheckLine], None] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def add(self, status: str, message: str) -> None:
        line = CheckLine(status=status, message=message)
        self.lines.append(line)
        if self.line_callback:
            self.line_callback(line)

    def failed(self, needle: str) -> bool:
        return any(line.status == "FAIL" and needle in line.message for line in self.lines)


_HEALTHY = "Access and L3 checks look healthy; if client still offline, check CPE/billing/auth"
ONT_OFFLINE_VERDICT = "ONT is offline — check fiber/power/ONT registration"
# (substring of a FAIL line, verdict) — first match wins.
_FAIL_VERDICTS = (
    ("Connection: access switch", "Access switch unreachable or not answering on Telnet"),
    ("Connection: L3 switch", "Access switch is up, but the matched L3 switch is unreachable"),
    ("Port link", "Problem at access port (link/admin down or errors)"),
)


def derive_verdict(report: ClientCheckReport) -> str:
    statuses = {line.status for line in report.lines}
    if "FAIL" in statuses:
        for needle, verdict in _FAIL_VERDICTS:
            if report.failed(needle):
                return verdict
        fails = [line.message for line in report.lines if line.status == "FAIL"]
        if any(msg.startswith("ONT ") and "OFFLINE" in msg for msg in fails):
            return ONT_OFFLINE_VERDICT
        if any(msg.startswith("ONT ") and "not found" in msg.casefold() for msg in fails):
            return "ONT not found on this OLT"
        if any("MAC on ONT" in msg or "MAC on port" in msg or "No client MAC learned on ONT" in msg for msg in fails):
            return "L2 issue — no MAC or wrong VLAN on access port"
        if report.failed("L3 MAC"):
            return "L2 present but L3 path broken (VLAN/trunk/SVI?)"
        if report.failed("L3 ARP"):
            return "MAC reaches L3 but client IP not in ARP (CPE/router/auth?)"
        return "One or more checks failed — see lines above"
    if "WARN" in statuses:
        # Soft WARNs (tiny counter noise) stay visible but do not own the likely-cause line alone.
        hard = [
            line.message
            for line in report.lines
            if line.status == "WARN" and not line.message.startswith("Interface error counters:")
        ]
        if not hard:
            return _HEALTHY
        if any("unstable" in msg.casefold() for msg in hard):
            return "Port link unstable — check link/optics/CPE power"
        if any("RSSI" in msg or "ONT optics" in msg for msg in hard):
            return "ONT optical level is low — check fiber/splitter/ONT"
        if any("cable" in msg.casefold() or "optics" in msg.casefold() for msg in hard):
            return "Physical layer issue — check cable/optics"
        if any("CPE management" in msg for msg in hard):
            return "Path up, router management unreachable"
        return "Path mostly up; review warnings (counters or ARP mismatch)"
    return _HEALTHY
