"""Tiny shared helpers: debug prints, invalid-command / junk-MAC checks."""

from __future__ import annotations

import re

from vlan_tool.trace_panel import ui_print
from vlan_tool.vendors.base import MAC_RE  # noqa: F401  (re-exported for provisioning/diagnostics)

_INVALID_COMMAND_MARKERS = (
    "invalid input",
    "unknown command",
    "unrecognized command",
    "incomplete command",
    "wrong number of parameters",
    "invalid range",
)
_CONTROL_PLANE_PREFIXES = ("01000ccc", "0180c2", "3333")


def debug_note(enabled: bool, message: str) -> None:
    if enabled:
        ui_print(message)


def compact_mac(mac_address: str) -> str:
    """Strip separators and lowercase: 'AA-bb.cc' -> 'aabbcc'. Does not validate length."""
    return re.sub(r"[^0-9A-Fa-f]", "", mac_address).casefold()


def looks_like_invalid_command(output: str) -> bool:
    lowered = output.casefold()
    return any(marker in lowered for marker in _INVALID_COMMAND_MARKERS)


def looks_like_control_plane_mac(compact: str) -> bool:
    if compact in {"000000000000", "ffffffffffff"} or compact.startswith("00000000"):
        return True
    return compact.startswith(_CONTROL_PLANE_PREFIXES)


def looks_like_login_output(output: str) -> bool:
    if not output:
        return False
    return bool(re.search(r"\b(username|password|user access verification|login)\b", output.casefold()))
