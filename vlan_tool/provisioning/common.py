from __future__ import annotations

import re


def debug_note(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[debug] {message}")


def looks_like_invalid_command(output: str) -> bool:
    lowered = output.casefold()
    return "invalid input" in lowered or "unknown command" in lowered or "incomplete command" in lowered


def looks_like_control_plane_mac(compact_mac: str) -> bool:
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


def looks_like_login_output(output: str) -> bool:
    if not output:
        return False
    return bool(re.search(r"\b(username|password|user access verification|login)\b", output.casefold()))
