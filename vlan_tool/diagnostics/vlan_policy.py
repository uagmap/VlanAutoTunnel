"""Port-description rules for expected client VLAN (F=shared pool, U=static)."""

from __future__ import annotations

import re

from vlan_tool import site

F_PORT_RE = re.compile(r"^F\d+", re.IGNORECASE)
U_PORT_RE = re.compile(r"^U\d+", re.IGNORECASE)


def expected_vlans_for_port(
    description: str | None,
    *,
    access_vlan: int | None = None,
    vlan_alt: int | None = None,
) -> tuple[set[int] | None, str]:
    if vlan_alt is None:
        vlan_alt = site.F_PORT_ALT_VLAN
    token = (description or "").split()[0] if (description or "").strip() else ""
    if F_PORT_RE.match(token):
        return {site.F_PORT_VLAN, vlan_alt}, f"F-port ({token}): VLAN {site.F_PORT_VLAN} or {vlan_alt}"
    if U_PORT_RE.match(token):
        if access_vlan is not None:
            return {access_vlan}, f"U-port ({token}): static access VLAN {access_vlan}"
        return None, f"U-port ({token}): static VLAN (read access VLAN from switch config)"
    if token:
        return None, f"unknown port class ({token!r}): no F/U prefix rule"
    return None, "no port description — cannot infer VLAN policy"
