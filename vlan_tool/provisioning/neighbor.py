"""Port description helpers + Zabbix name matching for the next hop.

Reads interface descriptions, then turns them into the next SwitchRecord.
That is how live_path walks hop-to-hop without a static topology map.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from vlan_tool import site
from vlan_tool.models import SwitchRecord
from vlan_tool.naming import (
    canonical_neighbor_name,
    equipment_family,
    equipment_location,
    equipment_port_count,
    extract_id_token,
    strip_optical_link_noise,
    vendor_family,
)
from vlan_tool.provisioning.common import debug_note as _debug_note
from vlan_tool.provisioning.common import looks_like_invalid_command
from vlan_tool.vendors.snr import format_snr_cli_interface, normalize_snr_interface

if TYPE_CHECKING:
    from vlan_tool.resolver import SwitchResolver


def resolve_neighbor_from_description(
    resolver: SwitchResolver,
    description: str | None,
    *,
    source_switch: SwitchRecord | None = None,
    debug: bool = False,
) -> SwitchRecord | None:
    if not description:
        return None
    base = description.strip().strip("\"'`")
    if not base:
        return None
    # ponytail: strip nm/km/wavelength suffixes before Zabbix/name matching.
    cleaned = strip_optical_link_noise(base) or base
    if debug and cleaned != base:
        _debug_note(debug, f"Normalized neighbor description '{base}' -> '{cleaned}'")

    id_token = extract_id_token(cleaned) or extract_id_token(base)
    if id_token:
        try:
            resolved_by_id = resolver.resolve(id_token)
        except LookupError:
            resolved_by_id = None
        if resolved_by_id:
            score = score_neighbor_match(
                description=cleaned,
                switch=resolved_by_id,
                source_switch=source_switch,
            )
            if score >= 100:
                _debug_note(
                    debug,
                    "Resolved next hop from description "
                    f"'{cleaned}' via ID '{id_token}' -> {resolved_by_id.name} ({resolved_by_id.host})",
                )
                return resolved_by_id
            _debug_note(
                debug,
                "Rejected weak neighbor ID candidate "
                f"'{id_token}' -> {resolved_by_id.name} ({resolved_by_id.host}) score={score}",
            )

    try:
        resolved_candidates = resolver.resolve_candidates(cleaned)
    except LookupError:
        resolved_candidates = []

    if source_switch:
        for resolved in resolved_candidates:
            if not _same_switch(source_switch, resolved):
                continue
            if score_neighbor_match(
                description=cleaned,
                switch=resolved,
                source_switch=None,
            ) >= 100:
                _debug_note(
                    debug,
                    "Rejected self-referencing neighbor description "
                    f"'{cleaned}' -> {resolved.name} ({resolved.host})",
                )
                return None

    scored_by_switch: dict[str, tuple[int, SwitchRecord]] = {}
    for resolved in resolved_candidates:
        score = score_neighbor_match(
            description=cleaned,
            switch=resolved,
            source_switch=source_switch,
        )
        key = str(resolved.metadata.get("zabbix_hostid") or resolved.host).casefold()
        previous = scored_by_switch.get(key)
        if score >= 100 and (previous is None or score > previous[0]):
            scored_by_switch[key] = (score, resolved)
        else:
            _debug_note(
                debug,
                "Rejected weak neighbor candidate "
                f"'{cleaned}' -> {resolved.name} ({resolved.host}) score={score}",
            )

    ranked = sorted(
        scored_by_switch.values(),
        key=lambda item: (-item[0], item[1].name.casefold(), item[1].host),
    )
    if not ranked:
        return None

    best_score, best_switch = ranked[0]
    if len(ranked) > 1:
        second_score, second_switch = ranked[1]
        if best_score - second_score < 80:
            _debug_note(
                debug,
                "Rejected ambiguous neighbor description "
                f"'{cleaned}': {best_switch.name} ({best_switch.host}) score={best_score}, "
                f"{second_switch.name} ({second_switch.host}) score={second_score}",
            )
            return None

    _debug_note(
        debug,
        "Resolved next hop from description "
        f"'{cleaned}' -> {best_switch.name} ({best_switch.host}) score={best_score}",
    )
    return best_switch


def score_neighbor_match(
    *,
    description: str,
    switch: SwitchRecord,
    source_switch: SwitchRecord | None,
) -> int:
    if source_switch and _same_switch(source_switch, switch):
        return 0

    names = [*switch.all_names, switch.host]
    id_token = extract_id_token(description)
    candidate_ids = {token for name in names if (token := extract_id_token(name))}
    if id_token:
        if candidate_ids and id_token not in candidate_ids:
            return 0
        if id_token in candidate_ids:
            return 1_000

    score = max((_score_neighbor_name(description, name, switch.vendor) for name in names if name), default=0)
    if score < 100:
        return 0
    if source_switch and _in_same_access_pool(source_switch.host, switch.host):
        score += 20
    return score


def _score_neighbor_name(description: str, candidate_name: str, candidate_vendor: str) -> int:
    # Port desc may omit "id" before the inventory number (..._2252 vs ..._id2252).
    # Only strip bare digits when they match THIS candidate's id — not wavelengths.
    aligned_description = _align_description_id_shorthand(description, candidate_name)
    probe = canonical_neighbor_name(aligned_description)
    candidate = canonical_neighbor_name(candidate_name)
    if not probe or not candidate:
        return 0

    exact_name = probe == candidate
    description_family = equipment_family(aligned_description)
    candidate_family = equipment_family(candidate_name) or vendor_family(candidate_vendor)

    if description_family:
        if candidate_family != description_family:
            return 0
    elif not exact_name:
        # Unknown equipment types are safe only on an exact normalized name.
        return 0

    description_location = equipment_location(aligned_description)
    candidate_location = equipment_location(candidate_name)
    location_quality = _location_match_quality(description_location, candidate_location)
    if description_family and location_quality == 0:
        return 0

    score = 100
    if description_family and candidate_family == description_family:
        score += 120
    if exact_name:
        score += 300
    score += location_quality * 2

    description_ports = equipment_port_count(aligned_description)
    candidate_ports = equipment_port_count(candidate_name)
    if description_ports is not None and candidate_ports is not None:
        if description_ports == candidate_ports:
            score += 140
        else:
            return 0
    return score


def _align_description_id_shorthand(description: str, candidate_name: str) -> str:
    """If desc ends with _2252 and candidate is ..._id2252, treat as the same id suffix."""
    candidate_id = extract_id_token(candidate_name)
    if not candidate_id:
        return description
    digits = candidate_id[2:]
    if not digits.isdigit():
        return description
    return re.sub(
        rf"([_\-.])(?:id)?{re.escape(digits)}(?![a-z0-9])",
        "",
        description,
        count=1,
        flags=re.IGNORECASE,
    )


def _location_match_quality(left: str, right: str) -> int:
    if not left or not right:
        return 0
    left_compact = re.sub(r"[^a-z0-9]", "", left.casefold())
    right_compact = re.sub(r"[^a-z0-9]", "", right.casefold())
    if left_compact == right_compact:
        return 100
    # Abbreviated street stem, same building suffix: river98-26 vs riverside98-26.
    # Require a shared trailing number block so Campus vs CampusWest stays rejected.
    left_parts = re.match(r"^([a-z]+)([0-9].*)$", left_compact)
    right_parts = re.match(r"^([a-z]+)([0-9].*)$", right_compact)
    if not left_parts or not right_parts:
        return 0
    if left_parts.group(2) != right_parts.group(2):
        return 0
    left_stem, right_stem = left_parts.group(1), right_parts.group(1)
    shorter, longer = sorted((left_stem, right_stem), key=len)
    if len(shorter) >= 4 and longer.startswith(shorter):
        return 80
    return 0


def _same_switch(left: SwitchRecord, right: SwitchRecord) -> bool:
    if left.host.casefold() == right.host.casefold():
        return True
    left_id = str(left.metadata.get("zabbix_hostid") or "")
    right_id = str(right.metadata.get("zabbix_hostid") or "")
    return bool(left_id and right_id and left_id == right_id)


def _in_same_access_pool(left_host: str, right_host: str) -> bool:
    left_pool = site.access_pool(left_host)
    right_pool = site.access_pool(right_host)
    if left_pool is None or right_pool is None:
        return True
    return left_pool == right_pool


def lookup_interface_description(
    *,
    statuses: dict[str, object],
    driver,
    interface: str | None,
) -> str | None:
    if not interface:
        return None
    details = statuses.get(driver.normalize_interface(interface))
    if not details:
        return None
    description = str(getattr(details, "description", "") or "").strip()
    return description or None


def discover_interface_description(*, session, driver, interface: str | None) -> str | None:
    if not interface:
        return None

    for command in _build_interface_description_commands(driver.vendor_key, interface):
        output = _run_vendor_show_command(session=session, vendor_key=driver.vendor_key, command=command)
        if not output or looks_like_invalid_command(output):
            continue
        keyword = r"port-name\s+\d+" if driver.vendor_key == "gr_ep_olt2" else "description"
        match = re.search(
            rf"^\s*{keyword}\s+(?P<description>.+)$",
            output,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        description = match.group("description").strip() if match else ""
        if description:
            return description
    return None


def _build_interface_description_commands(vendor_key: str, interface: str) -> list[str]:
    raw = interface.strip()
    compact = raw.lower().replace(" ", "")
    if vendor_key == "snr":
        normalized = normalize_snr_interface(interface)
        return [
            f"show run int eth {normalized}",
            f"show run int eth{normalized}",
            f"show run int {format_snr_cli_interface(interface)}",
        ]
    if vendor_key in {"snr_s5xxx", "bdcom"}:
        return [
            f"show running-config interface {compact}",
            f"show run interface {compact}",
            f"show run int {compact}",
            *([f"show run int {raw}"] if vendor_key == "snr_s5xxx" else []),
        ]
    if vendor_key == "snr_s2970":
        from vlan_tool.vendors.snr_s2970 import format_snr_s2970_config_interface

        port = format_snr_s2970_config_interface(interface)
        return [
            f"show run int {port}",
            f"show running-config interface {port}",
            f"show run interface {port}",
        ]
    if vendor_key in {"eltex_mes", "arista"}:
        return [f"show run int {compact}"]
    if vendor_key == "gr_ep_olt2":
        from vlan_tool.vendors.gr_ep_olt2 import format_gr_ep_olt2_section_interface

        section = format_gr_ep_olt2_section_interface(interface)
        return [f"show current-config section {section}"]
    return [f"show run int {raw}"]


_TIMING_VENDORS = {"snr", "snr_s2970", "snr_s5xxx", "eltex_mes", "arista", "bdcom", "fd160", "gr_ep_olt2", "ltp"}


def _run_vendor_show_command(*, session, vendor_key: str, command: str) -> str:
    if vendor_key in _TIMING_VENDORS:
        return session.run_timing(command)
    return session.run_show(command)
