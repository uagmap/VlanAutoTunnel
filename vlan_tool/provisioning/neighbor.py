"""Port description helpers + Zabbix name matching for the next hop.

Reads interface descriptions, then turns them into the next SwitchRecord.
That is how live_path walks hop-to-hop without a static topology map.
"""

from __future__ import annotations

import ipaddress
import re

from vlan_tool.models import SwitchRecord
from vlan_tool.provisioning.actions import normalize_snr_interface_local, to_snr_ethernet_name
from vlan_tool.provisioning.common import debug_note as _debug_note
from vlan_tool.provisioning.common import looks_like_invalid_command
from vlan_tool.resolver import SwitchResolver


# Trailing fiber metadata often glued onto L3/downlink descriptions.
_OPTICAL_TRAILING_RE = re.compile(
    r"(?:[_\-\s]+(?:\d{3,4}\s*nm|\d+\s*km|1[2-6]\d{2}))+$",
    re.IGNORECASE,
)


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
                if debug:
                    _debug_note(
                        debug,
                        "Resolved next hop from description "
                        f"'{cleaned}' via ID '{id_token}' -> {resolved_by_id.name} ({resolved_by_id.host})",
                    )
                return resolved_by_id
            if debug:
                _debug_note(
                    debug,
                    "Rejected weak neighbor ID candidate "
                    f"'{id_token}' -> {resolved_by_id.name} ({resolved_by_id.host}) score={score}",
                )

    candidates = build_neighbor_resolution_candidates(cleaned)
    best: tuple[int, str, SwitchRecord] | None = None
    for candidate in candidates:
        if id_token and candidate.casefold() == id_token:
            continue
        try:
            resolved = resolver.resolve(candidate)
        except LookupError:
            continue
        score = score_neighbor_match(
            description=cleaned,
            switch=resolved,
            source_switch=source_switch,
        )
        if score < 100:
            if debug:
                _debug_note(
                    debug,
                    "Rejected weak neighbor candidate "
                    f"'{candidate}' -> {resolved.name} ({resolved.host}) score={score}",
                )
            continue
        if best is None or score > best[0]:
            best = (score, candidate, resolved)

    if best and debug:
        _, candidate, resolved = best
        _debug_note(
            debug,
            "Resolved next hop from description "
            f"'{cleaned}' via candidate '{candidate}' -> {resolved.name} ({resolved.host})",
        )
    return best[2] if best else None


def strip_optical_link_noise(text: str) -> str:
    cleaned = text.strip().strip("\"'`")
    while True:
        updated = _OPTICAL_TRAILING_RE.sub("", cleaned)
        if updated == cleaned:
            break
        cleaned = updated
    return cleaned.rstrip("_- \t")


def build_neighbor_resolution_candidates(description: str) -> list[str]:
    candidates: list[str] = []
    cleaned = strip_optical_link_noise(description) or description.strip()

    def _add(value: str | None) -> None:
        if not value:
            return
        text = value.strip().strip("\"'`")
        if text and text not in candidates:
            candidates.append(text)

    _add(cleaned)
    without_id = description_without_id(cleaned)
    _add(without_id)
    primary = re.split(r"[\s,;]+", cleaned, maxsplit=1)[0]
    _add(primary)
    _add(description_without_id(primary))

    id_token = extract_id_token(cleaned)
    if id_token:
        _add(id_token)

    if primary and "." in primary:
        _, _, tail = primary.partition(".")
        _add(tail)
        _add(description_without_id(tail))

    return candidates


def description_without_id(text: str) -> str:
    cleaned = re.sub(r"[_\-.]?id\d{3,}", "", text, flags=re.IGNORECASE)
    return cleaned.strip("._- \t")


def strong_name_match(description: str, switch: SwitchRecord) -> bool:
    """True when description matches switch hostname aside from optional id/optical noise."""
    probe = description_without_id(strip_optical_link_noise(description) or description).casefold()
    if not probe or len(probe) < 8:
        return False
    names = [switch.name.casefold(), *(alias.casefold() for alias in (switch.aliases or []) if alias)]
    for name in names:
        if not name:
            continue
        if probe == name:
            return True
        if probe.startswith(f"{name}.") or probe.startswith(f"{name}_"):
            return True
        if name.startswith(f"{probe}.") or name.startswith(f"{probe}_"):
            return True
        if len(name) >= 8 and (probe in name or name in probe):
            return True
    return False


def is_confident_neighbor_match(description: str, switch: SwitchRecord) -> bool:
    blob_parts = [switch.name, switch.host, *(switch.aliases or [])]
    blob = " ".join(part for part in blob_parts if part).casefold()
    probe = description.casefold()

    if probe and (probe == switch.host.casefold() or probe in blob):
        return True
    if strong_name_match(description, switch):
        return True

    id_token = extract_id_token(probe)
    if id_token and id_token in blob:
        return True

    tokens = description_tokens_for_match(probe)
    if not tokens:
        return False
    # Name-only tokens: ignore id* when the switch hostname simply omits the host id.
    name_tokens = [token for token in tokens if not (token.startswith("id") and token[2:].isdigit())]
    matched = [token for token in name_tokens if token in blob]
    if len(matched) >= 2:
        return True
    if len(matched) == 1 and len(matched[0]) >= 8:
        return True
    return False


def score_neighbor_match(
    *,
    description: str,
    switch: SwitchRecord,
    source_switch: SwitchRecord | None,
) -> int:
    if not is_confident_neighbor_match(description, switch):
        return 0

    blob_parts = [switch.name, switch.host, *(switch.aliases or [])]
    blob = " ".join(part for part in blob_parts if part).casefold()
    probe = description.casefold()
    score = 100

    if probe == switch.host.casefold():
        score += 500
    elif probe in blob:
        score += 240
    elif strong_name_match(description, switch):
        score += 220

    id_token = extract_id_token(probe)
    if id_token and id_token in blob:
        score += 360
    # ponytail: many Zabbix hosts omit idNNNN even when the port description has it.

    tokens = description_tokens_for_match(probe)
    matched = [token for token in tokens if token in blob]
    score += 45 * len(matched)
    if matched:
        score += max(len(token) for token in matched)

    if source_switch:
        if looks_like_map_mismatch(
            source_switch=source_switch,
            candidate_switch=switch,
            description=probe,
            has_id_token=bool(id_token and id_token in blob),
        ):
            # Fail-safe bias: avoid silent jumps to unrelated map names.
            score -= 320
        if in_same_switch_pool(source_switch.host, switch.host):
            score += 40

    return score


def looks_like_map_mismatch(
    *,
    source_switch: SwitchRecord,
    candidate_switch: SwitchRecord,
    description: str,
    has_id_token: bool,
) -> bool:
    if has_id_token:
        return False

    source_tokens = switch_identity_tokens(source_switch)
    candidate_tokens = switch_identity_tokens(candidate_switch)
    if not source_tokens or not candidate_tokens:
        return False
    if source_tokens.intersection(candidate_tokens):
        return False

    description_tokens = set(description_tokens_for_match(description))
    if description_tokens and description_tokens.intersection(candidate_tokens):
        return False

    # No source/candidate map-token overlap and description doesn't reinforce candidate:
    # likely stale/wrong description match from resolver search fuzziness.
    return True


def switch_identity_tokens(switch: SwitchRecord) -> set[str]:
    text = " ".join(
        part for part in [switch.name, *(switch.aliases or [])] if isinstance(part, str) and part.strip()
    ).casefold()
    tokens: set[str] = set()
    for token in re.findall(r"[a-z0-9]+", text):
        if token in {"snr", "mes", "cisco", "switch", "olt", "gpon", "epon"}:
            continue
        if token.startswith("id") and token[2:].isdigit():
            continue
        if token.isdigit():
            continue
        if len(token) < 4:
            continue
        if re.match(r"^(?:c\d{3,5}[a-z0-9]*|s\d{3,5}[a-z0-9]*)$", token):
            continue
        tokens.add(token)
    return tokens


def in_same_switch_pool(left_host: str, right_host: str) -> bool:
    left_pool = extract_10_7_pool(left_host)
    right_pool = extract_10_7_pool(right_host)
    if left_pool is None or right_pool is None:
        return True
    return left_pool == right_pool


def extract_10_7_pool(host: str) -> int | None:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not isinstance(parsed, ipaddress.IPv4Address):
        return None
    octets = host.split(".")
    if len(octets) != 4:
        return None
    if octets[0] != "10" or octets[1] != "7":
        return None
    if not octets[2].isdigit():
        return None
    return int(octets[2])


def extract_id_token(text: str) -> str | None:
    match = re.search(r"(?<![a-z0-9])id\d{3,}(?![a-z0-9])", text.casefold())
    if not match:
        return None
    return match.group(0)


def is_optical_noise_token(token: str) -> bool:
    lowered = token.casefold()
    if re.fullmatch(r"\d{3,4}nm", lowered):
        return True
    if re.fullmatch(r"\d+km", lowered):
        return True
    if lowered.isdigit() and 1200 <= int(lowered) <= 1700:
        return True
    return False


def description_tokens_for_match(text: str) -> list[str]:
    ignored = {
        "snr",
        "mes",
        "switch",
        "uplink",
        "downlink",
        "trunk",
        "port",
        "ethernet",
        "gigabit",
        "tengigabit",
    }
    tokens: list[str] = []
    for token in re.findall(r"[a-z0-9]+", text.casefold()):
        if token in ignored:
            continue
        if is_optical_noise_token(token):
            continue
        if token.startswith("id") and token[2:].isdigit():
            tokens.append(token)
            continue
        if token.isdigit():
            continue
        if len(token) < 4:
            continue
        tokens.append(token)
    return tokens


def lookup_interface_description(
    *,
    statuses: dict[str, object],
    driver,
    interface: str | None,
) -> str | None:
    if not interface:
        return None
    normalized = driver.normalize_interface(interface)
    details = statuses.get(normalized)
    if not details:
        return None
    description = str(getattr(details, "description", "") or "").strip()
    return description or None


def discover_interface_description(*, session, driver, interface: str | None) -> str | None:
    if not interface:
        return None

    commands = _build_interface_description_commands(driver.vendor_key, interface)
    for command in commands:
        output = _run_vendor_show_command(session=session, vendor_key=driver.vendor_key, command=command)
        if not output or looks_like_invalid_command(output):
            continue
        if driver.vendor_key == "gr_ep_olt2":
            match = re.search(
                r"^\s*port-name\s+\d+\s+(?P<description>.+)$",
                output,
                flags=re.IGNORECASE | re.MULTILINE,
            )
        else:
            match = re.search(
                r"^\s*description\s+(?P<description>.+)$",
                output,
                flags=re.IGNORECASE | re.MULTILINE,
            )
        if not match:
            continue
        description = match.group("description").strip()
        if description:
            return description
    return None


def _build_interface_description_commands(vendor_key: str, interface: str) -> list[str]:
    raw = interface.strip()
    if vendor_key == "snr":
        normalized = normalize_snr_interface_local(interface)
        return [
            f"show run int eth {normalized}",
            f"show run int eth{normalized}",
            f"show run int {to_snr_ethernet_name(interface)}",
        ]
    if vendor_key == "snr_s5xxx":
        compact = raw.lower().replace(" ", "")
        return [
            f"show running-config interface {compact}",
            f"show run interface {compact}",
            f"show run int {compact}",
            f"show run int {raw}",
        ]
    if vendor_key == "snr_s2970":
        from vlan_tool.vendors.snr_s2970 import format_snr_s2970_config_interface

        port = format_snr_s2970_config_interface(interface)
        return [
            f"show run int {port}",
            f"show running-config interface {port}",
            f"show run interface {port}",
        ]
    if vendor_key == "eltex_mes":
        return [f"show run int {raw.lower().replace(' ', '')}"]
    if vendor_key == "arista":
        return [f"show run int {raw.lower().replace(' ', '')}"]
    if vendor_key == "bdcom":
        compact = raw.lower().replace(" ", "")
        return [
            f"show running-config interface {compact}",
            f"show run interface {compact}",
            f"show run int {compact}",
        ]
    if vendor_key == "gr_ep_olt2":
        from vlan_tool.vendors.gr_ep_olt2 import format_gr_ep_olt2_section_interface

        section = format_gr_ep_olt2_section_interface(interface)
        return [f"show current-config section {section}"]
    return [f"show run int {raw}"]


def _run_vendor_show_command(*, session, vendor_key: str, command: str) -> str:
    if vendor_key in {
        "snr",
        "snr_s2970",
        "snr_s5xxx",
        "eltex_mes",
        "arista",
        "bdcom",
        "fd160",
        "gr_ep_olt2",
        "ltp",
    }:
        return session.run_timing(command)
    return session.run_show(command)
