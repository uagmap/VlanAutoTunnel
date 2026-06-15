from __future__ import annotations

import ipaddress
import re

from vlan_tool.models import SwitchRecord
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

    id_token = extract_id_token(base)
    if id_token:
        try:
            resolved_by_id = resolver.resolve(id_token)
        except LookupError:
            resolved_by_id = None
        if resolved_by_id:
            score = score_neighbor_match(
                description=base,
                switch=resolved_by_id,
                source_switch=source_switch,
            )
            if score >= 100:
                if debug:
                    _debug_note(
                        debug,
                        "Resolved next hop from description "
                        f"'{base}' via ID '{id_token}' -> {resolved_by_id.name} ({resolved_by_id.host})",
                    )
                return resolved_by_id
            if debug:
                _debug_note(
                    debug,
                    "Rejected weak neighbor ID candidate "
                    f"'{id_token}' -> {resolved_by_id.name} ({resolved_by_id.host}) score={score}",
                )

    candidates = build_neighbor_resolution_candidates(base)
    best: tuple[int, str, SwitchRecord] | None = None
    for candidate in candidates:
        if id_token and candidate.casefold() == id_token:
            continue
        try:
            resolved = resolver.resolve(candidate)
        except LookupError:
            continue
        score = score_neighbor_match(
            description=base,
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
            f"'{base}' via candidate '{candidate}' -> {resolved.name} ({resolved.host})",
        )
    return best[2] if best else None


def build_neighbor_resolution_candidates(description: str) -> list[str]:
    candidates: list[str] = []

    def _add(value: str | None) -> None:
        if not value:
            return
        text = value.strip().strip("\"'`")
        if text and text not in candidates:
            candidates.append(text)

    _add(description)
    primary = re.split(r"[\s,;]+", description, maxsplit=1)[0]
    _add(primary)

    id_token = extract_id_token(description)
    if id_token:
        _add(id_token)

    if primary and "." in primary:
        _, _, tail = primary.partition(".")
        _add(tail)

    return candidates


def is_confident_neighbor_match(description: str, switch: SwitchRecord) -> bool:
    blob_parts = [switch.name, switch.host, *(switch.aliases or [])]
    blob = " ".join(part for part in blob_parts if part).casefold()
    probe = description.casefold()

    if probe and (probe == switch.host.casefold() or probe in blob):
        return True

    id_token = extract_id_token(probe)
    if id_token:
        return id_token in blob

    tokens = description_tokens_for_match(probe)
    if not tokens:
        return False
    matched = [token for token in tokens if token in blob]
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

    id_token = extract_id_token(probe)
    if id_token:
        if id_token in blob:
            score += 360
        else:
            return 0

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
            has_id_token=bool(id_token),
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
        if token.startswith("id") and token[2:].isdigit():
            tokens.append(token)
            continue
        if token.isdigit():
            continue
        if len(token) < 4:
            continue
        tokens.append(token)
    return tokens


def _debug_note(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[debug] {message}")
