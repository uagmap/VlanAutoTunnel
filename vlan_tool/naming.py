"""Switch-name fingerprinting shared by Zabbix ranking (resolver) and next-hop matching (neighbor).

Names look like <model>.<location>_id<inventory>[_<optical noise>] and may carry a DNS suffix.
Pure string functions, no I/O.
"""

from __future__ import annotations

import re

# Trailing fiber metadata often glued onto L3/downlink descriptions (1310nm, 20km, bare 1550).
_OPTICAL_TRAILING_RE = re.compile(
    r"(?:[_\-\s]+(?:\d{3,4}\s*nm|\d+\s*km|1[2-6]\d{2}))+$",
    re.IGNORECASE,
)
_DIRECTION_PREFIX_RE = re.compile(
    r"^\s*(?:(?:up|down)link|to)(?:\s*[:._-]\s*|\s+)",
    re.IGNORECASE,
)
# ponytail: Zabbix hosts may be FQDNs (sw.site.example.net); strip any <label>-<tld> tail
# from the canonical form instead of hardcoding one domain.
_DNS_SUFFIX_RE = re.compile(r"-[a-z0-9]+-(?:net|com|org|local|lan)$")
_MODEL_PREFIX_PATTERNS = {
    "snr": re.compile(r"^(?:snr-)?s\d+[a-z]*(?:-\d+[a-z]+)?(?:-ups)?", re.IGNORECASE),
    "mes": re.compile(r"^mes\d+[a-z]*(?:-\d+p)?", re.IGNORECASE),
    "ltp": re.compile(r"^ltp-\d+x", re.IGNORECASE),
    "fd160": re.compile(r"^fd160\d*[a-z]*", re.IGNORECASE),
    "bdcom": re.compile(r"^bdcom-(?:(?:gp|gpon)\d+(?:-\d+)?)?", re.IGNORECASE),
    "gr": re.compile(r"^gr-ep-olt\d+(?:-\d+(?:-\d+ac)?)?", re.IGNORECASE),
    "cisco": re.compile(r"^(?:cisco-)?c\d+[a-z]*", re.IGNORECASE),
    "arista": re.compile(r"^(?:arista-|dcs-?|a)\d+[a-z0-9]*", re.IGNORECASE),
}
_KNOWN_MES_PORT_COUNTS = (64, 52, 48, 32, 28, 24, 16, 12, 10, 8, 4)


def infer_vendor_from_name(hostname: str) -> str:
    token = hostname.strip().casefold()
    model = token.split(".", 1)[0]
    if "bdcom.gp3600" in token or "bdcom.gpon" in token:
        return "bdcom_gpon"
    if model.startswith("fd160"):
        return "fd160"
    if model.startswith("gr-ep-olt1-4"):
        return "gr_ep_olt1"
    if model.startswith("gr-ep-olt2-8-2ac"):
        return "gr_ep_olt2"
    if model.startswith("ltp-"):
        return "ltp"
    if "bdcom" in model:
        return "bdcom"
    if re.match(r"^(?:snr-)?s5\d", model):
        return "snr_s5xxx"
    if re.match(r"^(?:snr-)?s2970", model):
        return "snr_s2970"
    if model.startswith("snr"):
        return "snr"
    if model.startswith("mes"):
        return "eltex_mes"
    if "arista" in model or model.startswith("dcs-") or re.match(r"^a\d{4}", model):
        return "arista"
    if model.startswith("c") or "cisco" in model:
        return "cisco_ios"
    return "generic_telnet"


def vendor_family(vendor: str) -> str | None:
    if vendor in {"snr", "snr_s2970", "snr_s5xxx"}:
        return "snr"
    if vendor == "eltex_mes":
        return "mes"
    if vendor in {"bdcom", "bdcom_gpon"}:
        return "bdcom"
    if vendor in {"gr_ep_olt1", "gr_ep_olt2"}:
        return "gr"
    if vendor in {"cisco_ios", "arista", "ltp", "fd160"}:
        return vendor.removesuffix("_ios")
    return None


def extract_id_token(text: str) -> str | None:
    match = re.search(r"(?<![a-z0-9])id\d{3,}(?![a-z0-9])", text.casefold())
    return match.group(0) if match else None


def strip_optical_link_noise(text: str) -> str:
    cleaned = text.strip().strip("\"'`")
    while True:
        updated = _OPTICAL_TRAILING_RE.sub("", cleaned)
        if updated == cleaned:
            break
        cleaned = updated
    return cleaned.rstrip("_- \t")


def description_without_id(text: str) -> str:
    cleaned = re.sub(r"[_\-.]?id\d{3,}", "", text, flags=re.IGNORECASE)
    return cleaned.strip("._- \t")


def canonical_neighbor_name(text: str) -> str:
    cleaned = description_without_id(strip_optical_link_noise(text) or text).casefold()
    while True:
        updated = _DIRECTION_PREFIX_RE.sub("", cleaned, count=1)
        if updated == cleaned:
            break
        cleaned = updated
    joined = "-".join(re.findall(r"[a-z0-9]+", cleaned))
    # Port descs often write LTP4x / LTP8X instead of LTP-4X / LTP-8X.
    return re.sub(r"^ltp(\d{1,2})x(?=-|$)", r"ltp-\1x", joined)


def equipment_family(text: str) -> str | None:
    canonical = canonical_neighbor_name(text)
    if re.match(r"^ltp(?:-|$)", canonical):
        return "ltp"
    if re.match(r"^(?:snr-)?s\d", canonical):
        return "snr"
    if re.match(r"^(?:mes|eltex-mes)", canonical):
        return "mes"
    if canonical.startswith("fd160"):
        return "fd160"
    if canonical.startswith("bdcom"):
        return "bdcom"
    if canonical.startswith("gr-ep-olt"):
        return "gr"
    if re.match(r"^(?:cisco-)?c\d{3,5}", canonical):
        return "cisco"
    if re.match(r"^(?:arista|dcs-|a\d{4})", canonical):
        return "arista"
    return None


def equipment_port_count(text: str) -> int | None:
    canonical = canonical_neighbor_name(text)
    family = equipment_family(canonical)
    if family == "ltp":
        match = re.match(r"^ltp-(\d{1,2})x(?:-|$)", canonical)
        return int(match.group(1)) if match else None
    if family == "snr":
        match = re.match(r"^(?:snr-)?s\d+[a-z]*-(\d{1,3})[a-z]+(?:-|$)", canonical)
        return int(match.group(1)) if match else None
    if family == "mes":
        explicit = re.match(r"^mes\d+[a-z]*-(\d{1,3})p(?:-|$)", canonical)
        if explicit:
            return int(explicit.group(1))
        model = re.match(r"^mes(\d+)", canonical)
        if model:
            digits = model.group(1)
            for count in _KNOWN_MES_PORT_COUNTS:
                if digits.endswith(str(count)):
                    return count
    if family == "bdcom":
        match = re.match(r"^bdcom-(?:gp|gpon)\d+-(\d{1,3})(?:-|$)", canonical)
        return int(match.group(1)) if match else None
    if family == "gr":
        match = re.match(r"^gr-ep-olt\d+-(\d{1,3})(?:-|$)", canonical)
        return int(match.group(1)) if match else None
    return None


def equipment_location(text: str) -> str:
    canonical = canonical_neighbor_name(text)
    pattern = _MODEL_PREFIX_PATTERNS.get(equipment_family(canonical) or "")
    prefix = pattern.match(canonical) if pattern else None
    if prefix:
        canonical = canonical[prefix.end():]
    return _DNS_SUFFIX_RE.sub("", canonical.strip("-"))
