from __future__ import annotations

import re

from vlan_tool import site
from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import CLI_ERROR_STRICT_RE as CLI_ERROR_RE, DriverCapabilities, VendorDriver, compact_mac, format_mac


MAC_LINE_RE = re.compile(
    r"^\s*(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
    r"(?P<vlan>\d+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<entry_type>\S+)\s*$"
)


class GREPOLT2Driver(VendorDriver):
    vendor_key = "gr_ep_olt2"
    capabilities = DriverCapabilities(mac_lookup=True)

    def __init__(self) -> None:
        # ponytail: per-hop cache; singleton driver, single-threaded CLI only.
        self._mgmt_vlan_output: str | None = None

    def prepare_session(self, session: SwitchSession) -> None:
        self._mgmt_vlan_output = None
        prompt = _find_prompt(session)
        if prompt.rstrip().endswith(">"):
            session.run_timing("enable", confirm_label="enter enable mode")
            if _find_prompt(session).rstrip().endswith(">"):
                session.run_timing("ENABLE", confirm_label="enter enable mode")

        # OLT2 MAC lookup must run from config mode; from ">" vtysh mangles spaces.
        if "(config)" not in _find_prompt(session).casefold():
            for command in ("config", "conf"):
                output = session.run_timing(command, confirm_label="enter config mode")
                if CLI_ERROR_RE.search(output):
                    continue
                if "(config)" in f"{output}\n{_find_prompt(session)}".casefold():
                    break

        session.run_timing("vty output show-all", confirm_label="disable pager")

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = compact_mac(mac_address)
        # ponytail: path tracing uses switch management MACs on the management VLAN; expand to
        # full VLAN scans if a site traces client MACs through these OLTs.
        if self._mgmt_vlan_output is None:
            output = session.run_timing(f"show mac-address vlan {site.MANAGEMENT_VLAN}")
            if CLI_ERROR_RE.search(output) or not output.strip():
                return []
            self._mgmt_vlan_output = output
        return parse_gr_ep_olt2_mac_lines(self._mgmt_vlan_output, wanted_mac=wanted)

    def normalize_interface(self, interface: str) -> str:
        return interface.strip().casefold().replace(" ", "")

    def summary(self) -> str:
        return "GR-EP-OLT2-8-2AC driver with VLAN/MAC tracing and FD160-style trunk tagging."


def format_gr_ep_olt2_section_interface(interface: str) -> str:
    normalized = interface.strip().casefold().replace(" ", "")
    match = re.match(r"^(ge|xge|pon)(\d+/\d+/\d+)$", normalized)
    if match:
        return f"{match.group(1)} {match.group(2)}"
    return interface.strip()


def gr_ep_olt2_trunk_context(interface: str) -> tuple[str, str]:
    normalized = interface.strip().casefold().replace(" ", "")
    match = re.match(
        r"^(ge|xge|pon)(?P<slot>\d+)/(?P<group>\d+)/(?P<port>\d+)$",
        normalized,
    )
    if not match:
        raise ValueError(
            f"GR-EP-OLT2 trunk tagging expects ge/xge/pon X/Y/Z, got: {interface}"
        )
    intf_type = match.group(1)
    return f"{intf_type} {match.group('slot')}/{match.group('group')}", match.group("port")


def gr_ep_olt2_vlan_exists(vlan_id: int, snapshot: str) -> bool:
    if CLI_ERROR_RE.search(snapshot):
        return False
    return bool(
        re.search(rf"vlan-id:\s*{vlan_id}\b", snapshot, flags=re.IGNORECASE)
    )


def gr_ep_olt2_interface_tagged(*, vlan_id: int, interface: str, snapshot: str) -> bool:
    if not gr_ep_olt2_vlan_exists(vlan_id, snapshot):
        return False
    wanted = interface.strip().casefold().replace(" ", "")
    in_tagged = False
    tagged_tokens: list[str] = []
    for line in snapshot.splitlines():
        lowered = line.casefold()
        if "tagged-ports" in lowered:
            in_tagged = True
            continue
        if not in_tagged:
            continue
        stripped = line.strip()
        if stripped.startswith("-"):
            break
        if not stripped:
            continue
        tagged_tokens.extend(re.findall(r"\S+", stripped))
    return any(token.casefold().replace(" ", "") == wanted for token in tagged_tokens)


def _is_pager_noise(line: str) -> bool:
    lowered = line.casefold()
    if "--more" in lowered or "press 'q' to quit" in lowered:
        return True
    return line.count("\x08") > 3


def _find_prompt(session: SwitchSession) -> str:
    try:
        return session.connection.find_prompt()
    except Exception:
        return ""


def parse_gr_ep_olt2_mac_lines(output: str, *, wanted_mac: str | None = None) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    normalized_wanted = compact_mac(wanted_mac) if wanted_mac else None
    for line in output.splitlines():
        line_text = line.rstrip()
        if not line_text or _is_pager_noise(line_text):
            continue
        match = MAC_LINE_RE.match(line_text)
        if not match:
            continue
        parsed_mac = compact_mac(match.group("mac"))
        if normalized_wanted and parsed_mac != normalized_wanted:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=format_mac(parsed_mac, sep=":", group=2, upper=True),
                interface=match.group("interface"),
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
