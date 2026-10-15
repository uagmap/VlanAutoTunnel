from __future__ import annotations

import re

from vlan_tool.models import MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import CLI_ERROR_STRICT_RE as CLI_ERROR_RE, DriverCapabilities, VendorDriver, compact_mac, format_mac


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+"
    r"(?P<mac>[0-9a-fA-F:.-]+)\s+"
    r"(?P<interface>(?:10G-front-port|front-port|pon-port)\s+\d+(?::\d+)?)\s+"
    r"(?P<entry_type>\S+)\s*$",
    flags=re.IGNORECASE,
)
class LTPDriver(VendorDriver):
    vendor_key = "ltp"
    capabilities = DriverCapabilities(mac_lookup=True)

    def prepare_session(self, session: SwitchSession) -> None:
        # LTP CLI needs explicit switch context for VLAN/MAC workflow.
        session.run_timing("switch", confirm_label="enter switch mode")

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = compact_mac(mac_address)
        lookup_mac = format_mac(wanted, sep=":", group=2)
        output = session.run_timing(f"show mac include mac {lookup_mac}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            output = session.run_timing("show mac")
        return _parse_ltp_mac_lines(output, wanted_mac=wanted)

    def normalize_interface(self, interface: str) -> str:
        return normalize_ltp_interface(interface)

    def summary(self) -> str:
        return "Eltex LTP driver with MAC lookup in switch context."


def normalize_ltp_interface(interface: str) -> str:
    text = re.sub(r"\s+", " ", interface.strip()).casefold()
    match = re.match(r"^(10g-front-port|front-port|pon-port)\s*([0-9]+(?::[0-9]+)?)$", text)
    if not match:
        return text
    return f"{match.group(1)} {match.group(2)}"


def _parse_ltp_mac_lines(output: str, *, wanted_mac: str | None = None) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        match = MAC_LINE_RE.match(line.rstrip())
        if not match:
            continue
        parsed_mac = compact_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=match.group("mac"),
                interface=match.group("interface"),
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
