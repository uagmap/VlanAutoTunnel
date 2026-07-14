from __future__ import annotations

import re

from vlan_tool.models import InterfaceStatus, MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+"
    r"(?P<mac>[0-9A-Fa-f.:-]+)\s+"
    r"(?P<entry_type>\S+)\s+"
    r"(?P<interface>\S+)\s*$"
)
INTERFACE_BRIEF_RE = re.compile(
    r"^(?P<interface>g\d+/\d+)\s+"
    r"(?P<description>.+?)\s+"
    r"(?P<status>up|down)\s+"
    r"(?P<vlan>\S+)\s+"
    r"(?P<duplex>\S+)\s+"
    r"(?P<speed>\S+)\s+"
    r"(?P<port_type>\S+)\s*$",
    re.IGNORECASE,
)
PASSWORD_PROMPT_RE = re.compile(r"(?:password|passcode)\s*[:>]\s*$", re.IGNORECASE)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command|error:)",
    re.IGNORECASE,
)


class SNRS2970Driver(VendorDriver):
    vendor_key = "snr_s2970"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=False,
        interface_inventory=True,
        provisioning=False,
    )

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def prepare_session(self, session: SwitchSession) -> None:
        prompt = ""
        try:
            prompt = session.connection.find_prompt()
        except Exception:
            pass
        if prompt.rstrip().endswith(">"):
            enable_output = session.run_timing("enable", confirm_label="enter enable mode")
            if PASSWORD_PROMPT_RE.search(enable_output):
                secret = str(getattr(session.connection, "secret", "") or "")
                session.run_timing(
                    secret,
                    confirm_label="send enable password",
                    sensitive=True,
                )

        for command in ("terminal length 0", "no page"):
            response = session.run_timing(command)
            if not CLI_ERROR_RE.search(response):
                break

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_snr_s2970_mac(mac_address)
        lookup_mac = format_snr_s2970_cli_mac(wanted)
        # Strict H.H.H format; no "address" keyword on this train.
        output = session.run_timing(f"show mac address-table {lookup_mac}")
        if CLI_ERROR_RE.search(output) or not output.strip():
            return []
        return parse_snr_s2970_mac_lines(output, wanted_mac=wanted)

    def get_interface_statuses(self, session: SwitchSession) -> dict[str, InterfaceStatus]:
        output = session.run_timing("show interface brief")
        if CLI_ERROR_RE.search(output):
            return {}

        results: dict[str, InterfaceStatus] = {}
        for line in output.splitlines():
            match = INTERFACE_BRIEF_RE.match(line.rstrip())
            if not match:
                continue
            interface = match.group("interface")
            vlan_text = match.group("vlan")
            mode = "trunk" if vlan_text.casefold().startswith("trunk") else "access"
            access_vlan = None
            if mode == "access" and vlan_text.isdigit():
                access_vlan = int(vlan_text)
            # ponytail: brief truncates descriptions; full text comes from show run int.
            normalized = self.normalize_interface(interface)
            results[normalized] = InterfaceStatus(
                interface=interface,
                normalized_interface=normalized,
                mode=mode,
                access_vlan=access_vlan,
                admin_state=match.group("status"),
                link_state=match.group("status"),
                description=None,
                raw_line=line,
            )
        return results

    def normalize_interface(self, interface: str) -> str:
        return normalize_snr_s2970_interface(interface)

    def summary(self) -> str:
        return "SNR-S2970 series driver with H.H.H MAC lookup and g0/N trunk tagging."


def normalize_snr_s2970_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_snr_s2970_cli_mac(normalized_mac: str) -> str:
    groups = [normalized_mac[index : index + 4] for index in range(0, 12, 4)]
    return ".".join(groups)


def normalize_snr_s2970_interface(interface: str) -> str:
    text = interface.strip().casefold().replace(" ", "")
    match = re.match(r"^(?:gigabitethernet|gi|g)(\d+/\d+)$", text)
    if match:
        return f"g{match.group(1)}"
    return text


def format_snr_s2970_config_interface(interface: str) -> str:
    return normalize_snr_s2970_interface(interface)


def parse_snr_s2970_mac_lines(output: str, *, wanted_mac: str | None = None) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        match = MAC_LINE_RE.match(line.rstrip())
        if not match:
            continue
        parsed_mac = normalize_snr_s2970_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=format_snr_s2970_cli_mac(parsed_mac),
                interface=match.group("interface"),
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries


def snr_s2970_vlan_exists(vlan_id: int, snapshot: str) -> bool:
    text = snapshot.casefold()
    if "invalid" in text and "input" in text:
        return False
    if any(marker in text for marker in ("not found", "no such", "does not exist")):
        return False
    return bool(re.search(rf"vlan\s*id\s*:\s*{vlan_id}\b", text, flags=re.IGNORECASE))


def snr_s2970_interface_tagged(*, vlan_id: int, interface: str, snapshot: str) -> bool:
    if not snr_s2970_vlan_exists(vlan_id, snapshot):
        return False
    wanted = normalize_snr_s2970_interface(interface)
    for line in snapshot.splitlines():
        match = re.match(
            r"^(?P<intf>g\d+/\d+)\s+(?P<attrs>.+)$",
            line.strip(),
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        if normalize_snr_s2970_interface(match.group("intf")) != wanted:
            continue
        return "tagged" in match.group("attrs").casefold()
    return False
