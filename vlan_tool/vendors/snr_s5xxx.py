from __future__ import annotations

import re

from vlan_tool.models import InterfaceStatus, MacTableEntry
from vlan_tool.session import SwitchSession
from vlan_tool.vendors.base import DriverCapabilities, VendorDriver


MAC_LINE_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+(?P<mac>[0-9a-fA-F.:-]+)\s+(?P<entry_type>\S+)\s+(?P<interface>\S+)\s*$"
)
INTERFACE_LINE_RE = re.compile(
    r"^(?P<interface>[A-Za-z]+[0-9]+(?:/[0-9]+)*)\s+"
    r"(?P<port_type>\S+)\s+"
    r"(?P<pvid>\S+)\s+"
    r"(?P<mode>\S+)\s+"
    r"(?P<status>\S+)\s+"
    r"(?P<reason>\S+)\s+"
    r"(?P<speed>\S+)\s+"
    r"(?P<port_ch>\S+)\s*"
    r"(?P<description>.*)$"
)
PASSWORD_PROMPT_RE = re.compile(r"(?:password|passcode)\s*[:>]\s*$", re.IGNORECASE)
CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|unrecognized command|incomplete command|error:)",
    re.IGNORECASE,
)


class SNRS5xxxDriver(VendorDriver):
    vendor_key = "snr_s5xxx"
    capabilities = DriverCapabilities(
        mac_lookup=True,
        mac_lookup_by_interface=True,
        interface_inventory=True,
        provisioning=False,
    )

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def prepare_session(self, session: SwitchSession) -> None:
        enable_output = session.run_timing("enable", confirm_label="enter enable mode")
        if PASSWORD_PROMPT_RE.search(enable_output):
            secret = str(getattr(session.connection, "secret", "") or "")
            session.run_timing(
                secret,
                confirm_label="send enable password",
                sensitive=True,
            )

        session.run_timing("terminal length 0")
        session.run_timing("terminal width 511")
        session.run_timing("no page")

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        wanted = normalize_snr_s5_mac(mac_address)
        output = session.run_timing(
            f"show mac address-table address {format_snr_s5_cli_mac(wanted)}"
        )
        if CLI_ERROR_RE.search(output) or not output.strip():
            output = session.run_timing("show mac address-table")
        return _parse_snr_s5_mac_lines(output, wanted_mac=wanted)

    def lookup_interface_macs(self, session: SwitchSession, interface: str) -> list[MacTableEntry]:
        lookup_interface = format_snr_s5_cli_interface(interface)
        outputs: list[str] = []
        for command in (
            f"show mac address-table interface {lookup_interface}",
            f"show mac address-table dynamic interface {lookup_interface}",
            "show mac address-table",
        ):
            output = session.run_timing(command)
            outputs.append(output)
            if command == "show mac address-table":
                break
            if not CLI_ERROR_RE.search(output) and output.strip():
                break

        wanted_interface = self.normalize_interface(interface)
        for output in outputs:
            entries = _parse_snr_s5_mac_lines(output, wanted_interface=wanted_interface)
            if entries:
                return entries
        return []

    def get_interface_statuses(self, session: SwitchSession) -> dict[str, InterfaceStatus]:
        output = session.run_timing("show int brief")
        if CLI_ERROR_RE.search(output):
            output = session.run_timing("show interface brief")

        results: dict[str, InterfaceStatus] = {}
        last_interface_key: str | None = None
        for line in output.splitlines():
            stripped = line.rstrip()
            if not stripped or stripped.lstrip().startswith(("-", "Codes:", "Ethernet", "Interface")):
                continue

            match = INTERFACE_LINE_RE.match(stripped)
            if match:
                interface = match.group("interface")
                mode_text = match.group("mode").strip().casefold()
                pvid_text = match.group("pvid").strip()
                access_vlan = int(pvid_text) if pvid_text.isdigit() and mode_text == "access" else None
                mode = "trunk" if mode_text == "trunk" else ("access" if mode_text == "access" else mode_text)
                description = match.group("description").strip() or None
                normalized = self.normalize_interface(interface)
                results[normalized] = InterfaceStatus(
                    interface=interface,
                    normalized_interface=normalized,
                    mode=mode,
                    access_vlan=access_vlan,
                    admin_state=match.group("status").strip(),
                    link_state=match.group("reason").strip(),
                    description=description,
                    raw_line=line,
                )
                last_interface_key = normalized
                continue

            if last_interface_key and results.get(last_interface_key):
                continuation = stripped.strip()
                if continuation and not continuation.startswith("-"):
                    current_description = results[last_interface_key].description or ""
                    joined = f"{current_description} {continuation}".strip()
                    results[last_interface_key].description = joined or None

        return results

    def normalize_interface(self, interface: str) -> str:
        return normalize_snr_s5_interface(interface)

    def summary(self) -> str:
        return "SNR S5xxx driver (eNOS-style CLI) with MAC lookup and interface brief parsing."


def normalize_snr_s5_mac(mac_address: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_snr_s5_cli_mac(normalized_mac: str) -> str:
    groups = [normalized_mac[index : index + 4] for index in range(0, 12, 4)]
    return ".".join(groups)


def normalize_snr_s5_interface(interface: str) -> str:
    normalized = interface.strip().lower().replace(" ", "")
    replacements = (
        ("tengigabitethernet", "xe"),
        ("xge", "xe"),
        ("gigabitethernet", "ge"),
        ("ethernet", "eth"),
        ("vlan", "vlan"),
    )
    for source, target in replacements:
        if normalized.startswith(source):
            return normalized.replace(source, target, 1)
    return normalized


def format_snr_s5_cli_interface(interface: str) -> str:
    normalized = normalize_snr_s5_interface(interface)
    return normalized


def extract_snr_s5_vlan_mac_from_version(output: str) -> str | None:
    for line in output.splitlines():
        if "vlan mac" not in line.casefold():
            continue
        mac_match = re.search(
            r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})",
            line,
        )
        if not mac_match:
            continue
        try:
            normalize_snr_s5_mac(mac_match.group(1))
        except ValueError:
            continue
        return mac_match.group(1)
    return None


def _parse_snr_s5_mac_lines(
    output: str,
    *,
    wanted_mac: str | None = None,
    wanted_interface: str | None = None,
) -> list[MacTableEntry]:
    entries: list[MacTableEntry] = []
    for line in output.splitlines():
        match = MAC_LINE_RE.match(line.rstrip())
        if not match:
            continue
        parsed_mac = normalize_snr_s5_mac(match.group("mac"))
        if wanted_mac and parsed_mac != wanted_mac:
            continue
        parsed_interface = match.group("interface")
        if wanted_interface and normalize_snr_s5_interface(parsed_interface) != wanted_interface:
            continue
        entries.append(
            MacTableEntry(
                vlan_id=int(match.group("vlan")),
                mac_address=match.group("mac"),
                interface=parsed_interface,
                entry_type=match.group("entry_type"),
                raw_line=line,
            )
        )
    return entries
