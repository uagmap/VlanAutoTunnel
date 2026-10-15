"""VendorDriver base class + capability flags. One subclass per platform under vendors/."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import re

from vlan_tool.models import FreeVlanResult, InterfaceStatus, MacTableEntry, VlanRange
from vlan_tool.session import SwitchSession

# Dotted (aabb.ccdd.eeff) or separated (aa:bb:cc:dd:ee:ff / aa-bb-...) MAC; group(1) is the MAC text.
MAC_RE = re.compile(r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})")
PASSWORD_PROMPT_RE = re.compile(r"(?:password|passcode)\s*[:>]\s*$", re.IGNORECASE)
# Generic CLI rejection markers. Drivers whose devices print "Error: ..." use CLI_ERROR_STRICT_RE.
_CLI_ERRORS = r"invalid input|unknown command|unrecognized command|incomplete command"
CLI_ERROR_RE = re.compile(f"(?:{_CLI_ERRORS})", re.IGNORECASE)
CLI_ERROR_STRICT_RE = re.compile(f"(?:{_CLI_ERRORS}|error:)", re.IGNORECASE)


@dataclass(slots=True)
class DriverCapabilities:
    mac_lookup: bool = False
    mac_lookup_by_interface: bool = False
    interface_inventory: bool = False
    free_vlan_search: bool = False


class VendorDriver(ABC):
    vendor_key = "generic_telnet"
    capabilities = DriverCapabilities()

    def prepare_session(self, session: SwitchSession) -> None:
        """Hook: enable, pager off, mode changes. Default: nothing."""

    def lookup_mac(self, session: SwitchSession, mac_address: str) -> list[MacTableEntry]:
        raise NotImplementedError(
            f"MAC lookup is not implemented for vendor '{self.vendor_key}' yet."
        )

    def lookup_interface_macs(self, session: SwitchSession, interface: str) -> list[MacTableEntry]:
        raise NotImplementedError(
            f"Interface MAC lookup is not implemented for vendor '{self.vendor_key}' yet."
        )

    def get_interface_statuses(self, session: SwitchSession) -> dict[str, InterfaceStatus]:
        raise NotImplementedError(
            f"Interface parsing is not implemented for vendor '{self.vendor_key}' yet."
        )

    def normalize_interface(self, interface: str) -> str:
        return interface.strip().casefold()

    def find_free_vlan(self, session: SwitchSession, vlan_ranges: list[VlanRange]) -> FreeVlanResult | None:
        raise NotImplementedError(
            f"Free VLAN search is not implemented for vendor '{self.vendor_key}' yet."
        )

    @abstractmethod
    def summary(self) -> str:
        raise NotImplementedError


def compact_mac(mac_address: str) -> str:
    """Strict 12-hex lowercase form; raises ValueError on anything else."""
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        raise ValueError(f"Unsupported MAC address format: {mac_address}")
    return compact.casefold()


def format_mac(compact: str, *, sep: str, group: int, upper: bool = False) -> str:
    """'aabbccddeeff' -> 'aabb.ccdd.eeff' (sep='.', group=4) or 'AA:BB:...' (sep=':', group=2, upper)."""
    text = sep.join(compact[index:index + group] for index in range(0, 12, group))
    return text.upper() if upper else text


def mac_on_line_containing(output: str, needle: str) -> str | None:
    """First MAC on the first line whose lowercase text contains needle ('show version' scraping)."""
    for line in output.splitlines():
        if needle in line.casefold():
            match = MAC_RE.search(line)
            if match:
                return match.group(1)
    return None


def enter_enable_mode(session: SwitchSession) -> None:
    """Send `enable`; answer the password prompt with the configured secret if asked."""
    enable_output = session.run_timing("enable", confirm_label="enter enable mode")
    if PASSWORD_PROMPT_RE.search(enable_output):
        secret = str(getattr(session.connection, "secret", "") or "")
        session.run_timing(secret, confirm_label="send enable password", sensitive=True)


def first_accepted(session: SwitchSession, commands: tuple[str, ...], error_re: re.Pattern[str] = CLI_ERROR_RE) -> None:
    """Run commands in order until one is not rejected (best-effort pager/width setup)."""
    for command in commands:
        if not error_re.search(session.run_timing(command)):
            break
