from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from vlan_tool.models import FreeVlanResult, InterfaceStatus, MacTableEntry, VlanRange
from vlan_tool.session import SwitchSession


@dataclass(slots=True)
class DriverCapabilities:
    mac_lookup: bool = False
    mac_lookup_by_interface: bool = False
    interface_inventory: bool = False
    free_vlan_search: bool = False
    provisioning: bool = False


class VendorDriver(ABC):
    vendor_key = "generic_telnet"
    capabilities = DriverCapabilities()

    def session_setup_commands(self) -> list[str]:
        return []

    def probe_commands(self) -> list[str]:
        return ["show version"]

    def prepare_session(self, session: SwitchSession) -> None:
        for command in self.session_setup_commands():
            session.run_timing(command)

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
