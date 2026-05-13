from __future__ import annotations

from vlan_tool.vendors.arista import AristaDriver
from vlan_tool.vendors.base import VendorDriver
from vlan_tool.vendors.bdcom import BDCOMDriver
from vlan_tool.vendors.cisco_ios import CiscoIOSDriver
from vlan_tool.vendors.eltex_mes import EltexMESDriver
from vlan_tool.vendors.snr import SNRDriver
from vlan_tool.vendors.snr_s5xxx import SNRS5xxxDriver


class GenericTelnetDriver(VendorDriver):
    vendor_key = "generic_telnet"

    def summary(self) -> str:
        return "Generic Telnet fallback; use it for connection tests and raw session logging."


_DRIVERS = {
    "arista": AristaDriver(),
    "arista_eos": AristaDriver(),
    "bdcom": BDCOMDriver(),
    "cisco_ios": CiscoIOSDriver(),
    "eltex_mes": EltexMESDriver(),
    "snr": SNRDriver(),
    "snr_s5xxx": SNRS5xxxDriver(),
    "generic_telnet": GenericTelnetDriver(),
}


def get_driver(vendor: str | None) -> VendorDriver:
    if not vendor:
        return _DRIVERS["generic_telnet"]
    return _DRIVERS.get(vendor, _DRIVERS["generic_telnet"])
