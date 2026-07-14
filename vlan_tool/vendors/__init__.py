from __future__ import annotations

from vlan_tool.vendors.arista import AristaDriver
from vlan_tool.vendors.base import VendorDriver
from vlan_tool.vendors.bdcom import BDCOMDriver, BDCOMGPONDriver
from vlan_tool.vendors.cisco_ios import CiscoIOSDriver
from vlan_tool.vendors.eltex_mes import EltexMESDriver
from vlan_tool.vendors.fd160 import FD160Driver
from vlan_tool.vendors.gr_ep_olt1 import GREPOLT1Driver
from vlan_tool.vendors.gr_ep_olt2 import GREPOLT2Driver
from vlan_tool.vendors.ltp import LTPDriver
from vlan_tool.vendors.snr import SNRDriver
from vlan_tool.vendors.snr_s2970 import SNRS2970Driver
from vlan_tool.vendors.snr_s5xxx import SNRS5xxxDriver


class GenericTelnetDriver(VendorDriver):
    vendor_key = "generic_telnet"

    def summary(self) -> str:
        return "Generic Telnet fallback; use it for connection tests and raw session logging."


_DRIVERS = {
    "arista": AristaDriver(),
    "arista_eos": AristaDriver(),
    "bdcom": BDCOMDriver(),
    "bdcom_gpon": BDCOMGPONDriver(),
    "cisco_ios": CiscoIOSDriver(),
    "eltex_mes": EltexMESDriver(),
    "fd160": FD160Driver(),
    "gr_ep_olt1": GREPOLT1Driver(),
    "gr_ep_olt2": GREPOLT2Driver(),
    "ltp": LTPDriver(),
    "snr": SNRDriver(),
    "snr_s2970": SNRS2970Driver(),
    "snr_s5xxx": SNRS5xxxDriver(),
    "generic_telnet": GenericTelnetDriver(),
}


def get_driver(vendor: str | None) -> VendorDriver:
    if not vendor:
        return _DRIVERS["generic_telnet"]
    return _DRIVERS.get(vendor, _DRIVERS["generic_telnet"])
