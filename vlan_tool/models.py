from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TelnetSettings:
    username: str
    password: str
    secret: str | None = None
    port: int = 23
    timeout_seconds: int = 20
    global_delay_factor: float = 1.5


@dataclass(slots=True)
class ZabbixSettings:
    url: str | None = None
    username: str | None = None
    password: str | None = None
    api_token: str | None = None
    search_field: str = "host"
    enabled: bool = False

    def is_configured(self) -> bool:
        return bool(self.enabled and self.url and (self.api_token or (self.username and self.password)))


@dataclass(slots=True)
class VlanRange:
    start: int
    end: int


@dataclass(slots=True)
class SiteDefinition:
    name: str
    core_switches: list[str] = field(default_factory=list)
    vlan_ranges: list[VlanRange] = field(default_factory=list)


@dataclass(slots=True)
class SwitchRecord:
    name: str
    host: str
    vendor: str
    device_type: str | None = None
    role: str | None = None
    site: str | None = None
    aliases: list[str] = field(default_factory=list)
    requires_enable: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def all_names(self) -> list[str]:
        return [self.name, *self.aliases]


@dataclass(slots=True)
class AppConfig:
    path: Path
    log_directory: Path
    telnet: TelnetSettings
    zabbix: ZabbixSettings
    vlan_ranges: list[VlanRange] = field(default_factory=list)
    inventory: list[SwitchRecord] = field(default_factory=list)
    sites: dict[str, SiteDefinition] = field(default_factory=dict)
    vendors: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class ProvisioningRequest:
    l3_switch: str | None
    destination_switch: str
    destination_port: str
    target_mac: str | None = None
    requested_vlan: int | None = None


@dataclass(slots=True)
class MacTableEntry:
    vlan_id: int | None
    mac_address: str
    interface: str
    entry_type: str | None = None
    raw_line: str | None = None


@dataclass(slots=True)
class InterfaceStatus:
    interface: str
    normalized_interface: str
    mode: str | None = None
    access_vlan: int | None = None
    admin_state: str | None = None
    link_state: str | None = None
    description: str | None = None
    raw_line: str | None = None


@dataclass(slots=True)
class FreeVlanResult:
    vlan_id: int
    reason: str
    details: str
