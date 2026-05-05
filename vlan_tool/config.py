from __future__ import annotations

import os
import re
import ipaddress
from pathlib import Path

from vlan_tool.models import (
    AppConfig,
    L3MappingSettings,
    L3SubnetOverride,
    SiteDefinition,
    SwitchRecord,
    TelnetSettings,
    VlanRange,
    ZabbixSettings,
)


DEFAULT_CONFIG_PATH = Path("config.yaml")
ENV_REFERENCE_RE = re.compile(r"^\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}$")


def load_config(path: Path | None = None) -> AppConfig:
    import yaml

    config_path = (path or DEFAULT_CONFIG_PATH).resolve()
    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}. "
            f"Copy config.example.yaml to {config_path.name} and adjust it."
        )

    _load_dotenv_file(config_path.parent)

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Configuration root must be a mapping.")

    telnet_raw = raw.get("telnet", {})
    zabbix_raw = raw.get("zabbix", {})
    l3_mapping_raw = raw.get("l3_mapping", {}) or {}
    inventory_raw = raw.get("inventory", []) or []
    sites_raw = raw.get("sites", []) or []
    vlan_ranges_raw = raw.get("vlan_ranges", []) or []

    if not isinstance(l3_mapping_raw, dict):
        raise ValueError("Config key 'l3_mapping' must be a mapping.")
    if not isinstance(inventory_raw, list):
        raise ValueError("Config key 'inventory' must be a list.")
    if not isinstance(sites_raw, list):
        raise ValueError("Config key 'sites' must be a list.")
    if not isinstance(vlan_ranges_raw, list):
        raise ValueError("Config key 'vlan_ranges' must be a list.")

    telnet = TelnetSettings(
        username=_read_secret_setting(
            section=telnet_raw,
            value_key="username",
            env_key="username_env",
            fallback_env_keys=("VLAN_TELNET_USERNAME", "TELNET_USERNAME"),
            required=True,
            setting_name="telnet.username",
        ),
        password=_read_secret_setting(
            section=telnet_raw,
            value_key="password",
            env_key="password_env",
            fallback_env_keys=("VLAN_TELNET_PASSWORD", "TELNET_PASSWORD"),
            required=True,
            setting_name="telnet.password",
        ),
        secret=_read_secret_setting(
            section=telnet_raw,
            value_key="secret",
            env_key="secret_env",
            fallback_env_keys=("VLAN_TELNET_SECRET", "TELNET_SECRET"),
            required=False,
            setting_name="telnet.secret",
        ),
        port=int(telnet_raw.get("port", 23)),
        timeout_seconds=int(telnet_raw.get("timeout_seconds", 20)),
        global_delay_factor=float(telnet_raw.get("global_delay_factor", 1.5)),
    )

    zabbix = ZabbixSettings(
        url=_read_secret_setting(
            section=zabbix_raw,
            value_key="url",
            env_key="url_env",
            fallback_env_keys=("VLAN_ZABBIX_URL", "ZABBIX_URL"),
            required=False,
            setting_name="zabbix.url",
            allow_plaintext=True,
        ),
        username=_read_secret_setting(
            section=zabbix_raw,
            value_key="username",
            env_key="username_env",
            fallback_env_keys=("VLAN_ZABBIX_USERNAME", "ZABBIX_USERNAME"),
            required=False,
            setting_name="zabbix.username",
            allow_plaintext=False,
        ),
        password=_read_secret_setting(
            section=zabbix_raw,
            value_key="password",
            env_key="password_env",
            fallback_env_keys=("VLAN_ZABBIX_PASSWORD", "ZABBIX_PASSWORD"),
            required=False,
            setting_name="zabbix.password",
            allow_plaintext=False,
        ),
        api_token=_read_secret_setting(
            section=zabbix_raw,
            value_key="api_token",
            env_key="api_token_env",
            fallback_env_keys=("VLAN_ZABBIX_API_TOKEN", "ZABBIX_API_TOKEN"),
            required=False,
            setting_name="zabbix.api_token",
            allow_plaintext=False,
        ),
        search_field=str(zabbix_raw.get("search_field", "host")),
        enabled=bool(zabbix_raw.get("enabled", False)),
    )
    if zabbix.enabled and not (zabbix.url and (zabbix.api_token or (zabbix.username and zabbix.password))):
        raise ValueError(
            "Zabbix is enabled but credentials are missing. "
            "Use either API token (VLAN_ZABBIX_API_TOKEN) or username/password "
            "(VLAN_ZABBIX_USERNAME + VLAN_ZABBIX_PASSWORD), plus VLAN_ZABBIX_URL."
        )

    inventory = [_parse_switch(item) for item in inventory_raw]
    parsed_sites = [_parse_site(item) for item in sites_raw]
    sites = {site.name: site for site in parsed_sites}
    vlan_ranges = _parse_vlan_ranges(vlan_ranges_raw, context="vlan_ranges")
    l3_mapping = L3MappingSettings(
        overrides=_parse_l3_overrides(l3_mapping_raw.get("overrides", [])),
    )

    return AppConfig(
        path=config_path,
        log_directory=(config_path.parent / raw.get("log_directory", "logs")).resolve(),
        telnet=telnet,
        zabbix=zabbix,
        l3_mapping=l3_mapping,
        vlan_ranges=vlan_ranges,
        inventory=inventory,
        sites=sites,
        vendors=raw.get("vendors", {}),
    )


def _parse_switch(raw: dict) -> SwitchRecord:
    if not isinstance(raw, dict):
        raise ValueError("Each inventory entry must be a mapping.")

    metadata = {
        key: value
        for key, value in raw.items()
        if key
        not in {
            "name",
            "host",
            "vendor",
            "device_type",
            "role",
            "site",
            "aliases",
            "requires_enable",
        }
    }
    return SwitchRecord(
        name=str(raw["name"]),
        host=str(raw["host"]),
        vendor=str(raw["vendor"]),
        device_type=_optional_str(raw.get("device_type")),
        role=_optional_str(raw.get("role")),
        site=_optional_str(raw.get("site")),
        aliases=[str(alias) for alias in raw.get("aliases", [])],
        requires_enable=bool(raw.get("requires_enable", False)),
        metadata=metadata,
    )


def _parse_site(raw: dict) -> SiteDefinition:
    if not isinstance(raw, dict):
        raise ValueError("Each site entry must be a mapping.")

    return SiteDefinition(
        name=str(raw["name"]),
        core_switches=[str(name) for name in raw.get("core_switches", [])],
        vlan_ranges=_parse_vlan_ranges(raw.get("vlan_ranges", []), context=f"site:{raw['name']}.vlan_ranges"),
    )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _parse_vlan_ranges(raw_ranges: list, *, context: str) -> list[VlanRange]:
    ranges: list[VlanRange] = []
    for index, item in enumerate(raw_ranges):
        if not isinstance(item, dict):
            raise ValueError(f"Each item in '{context}' must be a mapping. Failed at index {index}.")
        start = int(item["start"])
        end = int(item["end"])
        if start > end:
            raise ValueError(
                f"Invalid VLAN range in '{context}' at index {index}: start ({start}) is greater than end ({end})."
            )
        ranges.append(VlanRange(start=start, end=end))
    return ranges


def _parse_l3_overrides(raw_overrides: object) -> list[L3SubnetOverride]:
    if raw_overrides is None:
        return []
    if not isinstance(raw_overrides, list):
        raise ValueError("Config key 'l3_mapping.overrides' must be a list.")

    overrides: list[L3SubnetOverride] = []
    for index, item in enumerate(raw_overrides):
        if not isinstance(item, dict):
            raise ValueError(
                "Each item in 'l3_mapping.overrides' must be a mapping. "
                f"Failed at index {index}."
            )
        if "subnet" not in item or "l3_ip" not in item:
            raise ValueError(
                "Each item in 'l3_mapping.overrides' must contain "
                f"'subnet' and 'l3_ip'. Failed at index {index}."
            )

        subnet_raw = str(item["subnet"]).strip()
        l3_ip_raw = str(item["l3_ip"]).strip()
        try:
            network = ipaddress.ip_network(subnet_raw, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"Invalid subnet '{subnet_raw}' in 'l3_mapping.overrides' at index {index}."
            ) from exc
        if network.version != 4:
            raise ValueError(
                f"Only IPv4 subnets are supported in 'l3_mapping.overrides'. "
                f"Failed at index {index} ({subnet_raw})."
            )

        try:
            l3_ip = ipaddress.ip_address(l3_ip_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid l3_ip '{l3_ip_raw}' in 'l3_mapping.overrides' at index {index}."
            ) from exc
        if l3_ip.version != 4:
            raise ValueError(
                f"Only IPv4 l3_ip is supported in 'l3_mapping.overrides'. "
                f"Failed at index {index} ({l3_ip_raw})."
            )

        overrides.append(
            L3SubnetOverride(
                subnet=str(network),
                l3_ip=str(l3_ip),
            )
        )
    return overrides


def _read_secret_setting(
    *,
    section: dict,
    value_key: str,
    env_key: str,
    fallback_env_keys: tuple[str, ...],
    required: bool,
    setting_name: str,
    allow_plaintext: bool = False,
) -> str | None:
    env_name = _optional_str(section.get(env_key))
    if env_name:
        value = _optional_str(os.getenv(env_name))
        if value is not None:
            return value
        if required:
            raise ValueError(
                f"Missing required environment variable '{env_name}' for '{setting_name}'."
            )

    raw_value = _optional_str(section.get(value_key))
    if raw_value:
        env_match = ENV_REFERENCE_RE.match(raw_value)
        if env_match:
            ref_name = env_match.group("name")
            value = _optional_str(os.getenv(ref_name))
            if value is not None:
                return value
            if required:
                raise ValueError(
                    f"Missing required environment variable '{ref_name}' referenced by '{setting_name}'."
                )
        else:
            if allow_plaintext:
                return raw_value
            raise ValueError(
                f"Plaintext value is not allowed for '{setting_name}'. "
                f"Use '{env_key}' or a ${{ENV_VAR}} reference instead."
            )

    for fallback_name in fallback_env_keys:
        value = _optional_str(os.getenv(fallback_name))
        if value is not None:
            return value

    if required:
        raise ValueError(
            f"Required setting '{setting_name}' is missing. "
            f"Set '{env_key}' in config or one of: {', '.join(fallback_env_keys)}."
        )
    return None


def _load_dotenv_file(config_directory: Path) -> None:
    env_path = config_directory / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue

        value = _normalize_env_value(raw_value.strip())
        # .env values are authoritative for this workspace run.
        os.environ[key] = value


def _normalize_env_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        inner = value[1:-1]
        if value[0] == '"':
            return inner.encode("utf-8").decode("unicode_escape")
        return inner
    return value
