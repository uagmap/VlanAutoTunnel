"""Site conventions: addressing scheme and well-known VLANs.

The defaults below are placeholders for a typical ISP access network. Override
them in config.yaml:

site:
  access_prefix: "10.20."   # access switches live in <access_prefix>X.Y
  l3_prefix: "10.30.1."     # their L3 gateway is <l3_prefix>X (same X)
  management_vlan: 10       # VLAN where switch self-MACs are learned (path tracing)
  f_port_vlan: 20           # shared client VLAN for F* port descriptions
  f_port_alt_vlan: 21       # alternate shared VLAN (default for --vlan-alt)
"""

from __future__ import annotations

import ipaddress

ACCESS_PREFIX = "10.20."
L3_PREFIX = "10.30.1."
MANAGEMENT_VLAN = 10
F_PORT_VLAN = 20
F_PORT_ALT_VLAN = 21


def configure(raw: dict | None) -> None:
    # ponytail: module globals instead of threading a settings object through
    # every pure helper; load_config() calls this once per process.
    global ACCESS_PREFIX, L3_PREFIX, MANAGEMENT_VLAN, F_PORT_VLAN, F_PORT_ALT_VLAN
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError("Config key 'site' must be a mapping.")
    ACCESS_PREFIX = str(raw.get("access_prefix", ACCESS_PREFIX))
    L3_PREFIX = str(raw.get("l3_prefix", L3_PREFIX))
    MANAGEMENT_VLAN = int(raw.get("management_vlan", MANAGEMENT_VLAN))
    F_PORT_VLAN = int(raw.get("f_port_vlan", F_PORT_VLAN))
    F_PORT_ALT_VLAN = int(raw.get("f_port_alt_vlan", F_PORT_ALT_VLAN))
    for name, prefix in (("access_prefix", ACCESS_PREFIX), ("l3_prefix", L3_PREFIX)):
        if not prefix.endswith(".") or not all(part.isdigit() for part in prefix[:-1].split(".")):
            raise ValueError(f"site.{name} must look like '10.20.' (dotted octets ending with a dot).")


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def looks_like_l3_ip(host: str) -> bool:
    return is_ip_address(host) and host.startswith(L3_PREFIX)


def access_pool(host: str) -> int | None:
    """The X in <access_prefix>X.Y, or None when host is not an access-switch IP."""
    if not is_ip_address(host) or not host.startswith(ACCESS_PREFIX):
        return None
    return int(host[len(ACCESS_PREFIX):].split(".")[0])


def derive_l3_ip(host: str) -> str | None:
    """<access_prefix>X.Y -> <l3_prefix>X. L3 IPs map to themselves."""
    if looks_like_l3_ip(host):
        return host
    pool = access_pool(host)
    return None if pool is None else f"{L3_PREFIX}{pool}"


def l3_rule_text() -> str:
    return f"{ACCESS_PREFIX}X.Y -> {L3_PREFIX}X"
