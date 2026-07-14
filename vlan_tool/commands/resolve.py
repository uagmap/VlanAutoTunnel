"""CLI: resolve — print Zabbix-resolved switch + matched L3."""

from __future__ import annotations

from vlan_tool.resolver import SwitchResolver


def run(config, query: str) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(query)
    print(f"Resolved: {switch.name}")
    print(f"Host: {switch.host}")
    print(f"Vendor: {switch.vendor}")
    print(f"Device type: {switch.device_type or 'auto'}")
    print(f"Role: {switch.role or 'n/a'}")
    matched_l3, l3_reason = resolver.resolve_matched_l3(switch)
    if matched_l3:
        print(f"Matched L3: {matched_l3.name} ({matched_l3.host})")
        print(f"L3 match rule: {l3_reason}")
    else:
        print("Matched L3: not found")
        print(f"L3 match rule: {l3_reason}")
    return 0
