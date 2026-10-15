"""CLI: resolve — print Zabbix-resolved switch + matched L3."""

from __future__ import annotations

from vlan_tool.resolver import SwitchResolver


def run(config, query: str) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(query)
    print(f"Resolved: {switch.name}")
    print(f"Host: {switch.host}")
    print(f"Vendor: {switch.vendor}")
    matched_l3, l3_reason = resolver.resolve_matched_l3(switch)
    print(f"Matched L3: {f'{matched_l3.name} ({matched_l3.host})' if matched_l3 else 'not found'}")
    print(f"L3 match rule: {l3_reason}")
    return 0
