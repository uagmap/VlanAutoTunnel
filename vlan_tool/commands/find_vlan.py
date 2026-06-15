from __future__ import annotations

from vlan_tool.provisioning.discovery import looks_like_l3_ip, select_vlan_ranges
from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver


def run(
    config,
    switch_query: str,
    *,
    confirm_steps: bool = False,
    debug: bool = False,
) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(switch_query)
    driver = get_driver(switch.vendor)
    if not driver.capabilities.free_vlan_search:
        print(
            f"Vendor driver '{driver.vendor_key}' does not support free VLAN search yet."
        )
        return 1

    ranges = select_vlan_ranges(config, switch)
    if not ranges:
        print("No VLAN ranges configured. Add 'vlan_ranges' in config.yaml.")
        return 1

    if not looks_like_l3_ip(switch.host):
        print(
            f"Warning: {switch.host} does not match expected L3 pattern 10.1.1.X. Continuing anyway."
        )

    with open_switch_session(
        config,
        switch,
        confirm_connect=confirm_steps,
        confirm_commands=confirm_steps,
        debug=debug,
    ) as session:
        driver.prepare_session(session)
        result = driver.find_free_vlan(session, ranges)
        print(f"Session log: {session.session_log}")
        if result is None:
            print("No free VLAN found in configured ranges.")
            return 1
        print(f"Found free VLAN: {result.vlan_id}")
        print(f"Reason: {result.reason}")
        print(f"Details: {result.details}")
        return 0
