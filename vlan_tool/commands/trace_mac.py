from __future__ import annotations

from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver


def run(config, switch_query: str, mac_address: str, *, debug: bool = True) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(switch_query)
    driver = get_driver(switch.vendor)

    if not driver.capabilities.mac_lookup:
        print(
            f"Vendor driver '{driver.vendor_key}' does not support MAC lookup yet. "
            "Add command samples for this platform first."
        )
        return 1

    with open_switch_session(config, switch, debug=debug) as session:
        driver.prepare_session(session)
        interface_statuses = {}
        if driver.capabilities.interface_inventory:
            interface_statuses = driver.get_interface_statuses(session)
        entries = driver.lookup_mac(session, mac_address)
        print(f"Session log: {session.session_log}")
        if not entries:
            print(f"No entries found for {mac_address} on {switch.name}.")
            return 1

        for entry in entries:
            vlan_text = entry.vlan_id if entry.vlan_id is not None else "n/a"
            line = f"VLAN {vlan_text} -> {entry.interface} ({entry.entry_type or 'unknown'})"
            details = interface_statuses.get(driver.normalize_interface(entry.interface))
            if details:
                extras: list[str] = []
                if details.mode == "access" and details.access_vlan is not None:
                    extras.append(f"access vlan {details.access_vlan}")
                elif details.mode:
                    extras.append(details.mode)
                if details.link_state:
                    extras.append(f"link {details.link_state}")
                if details.description:
                    extras.append(details.description)
                if extras:
                    line = f"{line} | {' | '.join(extras)}"
            print(line)
        return 0
