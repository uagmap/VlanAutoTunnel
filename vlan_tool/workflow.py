from __future__ import annotations

from vlan_tool.models import AppConfig, ProvisioningRequest
from vlan_tool.resolver import SwitchResolver
from vlan_tool.vendors import get_driver


def build_plan(config: AppConfig, request: ProvisioningRequest) -> list[str]:
    resolver = SwitchResolver(config)
    destination_switch = resolver.resolve(request.destination_switch)
    auto_l3_switch, auto_l3_reason = resolver.resolve_matched_l3(destination_switch)
    l3_source = "user input"
    if request.l3_switch:
        l3_switch = resolver.resolve(request.l3_switch)
    else:
        if not auto_l3_switch:
            raise LookupError(
                "Unable to auto-match L3 from destination switch. "
                "Provide --l3 explicitly for this topology."
            )
        l3_switch = auto_l3_switch
        l3_source = f"auto ({auto_l3_reason})"
    l3_driver = get_driver(l3_switch.vendor)
    destination_driver = get_driver(destination_switch.vendor)

    lines = [
        f"L3 switch: {l3_switch.name} ({l3_switch.host}) via {l3_driver.vendor_key}",
        f"L3 selection source: {l3_source}",
        f"Destination switch: {destination_switch.name} ({destination_switch.host}) via {destination_driver.vendor_key}",
        f"Destination port: {request.destination_port}",
        f"Observed MAC: {request.target_mac or 'auto-discovered from destination port'}",
        f"VLAN description: {request.vlan_description or 'free (default)'}",
    ]
    if auto_l3_switch:
        lines.append(
            f"Auto-matched L3 from destination: {auto_l3_switch.name} ({auto_l3_switch.host}) [{auto_l3_reason}]"
        )
        if auto_l3_switch.host != l3_switch.host:
            lines.append(
                f"Note: requested L3 differs from auto-match ({l3_switch.host} vs {auto_l3_switch.host})."
            )
    else:
        lines.append(f"Auto-matched L3 from destination: n/a ({auto_l3_reason})")

    site_name = l3_switch.site or destination_switch.site
    if site_name and site_name in config.sites and config.sites[site_name].vlan_ranges:
        site = config.sites[site_name]
        ranges = ", ".join(f"{item.start}-{item.end}" for item in site.vlan_ranges) or "not set"
        lines.append(f"Candidate VLAN ranges for site {site.name}: {ranges}")
    elif config.vlan_ranges:
        ranges = ", ".join(f"{item.start}-{item.end}" for item in config.vlan_ranges)
        lines.append(f"Candidate VLAN ranges (global default): {ranges}")
    else:
        lines.append("Candidate VLAN ranges: not configured yet.")

    if request.requested_vlan is not None:
        lines.append(f"Requested VLAN override: {request.requested_vlan}")
        if not _vlan_in_ranges(request.requested_vlan, config.vlan_ranges):
            lines.append(
                "Note: requested VLAN is outside configured candidate ranges; explicit VLAN should still be used."
            )
    else:
        lines.append("Requested VLAN override: auto-select free VLAN")

    lines.extend(
        [
            "",
            "Planned workflow:",
            "1. Resolve the L3 and destination switches from inventory or Zabbix.",
            "2. Discover a target MAC on destination port when not explicitly provided.",
            "3. Connect to the L3 switch with Netmiko over Telnet and record the full session log.",
            (
                "4. Use requested VLAN directly and validate it across the path."
                if request.requested_vlan is not None
                else "4. Find a free VLAN in the configured working range or prepare to create a new VLAN if missing."
            ),
            "5. Trace the observed MAC address hop by hop using vendor-specific MAC table commands.",
            "6. Ensure the VLAN exists and is allowed on every trunk along the path.",
            "7. Destination access-port configuration can be added later; it is intentionally excluded from this dry-run step.",
        ]
    )

    return lines


def _vlan_in_ranges(vlan_id: int, ranges: list) -> bool:
    for item in ranges:
        if item.start <= vlan_id <= item.end:
            return True
    return False
