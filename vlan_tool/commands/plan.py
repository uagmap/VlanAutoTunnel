"""CLI: plan — dry-run live path (report required VLAN/tag changes, apply nothing)."""

from __future__ import annotations

from dataclasses import replace

from vlan_tool.models import ProvisioningRequest
from vlan_tool.provisioning.discovery import discover_target_mac
from vlan_tool.provisioning.live_path import execute_live_path_plan


def run(
    config,
    request: ProvisioningRequest,
    *,
    debug: bool = True,
) -> int:
    effective_request = request
    if not request.target_mac and request.destination_port:
        discovered, discovery_source = discover_target_mac(
            config,
            request,
            debug=debug,
        )
        if not discovered:
            raise RuntimeError(
                "Unable to auto-discover destination MAC from requested destination port. "
                "Verify the port and MAC visibility."
            )
        effective_request = replace(request, target_mac=discovered)
        print(f"Auto-discovered target MAC ({discovery_source}): {discovered}")

    for line in execute_live_path_plan(
        config,
        effective_request,
        apply_changes=False,
        debug=debug,
    ):
        print(line)
    return 0
