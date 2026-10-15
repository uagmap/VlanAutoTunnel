"""CLI: plan + deploy — shared live-path runner (dry-run vs apply)."""

from __future__ import annotations

from dataclasses import replace

from vlan_tool.models import ProvisioningRequest
from vlan_tool.provisioning.discovery import discover_target_mac
from vlan_tool.provisioning.live_path import execute_live_path_plan
from vlan_tool.trace_panel import live_trace_ui, ui_print


def run(
    config,
    request: ProvisioningRequest,
    *,
    apply_changes: bool,
    debug: bool = True,
) -> int:
    with live_trace_ui():
        effective_request = request
        if not request.target_mac and request.destination_port:
            discovered, discovery_source = discover_target_mac(
                config,
                request,
                debug=debug,
            )
            if not discovered:
                raise RuntimeError(
                    "Unable to auto-discover a MAC on the requested destination port "
                    "and switch self-MAC fallback also failed. "
                    "Verify the port or provide a reachable MAC."
                )
            effective_request = replace(request, target_mac=discovered)
            ui_print(f"Auto-discovered target MAC ({discovery_source}): {discovered}")
            if "no MAC on port" in discovery_source:
                ui_print(
                    f"Note: no client MAC on {request.destination_port}; "
                    "using switch self-MAC for path tracing. Requested port will still be tagged."
                )

        for line in execute_live_path_plan(
            config,
            effective_request,
            apply_changes=apply_changes,
            debug=debug,
        ):
            ui_print(line)
    return 0
