from __future__ import annotations

from dataclasses import dataclass

from vlan_tool.models import SwitchRecord


@dataclass(slots=True)
class HopReport:
    switch: SwitchRecord
    role: str
    uplink_interface: str | None = None
    downlink_interface: str | None = None
    neighbor_description: str | None = None
    neighbor_switch: SwitchRecord | None = None
    vlan_exists: bool | None = None
    uplink_tagged: bool | None = None
    downlink_tagged: bool | None = None
    session_log: str | None = None
    notes: list[str] = None
    actions: list[str] = None
    applied_actions: list[str] = None

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = []
        if self.actions is None:
            self.actions = []
        if self.applied_actions is None:
            self.applied_actions = []


def render_live_path_plan(
    *,
    destination_switch: SwitchRecord,
    destination_driver: str,
    destination_port: str | None,
    l3_switch: SwitchRecord,
    l3_driver: str,
    l3_source: str,
    auto_l3_switch: SwitchRecord | None,
    auto_l3_reason: str | None,
    chosen_vlan: int,
    chosen_vlan_reason: str,
    target_mac: str,
    target_mac_source: str,
    l3_trace_mac: str,
    hop_reports: list[HopReport],
    apply_requested: bool,
    executed_commands: int,
) -> list[str]:
    lines = [
        f"L3 switch: {l3_switch.name} ({l3_switch.host}) via {l3_driver}",
        f"L3 selection source: {l3_source}",
        f"Destination switch: {destination_switch.name} ({destination_switch.host}) via {destination_driver}",
        f"Destination MAC source: {target_mac_source}",
        f"Destination MAC: {target_mac}",
        f"L3 trace MAC: {l3_trace_mac}",
        f"Selected VLAN: {chosen_vlan} ({chosen_vlan_reason})",
        f"Execution mode: {'deploy' if apply_requested else 'dry-run'}",
    ]
    if auto_l3_switch and auto_l3_reason:
        lines.append(
            f"Auto-matched L3 reference: {auto_l3_switch.name} ({auto_l3_switch.host}) [{auto_l3_reason}]"
        )

    missing_actions = 0
    for index, hop in enumerate(hop_reports, start=1):
        lines.append("")
        lines.append(
            f"Hop {index} [{hop.role}] {hop.switch.name} ({hop.switch.host})"
        )
        if hop.session_log:
            lines.append(f"Session log: {hop.session_log}")
        if hop.uplink_interface:
            lines.append(f"Uplink interface (by L3 MAC): {hop.uplink_interface}")
        if hop.downlink_interface:
            lines.append(f"Downlink interface (by destination MAC): {hop.downlink_interface}")
        if hop.neighbor_description:
            lines.append(f"Downlink description: {hop.neighbor_description}")
        if hop.neighbor_switch:
            lines.append(f"Resolved next switch: {hop.neighbor_switch.name} ({hop.neighbor_switch.host})")
        if hop.vlan_exists is not None:
            lines.append(f"VLAN exists: {'yes' if hop.vlan_exists else 'no'}")
        if hop.uplink_tagged is not None:
            lines.append(f"VLAN tagged on uplink: {'yes' if hop.uplink_tagged else 'no'}")
        if hop.downlink_tagged is not None:
            lines.append(f"VLAN tagged on downlink: {'yes' if hop.downlink_tagged else 'no'}")
        for note in hop.notes:
            lines.append(f"Note: {note}")
        if hop.actions:
            missing_actions += len(hop.actions)
            for action in hop.actions:
                if apply_requested and action in hop.applied_actions:
                    lines.append(f"Applied change: {action}")
                else:
                    lines.append(f"Needs change: {action}")

    lines.append("")
    lines.append(f"Trace completed with {len(hop_reports)} hops.")
    if apply_requested:
        if missing_actions:
            lines.append(f"Deployment actions planned: {missing_actions}")
            lines.append(f"Deploy completed: {executed_commands} commands executed inline.")
        else:
            lines.append("No VLAN/tagging changes detected for traced path.")
    elif missing_actions:
        lines.append(f"Pending config actions detected: {missing_actions}")
    else:
        lines.append("No VLAN/tagging changes detected for traced path.")
    return lines
