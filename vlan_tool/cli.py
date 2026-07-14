from __future__ import annotations

import argparse

from vlan_tool.commands import deploy, find_vlan, plan, probe, resolve, trace_mac
from vlan_tool.config import load_config
from vlan_tool.models import ProvisioningRequest

try:
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
        ReadTimeout,
    )
except ImportError:  # pragma: no cover - optional until dependencies are installed
    class _NetmikoPlaceholderException(Exception):
        pass

    NetmikoAuthenticationException = _NetmikoPlaceholderException
    NetmikoTimeoutException = _NetmikoPlaceholderException
    ReadTimeout = _NetmikoPlaceholderException


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Terminal tool for VLAN tunnel automation across mixed-vendor switches."
    )
    parser.add_argument(
        "--nodebug",
        action="store_true",
        help=(
            "Quiet mode: hide live switch connect/command output. "
            "Still prints chosen VLAN and the change summary."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve_parser = subparsers.add_parser("resolve", help="Resolve a switch name or IP.")
    resolve_parser.add_argument("query", help="Switch name, alias, or IP.")

    probe_parser = subparsers.add_parser(
        "probe",
        help="Open a Telnet session, run vendor probe commands, and save a full session log.",
    )
    probe_parser.add_argument("switch", help="Switch name, alias, or IP.")
    probe_parser.add_argument(
        "--l3",
        dest="l3_switch",
        help=(
            "Optional L3 override for special topologies. "
            "If omitted, the tool derives L3 as 10.7.X.Y -> 10.1.1.X."
        ),
    )

    mac_parser = subparsers.add_parser(
        "mac",
        help="Look up a MAC address on a switch when the vendor driver supports it.",
    )
    mac_parser.add_argument("switch", help="Switch name, alias, or IP.")
    mac_parser.add_argument("mac", help="MAC address to search for.")

    free_vlan_parser = subparsers.add_parser(
        "find-vlan",
        help="Find the first free VLAN on an L3 switch using vendor-specific rules.",
    )
    free_vlan_parser.add_argument("switch", help="L3 switch name, alias, or IP.")

    plan_parser = subparsers.add_parser(
        "plan",
        help="Trace VLAN path live (destination-first) and report required changes (dry-run).",
    )
    _add_plan_arguments(plan_parser)

    deploy_parser = subparsers.add_parser(
        "deploy",
        help="Trace VLAN path live and apply required VLAN/tagging changes hop-by-hop.",
    )
    _add_plan_arguments(deploy_parser)

    return parser


def main() -> int:
    parser = build_parser()
    try:
        args = parser.parse_args()
        debug = not args.nodebug
        config = load_config()

        if args.command == "resolve":
            return resolve.run(config, args.query)
        if args.command == "probe":
            return probe.run(config, args.switch, args.l3_switch, debug=debug)
        if args.command == "mac":
            return trace_mac.run(config, args.switch, args.mac, debug=debug)
        if args.command == "find-vlan":
            return find_vlan.run(config, args.switch, debug=debug)
        if args.command == "plan":
            request = ProvisioningRequest(
                l3_switch=args.l3_switch,
                destination_switch=args.destination_switch,
                destination_port=args.destination_port,
                requested_vlan=args.vlan,
            )
            return plan.run(config, request, debug=debug)
        if args.command == "deploy":
            request = ProvisioningRequest(
                l3_switch=args.l3_switch,
                destination_switch=args.destination_switch,
                destination_port=args.destination_port,
                requested_vlan=args.vlan,
            )
            return deploy.run(config, request, debug=debug)

        parser.error(f"Unsupported command: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("Operation cancelled by user.")
        return 130
    except (NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout) as exc:
        print(
            "Error: Telnet command failed due to authentication/prompt timeout. "
            "Check credentials and review session log for prompt flow details."
        )
        print(f"Details: {exc}")
        return 1
    except (FileNotFoundError, LookupError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1


def _add_plan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "destination_switch",
        help="Destination switch name or IP.",
    )
    parser.add_argument(
        "destination_port",
        nargs="?",
        default=None,
        help=(
            "Optional destination switch port for client-MAC discovery. "
            "If omitted, tool uses L3 ARP for the destination switch IP."
        ),
    )
    parser.add_argument(
        "--l3",
        dest="l3_switch",
        help=(
            "Optional name/IP of L3 switch. "
            "If omitted, L3 is auto-matched from destination IP using 10.7.X.Y -> 10.1.1.X."
        ),
    )
    parser.add_argument(
        "--vlan",
        dest="vlan",
        type=int,
        help="Optional fixed VLAN ID (if omitted, tool auto-selects free VLAN).",
    )
