"""CLI argument parsing and command dispatch (main.py entry)."""

from __future__ import annotations

import argparse

from vlan_tool import site
from vlan_tool.commands import client_check, find_vlan, mac, plan_deploy, probe, resolve
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
    l3_help = (
        "Optional L3 override for special topologies. "
        "If omitted, L3 is derived from the switch IP (config: site.access_prefix -> site.l3_prefix)."
    )

    resolve_parser = subparsers.add_parser("resolve", help="Resolve a switch name or IP.")
    resolve_parser.add_argument("query", help="Switch name, alias, or IP.")

    probe_parser = subparsers.add_parser(
        "probe",
        help="Open a Telnet session, run vendor probe commands, and save a full session log.",
    )
    probe_parser.add_argument("switch", help="Switch name, alias, or IP.")
    probe_parser.add_argument("--l3", dest="l3_switch", help=l3_help)

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

    client_check_parser = subparsers.add_parser(
        "check",
        help="Run layered client access checks on a switch port (link, MAC, L3, optional ARP).",
    )
    client_check_parser.add_argument("switch", help="Access switch name, alias, or IP.")
    client_check_parser.add_argument(
        "port",
        help=(
            "Client-facing port, or GPON ONT as pon/ont "
            "(e.g. Gi0/24, 0/63, 1/41, 2/52)."
        ),
    )
    client_check_parser.add_argument(
        "--client-ip",
        help="Optional client IP (if omitted, resolved from L3 ARP using port MAC).",
    )
    client_check_parser.add_argument("--l3", dest="l3_switch", help=l3_help)
    client_check_parser.add_argument(
        "--vlan-alt",
        type=int,
        default=None,
        help="Alternate shared VLAN for F* port descriptions (default: config site.f_port_alt_vlan).",
    )

    for name, help_text in (
        ("plan", "Trace VLAN path live (destination-first) and report required changes (dry-run)."),
        ("deploy", "Trace VLAN path live and apply required VLAN/tagging changes hop-by-hop."),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("destination_switch", help="Destination switch name or IP.")
        sub.add_argument(
            "destination_port",
            nargs="?",
            default=None,
            help=(
                "Optional destination switch port for client-MAC discovery. "
                "If omitted, tool uses L3 ARP for the destination switch IP."
            ),
        )
        sub.add_argument("--l3", dest="l3_switch", help=l3_help)
        sub.add_argument(
            "--vlan",
            dest="vlan",
            type=int,
            help="Optional fixed VLAN ID (if omitted, tool auto-selects free VLAN).",
        )

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
            return mac.run(config, args.switch, args.mac, debug=debug)
        if args.command == "find-vlan":
            return find_vlan.run(config, args.switch, debug=debug)
        if args.command == "check":
            return client_check.run(
                config,
                args.switch,
                args.port,
                client_ip=args.client_ip,
                l3_switch=args.l3_switch,
                vlan_alt=args.vlan_alt if args.vlan_alt is not None else site.F_PORT_ALT_VLAN,
                debug=debug,
            )
        # plan / deploy
        request = ProvisioningRequest(
            l3_switch=args.l3_switch,
            destination_switch=args.destination_switch,
            destination_port=args.destination_port,
            requested_vlan=args.vlan,
        )
        return plan_deploy.run(config, request, apply_changes=args.command == "deploy", debug=debug)
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
