from __future__ import annotations

import argparse
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vlan_tool.config import DEFAULT_CONFIG_PATH, load_config
from vlan_tool.models import AppConfig, SwitchRecord
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver


DEFAULT_EXCLUDED_L3 = ("10.1.1.17", "10.1.1.254")
DEFAULT_OUTPUT = Path("l3_mapping_overrides.txt")
L3_VLAN = 111
MGMT_PREFIX = "10.1.1."


@dataclass(slots=True)
class L3Candidate:
    ip: str
    host: str
    name: str
    hostid: str | None


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    config = load_config(args.config)
    if not config.zabbix.is_configured():
        raise RuntimeError(
            "Zabbix is not configured/enabled in config. "
            "Enable zabbix and provide credentials before running this helper."
        )

    excluded = {item.strip() for item in args.exclude_l3 if item.strip()}
    l3_candidates = _discover_l3_candidates_from_zabbix(config, debug=args.debug)
    l3_candidates = [item for item in l3_candidates if item.ip not in excluded]

    if args.debug:
        print(f"[debug] L3 candidates discovered (after excludes): {len(l3_candidates)}")

    subnet_to_l3_ips: dict[str, set[str]] = {}
    subnet_sources: dict[str, set[str]] = {}
    failures: list[str] = []
    scanned = 0

    for candidate in l3_candidates:
        scanned += 1
        try:
            _scan_l3_vlan111(
                config=config,
                candidate=candidate,
                subnet_to_l3_ips=subnet_to_l3_ips,
                subnet_sources=subnet_sources,
                debug=args.debug,
            )
        except Exception as exc:
            failures.append(f"{candidate.ip} ({candidate.name}): {exc}")
            if args.debug:
                print(f"[debug] Failed scanning {candidate.ip}: {exc}")

    clean_overrides: dict[str, str] = {}
    conflicts: dict[str, list[str]] = {}
    for subnet, l3_ips in subnet_to_l3_ips.items():
        if len(l3_ips) == 1:
            clean_overrides[subnet] = next(iter(l3_ips))
        else:
            conflicts[subnet] = sorted(l3_ips, key=_ip_sort_key)

    output_text = _render_output(
        clean_overrides=clean_overrides,
        conflicts=conflicts,
        subnet_sources=subnet_sources,
        excluded=sorted(excluded, key=_ip_sort_key),
        scanned=scanned,
        total=len(l3_candidates),
        failures=failures,
    )
    args.output.write_text(output_text, encoding="utf-8")

    print(f"Saved overrides snippet to: {args.output.resolve()}")
    print(f"L3 scanned: {scanned}/{len(l3_candidates)}")
    print(f"Overrides generated: {len(clean_overrides)}")
    print(f"Conflicts: {len(conflicts)}")
    print(f"Failures: {len(failures)}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate l3_mapping.overrides suggestions by scanning L3 switches "
            "from Zabbix (10.1.1.x) and parsing 'show run int vlan 111'."
        )
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to main YAML config file (default: config.yaml).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output text file (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--exclude-l3",
        action="append",
        default=list(DEFAULT_EXCLUDED_L3),
        help=(
            "L3 management IP to skip. Can be passed multiple times. "
            "Defaults include 10.1.1.17 and 10.1.1.254."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debug output while scanning.",
    )
    return parser


def _discover_l3_candidates_from_zabbix(config: AppConfig, *, debug: bool) -> list[L3Candidate]:
    client = _build_zabbix_client(config)
    _zabbix_login(client, config)

    # First try search/wildcard retrieval (fast path).
    query_variants = [
        {"search": {"ip": "10.1.1."}, "searchByAny": True},
        {"search": {"ip": "10.1.1.*"}, "searchByAny": True, "searchWildcardsEnabled": True},
        {"search": {"ip": "10.1.1"}, "searchByAny": True},
    ]

    interfaces: list[dict] = []
    for variant in query_variants:
        result = client.hostinterface.get(
            output=["interfaceid", "hostid", "ip", "dns", "main", "type"],
            selectHosts=["hostid", "host", "name"],
            limit=5000,
            **variant,
        )
        if result:
            interfaces = result
            if debug:
                print(f"[debug] hostinterface.get variant matched {len(result)} rows: {variant}")
            break

    # Fallback: exact lookup sweep for 10.1.1.0-255.
    if not interfaces:
        if debug:
            print("[debug] search variants returned no rows; running exact IP sweep fallback")
        for last_octet in range(0, 256):
            ip = f"10.1.1.{last_octet}"
            result = client.hostinterface.get(
                output=["interfaceid", "hostid", "ip", "dns", "main", "type"],
                selectHosts=["hostid", "host", "name"],
                filter={"ip": [ip]},
                limit=20,
            )
            if result:
                interfaces.extend(result)

    best_by_ip: dict[str, tuple[tuple[int, int, str], L3Candidate]] = {}
    for interface in interfaces:
        ip = str(interface.get("ip") or "").strip()
        if not ip.startswith(MGMT_PREFIX):
            continue
        if not _is_ipv4(ip):
            continue

        hosts = interface.get("hosts", [])
        if not hosts:
            continue
        host = hosts[0]

        candidate = L3Candidate(
            ip=ip,
            host=str(host.get("host") or ""),
            name=str(host.get("name") or host.get("host") or ip),
            hostid=str(host.get("hostid") or interface.get("hostid") or "") or None,
        )
        rank = (
            0 if str(interface.get("main") or "0") == "1" else 1,
            0 if str(interface.get("type") or "") == "1" else 1,
            candidate.name.casefold(),
        )

        current = best_by_ip.get(ip)
        if current is None or rank < current[0]:
            best_by_ip[ip] = (rank, candidate)

    return sorted((item[1] for item in best_by_ip.values()), key=lambda row: _ip_sort_key(row.ip))


def _scan_l3_vlan111(
    *,
    config: AppConfig,
    candidate: L3Candidate,
    subnet_to_l3_ips: dict[str, set[str]],
    subnet_sources: dict[str, set[str]],
    debug: bool,
) -> None:
    switch = SwitchRecord(
        name=candidate.name,
        host=candidate.ip,
        vendor=_infer_vendor_from_name(candidate.name),
        aliases=[candidate.host] if candidate.host and candidate.host != candidate.name else [],
        requires_enable=True,
    )

    with open_switch_session(
        config,
        switch,
        confirm_connect=False,
        confirm_commands=False,
        debug=debug,
    ) as session:
        driver = get_driver(switch.vendor)
        driver.prepare_session(session)
        output = session.run_show(f"show run int vlan {L3_VLAN}")

    if _looks_like_invalid(output):
        raise RuntimeError("command failed: show run int vlan 111")

    l3_octet = int(candidate.ip.split(".")[3])
    irregular_subnets = _extract_irregular_10_7_subnets(output=output, expected_octet=l3_octet)
    for subnet in irregular_subnets:
        subnet_to_l3_ips.setdefault(subnet, set()).add(candidate.ip)
        subnet_sources.setdefault(subnet, set()).add(candidate.name)


def _extract_irregular_10_7_subnets(*, output: str, expected_octet: int) -> set[str]:
    subnets: set[str] = set()
    pattern = re.compile(
        r"^\s*ip\s+address\s+10\.7\.(?P<third>\d{1,3})\.(?P<fourth>\d{1,3})\s+"
        r"(?P<mask>\d{1,3}(?:\.\d{1,3}){3})(?:\s+secondary)?\s*$",
        flags=re.IGNORECASE | re.MULTILINE,
    )
    for match in pattern.finditer(output):
        third_octet = int(match.group("third"))
        if third_octet < 0 or third_octet > 255:
            continue
        mask = match.group("mask")
        prefix = _mask_to_prefix(mask)
        # Only /24 management pools are relevant for switch-assignment overrides.
        if prefix != 24:
            continue
        if third_octet == expected_octet:
            continue
        subnets.add(f"10.7.{third_octet}.0/24")
    return subnets


def _render_output(
    *,
    clean_overrides: dict[str, str],
    conflicts: dict[str, list[str]],
    subnet_sources: dict[str, set[str]],
    excluded: list[str],
    scanned: int,
    total: int,
    failures: list[str],
) -> str:
    lines: list[str] = []
    lines.append("# Auto-generated L3 override suggestions")
    lines.append(f"# L3 scanned: {scanned}/{total}")
    lines.append(f"# Excluded L3 IPs: {', '.join(excluded) if excluded else '-'}")
    lines.append("")
    lines.append("l3_mapping:")
    lines.append("  overrides:")

    if clean_overrides:
        for subnet in sorted(clean_overrides.keys(), key=_subnet_sort_key):
            l3_ip = clean_overrides[subnet]
            lines.append(f"    - subnet: {subnet}")
            lines.append(f"      l3_ip: {l3_ip}")
    else:
        lines.append("    []")

    if conflicts:
        lines.append("")
        lines.append("# Conflicts detected (same subnet mapped to multiple L3 IPs).")
        lines.append("# Review manually before adding to config.yaml.")
        for subnet in sorted(conflicts.keys(), key=_subnet_sort_key):
            l3_ips = ", ".join(conflicts[subnet])
            sources = ", ".join(sorted(subnet_sources.get(subnet, set())))
            lines.append(f"# conflict: {subnet} -> [{l3_ips}]")
            if sources:
                lines.append(f"#   seen on: {sources}")

    if failures:
        lines.append("")
        lines.append("# Scan failures")
        for failure in failures:
            lines.append(f"# - {failure}")

    lines.append("")
    return "\n".join(lines)


def _build_zabbix_client(config: AppConfig) -> Any:
    ZabbixAPI = _import_zabbix_api()
    base = _normalize_zabbix_base_url(config.zabbix.url or "")
    if not base:
        raise RuntimeError("Zabbix URL is empty in config.")
    return ZabbixAPI(base)


def _zabbix_login(client: Any, config: AppConfig) -> None:
    token = (config.zabbix.api_token or "").strip()
    if token:
        try:
            client.login(api_token=token)
            return
        except TypeError:
            client.login(token)
            return

    username = (config.zabbix.username or "").strip()
    password = (config.zabbix.password or "").strip()
    if not username or not password:
        raise RuntimeError("Zabbix auth is missing (need token or username/password).")
    try:
        client.login(username=username, password=password)
    except TypeError:
        client.login(username, password)


def _normalize_zabbix_base_url(url: str) -> str:
    normalized = url.strip().rstrip("/")
    suffix = "/api_jsonrpc.php"
    if normalized.endswith(suffix):
        normalized = normalized[: -len(suffix)]
    return normalized


def _import_zabbix_api():
    try:
        from pyzabbix import ZabbixAPI  # type: ignore
    except ImportError:
        try:
            from pyzabbix.api import ZabbixAPI  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "pyzabbix is not installed. Install dependencies before running this helper."
            ) from exc
    return ZabbixAPI


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _looks_like_invalid(output: str) -> bool:
    text = output.casefold()
    return "invalid input" in text or "unknown command" in text or "incomplete command" in text


def _infer_vendor_from_name(hostname: str) -> str:
    token = hostname.strip().casefold()
    model = token.split(".", 1)[0]
    if model.startswith("snr"):
        return "snr"
    if model.startswith("mes"):
        return "eltex_mes"
    if "arista" in model or model.startswith("dcs-") or re.match(r"^a\d{4}", model):
        return "arista"
    if model.startswith("c") or "cisco" in model:
        return "cisco_ios"
    return "generic_telnet"


def _ip_sort_key(value: str) -> tuple[int, int, int, int]:
    try:
        ip = ipaddress.IPv4Address(value)
        parts = str(ip).split(".")
        return tuple(int(part) for part in parts)  # type: ignore[return-value]
    except Exception:
        return (999, 999, 999, 999)


def _subnet_sort_key(subnet: str) -> tuple[int, int, int, int, int]:
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            return (999, 999, 999, 999, 999)
        base = str(network.network_address).split(".")
        return (
            int(base[0]),
            int(base[1]),
            int(base[2]),
            int(base[3]),
            network.prefixlen,
        )
    except Exception:
        return (999, 999, 999, 999, 999)


def _mask_to_prefix(mask: str) -> int | None:
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    except Exception:
        return None
    return int(network.prefixlen)


if __name__ == "__main__":
    raise SystemExit(main())
