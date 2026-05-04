from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

try:
    from pyzabbix import ZabbixAPI
except ImportError:
    from pyzabbix.api import ZabbixAPI  # type: ignore


DEFAULT_DOTENV = Path(".env")


@dataclass(slots=True)
class HostCandidate:
    hostid: str
    host: str
    name: str
    interface_ip: str | None
    interface_dns: str | None
    match_score: int


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    _load_dotenv(args.dotenv)
    zapi = _connect_zabbix()

    if args.command == "hostname-to-ip":
        return _cmd_hostname_to_ip(
            zapi=zapi,
            query=args.hostname,
            mgmt_prefix=args.mgmt_prefix,
            limit=args.limit,
            exact=args.exact,
        )

    if args.command == "ip-to-hostname":
        return _cmd_ip_to_hostname(zapi=zapi, ip=args.ip)

    if args.command == "search":
        return _cmd_search(
            zapi=zapi,
            query=args.query,
            mgmt_prefix=args.mgmt_prefix,
            limit=args.limit,
        )

    parser.error(f"Unsupported command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve switch hostnames and management IPs using Zabbix API (pyzabbix)."
    )
    parser.add_argument(
        "--dotenv",
        type=Path,
        default=DEFAULT_DOTENV,
        help="Path to .env file (default: .env).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    h2i = subparsers.add_parser(
        "hostname-to-ip",
        help="Resolve hostname (or partial hostname) to management IP.",
    )
    h2i.add_argument("hostname", help="Host query (exact or partial).")
    h2i.add_argument(
        "--mgmt-prefix",
        "--prefix",
        default="10.1.1.",
        help="Preferred management IP prefix (default: 10.1.1.).",
    )
    h2i.add_argument("--limit", type=int, default=20, help="Max returned candidates.")
    h2i.add_argument(
        "--exact",
        action="store_true",
        help="Require exact host/name match instead of partial search.",
    )

    i2h = subparsers.add_parser(
        "ip-to-hostname",
        help="Resolve management IP to Zabbix host/name.",
    )
    i2h.add_argument("ip", help="Management IP, e.g. 10.1.1.137")

    search = subparsers.add_parser(
        "search",
        help="Search hosts by partial name and print ranked candidates.",
    )
    search.add_argument("query", help="Partial hostname query.")
    search.add_argument(
        "--mgmt-prefix",
        "--prefix",
        default="10.1.1.",
        help="Preferred management IP prefix (default: 10.1.1.).",
    )
    search.add_argument("--limit", type=int, default=20, help="Max returned candidates.")

    return parser


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def _connect_zabbix() -> ZabbixAPI:
    zabbix_url = _required_env("VLAN_ZABBIX_URL")
    zapi = ZabbixAPI(_normalize_zabbix_url(zabbix_url))

    token = os.getenv("VLAN_ZABBIX_API_TOKEN", "").strip()
    user = os.getenv("VLAN_ZABBIX_USERNAME", "").strip()
    password = os.getenv("VLAN_ZABBIX_PASSWORD", "").strip()

    if token:
        try:
            zapi.login(api_token=token)
        except TypeError:
            zapi.login(token)
        return zapi

    if not user or not password:
        raise RuntimeError(
            "Missing Zabbix auth. Set VLAN_ZABBIX_API_TOKEN or VLAN_ZABBIX_USERNAME + VLAN_ZABBIX_PASSWORD."
        )

    try:
        zapi.login(username=user, password=password)
    except TypeError:
        zapi.login(user, password)
    return zapi


def _cmd_hostname_to_ip(
    *,
    zapi: ZabbixAPI,
    query: str,
    mgmt_prefix: str,
    limit: int,
    exact: bool,
) -> int:
    candidates = _search_candidates(
        zapi=zapi,
        query=query,
        mgmt_prefix=mgmt_prefix,
        limit=limit,
        exact=exact,
    )
    if not candidates:
        print("No matching hosts found.")
        return 1

    best = candidates[0]
    if not best.interface_ip:
        print(f"Best host found, but no interface IP: host={best.host} name={best.name}")
        return 1

    print(best.interface_ip)
    if len(candidates) > 1:
        print("")
        print("Other candidates:")
        _print_candidates(candidates[1:])
    return 0


def _cmd_ip_to_hostname(*, zapi: ZabbixAPI, ip: str) -> int:
    interfaces = zapi.hostinterface.get(
        output=["interfaceid", "hostid", "ip", "dns", "main", "type", "useip"],
        filter={"ip": [ip]},
        selectHosts=["hostid", "host", "name", "status"],
    )

    rows = []
    for iface in interfaces:
        if str(iface.get("ip", "")).strip() != ip:
            continue
        hosts = iface.get("hosts", [])
        if not hosts:
            continue
        host = hosts[0]
        rows.append(
            (
                host.get("hostid", ""),
                host.get("host", ""),
                host.get("name", ""),
                iface.get("ip", ""),
                iface.get("dns", ""),
                iface.get("main", "0"),
                iface.get("type", ""),
            )
        )

    if not rows:
        print("No host found for this IP.")
        return 1

    rows.sort(key=lambda item: (item[5] != "1", item[6] != "1", str(item[1]).casefold()))
    best = rows[0]
    print(f"host={best[1]} name={best[2]} ip={best[3]} dns={best[4]}")
    if len(rows) > 1:
        print("")
        print("Other matches:")
        for row in rows[1:]:
            print(f"- host={row[1]} name={row[2]} ip={row[3]} dns={row[4]}")
    return 0


def _cmd_search(*, zapi: ZabbixAPI, query: str, mgmt_prefix: str, limit: int) -> int:
    candidates = _search_candidates(
        zapi=zapi,
        query=query,
        mgmt_prefix=mgmt_prefix,
        limit=limit,
        exact=False,
    )
    if not candidates:
        print("No matching hosts found.")
        return 1

    _print_candidates(candidates)
    return 0


def _search_candidates(
    *,
    zapi: ZabbixAPI,
    query: str,
    mgmt_prefix: str,
    limit: int,
    exact: bool,
) -> list[HostCandidate]:
    query_norm = query.casefold()
    merged = _lookup_hosts(zapi=zapi, query=query, limit=limit, exact=exact)

    candidates: list[HostCandidate] = []
    for host in merged.values():
        host_id = str(host.get("hostid", ""))
        host_key = str(host.get("host", ""))
        host_name = str(host.get("name", ""))
        iface_ip, iface_dns = _pick_interface(host.get("interfaces", []), mgmt_prefix)
        score = _score_match(query_norm, host_key, host_name, iface_ip, mgmt_prefix)
        candidates.append(
            HostCandidate(
                hostid=host_id,
                host=host_key,
                name=host_name,
                interface_ip=iface_ip,
                interface_dns=iface_dns,
                match_score=score,
            )
        )

    candidates.sort(
        key=lambda item: (
            -item.match_score,
            item.interface_ip is None,
            item.host.casefold(),
        )
    )
    return candidates[:limit]


def _lookup_hosts(*, zapi: ZabbixAPI, query: str, limit: int, exact: bool) -> dict[str, dict]:
    merged: dict[str, dict] = {}
    fields = ("host", "name")
    params = {
        "output": ["hostid", "host", "name", "status"],
        "selectInterfaces": ["interfaceid", "ip", "dns", "main", "type", "useip"],
        "limit": max(limit, 200),
    }

    if exact:
        for field in fields:
            hosts = zapi.host.get(**params, filter={field: [query]})
            _merge_hosts(merged, hosts)
        return merged

    terms = _build_search_terms(query)
    for term in terms:
        hosts = zapi.host.get(
            **params,
            search={field: term for field in fields},
            searchByAny=True,
        )
        _merge_hosts(merged, hosts)
        if merged:
            continue

        hosts = zapi.host.get(
            **params,
            search={field: f"*{term}*" for field in fields},
            searchByAny=True,
            searchWildcardsEnabled=True,
        )
        _merge_hosts(merged, hosts)

    return merged


def _merge_hosts(target: dict[str, dict], hosts: list[dict]) -> None:
    for host in hosts:
        hostid = str(host.get("hostid", "")).strip()
        if not hostid:
            continue
        if hostid not in target:
            target[hostid] = host


def _build_search_terms(query: str) -> list[str]:
    terms = [query.strip()]
    token = []
    for char in query:
        if char.isalnum():
            token.append(char)
            continue
        if token:
            terms.append("".join(token))
            token = []
    if token:
        terms.append("".join(token))

    deduped: list[str] = []
    seen: set[str] = set()
    for item in terms:
        text = item.strip()
        key = text.casefold()
        if len(text) < 3 or key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _pick_interface(interfaces: list[dict], mgmt_prefix: str) -> tuple[str | None, str | None]:
    if not interfaces:
        return None, None

    ordered = sorted(
        interfaces,
        key=lambda iface: (
            str(iface.get("ip", "")).startswith(mgmt_prefix) is False,
            iface.get("main") != "1",
            iface.get("type") != "1",
        ),
    )
    best = ordered[0]
    ip_raw = str(best.get("ip", "")).strip()
    ip = ip_raw if _looks_like_ip(ip_raw) else None
    dns = str(best.get("dns", "")).strip() or None
    return ip, dns


def _looks_like_ip(value: str) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        number = int(part)
        if number < 0 or number > 255:
            return False
    return True


def _score_match(query: str, host: str, name: str, ip: str | None, mgmt_prefix: str) -> int:
    host_norm = host.casefold()
    name_norm = name.casefold()
    score = 0
    if host_norm == query:
        score += 100
    if name_norm == query:
        score += 95
    if host_norm.startswith(query):
        score += 35
    if name_norm.startswith(query):
        score += 30
    if query in host_norm:
        score += 10
    if query in name_norm:
        score += 8
    if ip and ip.startswith(mgmt_prefix):
        score += 20
    if ip:
        score += 2
    return score


def _normalize_zabbix_url(url: str) -> str:
    normalized = url.strip().rstrip("/")
    if normalized.endswith("/api_jsonrpc.php"):
        normalized = normalized[: -len("/api_jsonrpc.php")]
    return normalized


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _print_candidates(candidates: list[HostCandidate]) -> None:
    for item in candidates:
        print(
            f"- host={item.host} name={item.name} ip={item.interface_ip or '-'} "
            f"dns={item.interface_dns or '-'} score={item.match_score}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
