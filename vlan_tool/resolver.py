"""Resolve switch name/IP -> SwitchRecord (Zabbix + L3 IP mapping)."""

from __future__ import annotations

import ipaddress
import re

from vlan_tool import site
from vlan_tool.models import AppConfig, SwitchRecord
from vlan_tool.naming import equipment_port_count, extract_id_token, infer_vendor_from_name, vendor_family
from vlan_tool.site import is_ip_address as _is_ip_address

try:
    from pyzabbix import ZabbixAPI
except ImportError:  # pragma: no cover - optional until dependencies are installed
    try:
        from pyzabbix.api import ZabbixAPI
    except ImportError:
        ZabbixAPI = None


class SwitchResolver:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._client = None
        # config.py already validated these as IPv4 networks.
        self._l3_subnet_overrides = [
            (ipaddress.ip_network(rule.subnet, strict=False), rule.l3_ip)
            for rule in config.l3_mapping.overrides
        ]

    def resolve(self, query: str) -> SwitchRecord:
        if _is_ip_address(query):
            try:
                zabbix_ip_match = self._resolve_ip_from_zabbix(query)
            except RuntimeError:
                zabbix_ip_match = None
            if zabbix_ip_match:
                return zabbix_ip_match
            vendor = "cisco_ios" if query.startswith(site.L3_PREFIX) else "generic_telnet"
            return SwitchRecord(
                name=query,
                host=query,
                vendor=vendor,
                requires_enable=vendor == "cisco_ios",
            )

        zabbix_match = self._resolve_from_zabbix(query)
        if zabbix_match:
            return zabbix_match

        raise LookupError(f"Unable to resolve switch '{query}' from Zabbix.")

    def resolve_candidates(self, query: str) -> list[SwitchRecord]:
        """Return every Zabbix candidate so contextual callers can rank safely."""
        if _is_ip_address(query):
            return [self.resolve(query)]

        records: list[SwitchRecord] = []
        for host in self._lookup_zabbix_hosts(query, include_partial_after_exact=True):
            record = self._switch_record_from_zabbix_host(host, fallback_name=query)
            if record:
                records.append(record)
        return records

    def resolve_matched_l3(
        self,
        switch: SwitchRecord,
        *,
        override: str | None = None,
    ) -> tuple[SwitchRecord | None, str]:
        if override:
            resolved = self.resolve(override)
            return resolved, f"manual override ({override})"

        override_match = self._derive_l3_from_overrides(switch.host)
        if override_match:
            l3_ip, source_subnet = override_match
            resolved = self._resolve_existing_l3_candidate(l3_ip)
            if not resolved:
                return (
                    None,
                    "configured L3 override "
                    f"{source_subnet} -> {l3_ip} matched {switch.host}, "
                    "but the L3 candidate was not found in Zabbix",
                )
            return resolved, f"configured override {source_subnet} -> {l3_ip}"

        derived_ip = site.derive_l3_ip(switch.host)
        if not derived_ip:
            return None, "no automatic L3 mapping rule matched this IP"

        resolved = self._resolve_existing_l3_candidate(derived_ip)
        if not resolved:
            return None, f"derived L3 candidate {derived_ip} was not found in Zabbix"
        if derived_ip == switch.host:
            return resolved, f"switch IP is already in L3 subnet ({site.L3_PREFIX}X)"
        return resolved, f"derived from {switch.host} via {site.l3_rule_text()}"

    def _resolve_from_zabbix(self, query: str) -> SwitchRecord | None:
        hosts = self._lookup_zabbix_hosts(query)
        if not hosts:
            return None

        chosen = _pick_best_host(hosts, query)
        if _score_host_match(chosen, query.casefold()) < 0:
            return None
        return self._switch_record_from_zabbix_host(chosen, fallback_name=query)

    def _zabbix_client(self):
        """Logged-in client, or None when Zabbix is disabled. Reused across lookups."""
        if not self.config.zabbix.is_configured():
            return None
        if self._client is not None:
            return self._client
        if ZabbixAPI is None:
            raise RuntimeError(
                "pyzabbix is not installed. Install dependencies before using Zabbix resolution."
            )
        client = ZabbixAPI(_normalize_zabbix_base_url(self.config.zabbix.url))
        try:
            _zabbix_login(client, self.config)
        except Exception as exc:
            raise RuntimeError(f"Zabbix authentication failed: {exc}") from exc
        self._client = client
        return client

    def _lookup_zabbix_hosts(
        self,
        query: str,
        *,
        include_partial_after_exact: bool = False,
    ) -> list[dict]:
        client = self._zabbix_client()
        if client is None:
            return []
        try:
            return _lookup_hosts(
                client,
                query,
                _build_search_fields(self.config.zabbix.search_field),
                include_partial_after_exact=include_partial_after_exact,
            )
        except Exception as exc:
            raise RuntimeError(f"Zabbix host lookup failed: {exc}") from exc

    @staticmethod
    def _switch_record_from_zabbix_host(
        host: dict,
        *,
        fallback_name: str,
        interface_ip: str | None = None,
    ) -> SwitchRecord | None:
        source_name = str(host.get("name") or host.get("host") or fallback_name)
        interface_ip = interface_ip or _extract_preferred_ip(host.get("interfaces", []))
        if not interface_ip:
            return None
        vendor = infer_vendor_from_name(source_name)

        return SwitchRecord(
            name=source_name,
            host=interface_ip,
            vendor=vendor,
            aliases=[str(host.get("host") or fallback_name)],
            requires_enable=vendor == "cisco_ios",
            metadata={"zabbix_hostid": host.get("hostid")},
        )

    def _resolve_ip_from_zabbix(self, ip_address: str) -> SwitchRecord | None:
        client = self._zabbix_client()
        if client is None:
            return None
        try:
            interfaces = client.hostinterface.get(
                output=["interfaceid", "hostid", "ip", "dns", "main", "type"],
                filter={"ip": [ip_address]},
                selectHosts=["hostid", "host", "name"],
            )
        except Exception as exc:
            raise RuntimeError(f"Zabbix host lookup failed: {exc}") from exc

        candidates = [
            interface
            for interface in interfaces
            if str(interface.get("ip") or "").strip() == ip_address and interface.get("hosts")
        ]
        if not candidates:
            return None

        chosen = min(
            candidates,
            key=lambda item: (
                str(item.get("main") or "0") != "1",
                str(item.get("type") or "") != "1",
                str(item["hosts"][0].get("host") or "").casefold(),
            ),
        )
        return self._switch_record_from_zabbix_host(
            chosen["hosts"][0], fallback_name=ip_address, interface_ip=ip_address
        )

    def _resolve_existing_l3_candidate(self, ip_address: str) -> SwitchRecord | None:
        try:
            return self._resolve_ip_from_zabbix(ip_address)
        except RuntimeError:
            return None

    def _derive_l3_from_overrides(self, host: str) -> tuple[str, str] | None:
        """Most specific configured override subnet containing host -> (l3_ip, subnet)."""
        try:
            candidate_ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        matches = [
            (network, l3_ip)
            for network, l3_ip in self._l3_subnet_overrides
            if candidate_ip.version == 4 and candidate_ip in network
        ]
        if not matches:
            return None
        network, l3_ip = max(matches, key=lambda item: item[0].prefixlen)
        return l3_ip, str(network)


def _zabbix_login(client: ZabbixAPI, config: AppConfig) -> None:
    if config.zabbix.api_token:
        try:
            client.login(api_token=config.zabbix.api_token)
            return
        except TypeError:
            # Compatibility fallback for older pyzabbix signatures.
            client.login(config.zabbix.api_token)
            return

    if not (config.zabbix.username and config.zabbix.password):
        raise RuntimeError("Zabbix username/password are missing.")

    try:
        client.login(username=config.zabbix.username, password=config.zabbix.password)
    except TypeError:
        # Compatibility fallback for older pyzabbix signatures.
        client.login(config.zabbix.username, config.zabbix.password)


def _normalize_zabbix_base_url(url: str | None) -> str:
    if not url:
        return ""
    normalized = url.rstrip("/")
    suffix = "/api_jsonrpc.php"
    if normalized.endswith(suffix):
        normalized = normalized[: -len(suffix)]
    return normalized


def _extract_preferred_ip(interfaces: list[dict]) -> str | None:
    preferred = sorted(
        interfaces or [],
        key=lambda item: (
            not str(item.get("ip") or "").strip().startswith(site.L3_PREFIX),
            item.get("main") != "1",
            item.get("type") != "1",
        ),
    )
    for item in preferred:
        candidate = str(item.get("ip") or "").strip()
        if _is_ip_address(candidate):
            return candidate
    return None


def _build_search_fields(primary_field: str) -> list[str]:
    fields = [primary_field.strip(), "host", "name"]
    result: list[str] = []
    seen = set()
    for field in fields:
        key = field.casefold()
        if not field or key in seen:
            continue
        seen.add(key)
        result.append(field)
    return result


def _lookup_hosts(
    client: ZabbixAPI,
    query: str,
    search_fields: list[str],
    *,
    include_partial_after_exact: bool = False,
) -> list[dict]:
    merged: dict[str, dict] = {}
    terms = _build_search_terms(query)
    common = {
        "output": ["host", "name", "hostid"],
        "selectInterfaces": ["ip", "dns", "type", "main"],
        "limit": 200,
    }

    # 1) Exact first for deterministic match if user passes full hostname.
    for field in search_fields:
        _merge_hosts(
            merged,
            client.host.get(
                **common,
                filter={field: [query]},
            ),
        )
    if merged and not include_partial_after_exact:
        return list(merged.values())

    # 2) Partial search on full query and extracted terms.
    for term in terms:
        search_payload = {field: term for field in search_fields}
        _merge_hosts(
            merged,
            client.host.get(
                **common,
                search=search_payload,
                searchByAny=True,
            ),
        )
        if merged:
            continue

        wildcard_payload = {field: f"*{term}*" for field in search_fields}
        _merge_hosts(
            merged,
            client.host.get(
                **common,
                search=wildcard_payload,
                searchByAny=True,
                searchWildcardsEnabled=True,
            ),
        )

    return list(merged.values())


def _merge_hosts(target: dict[str, dict], hosts: list[dict]) -> None:
    for host in hosts:
        host_id = str(host.get("hostid") or "").strip()
        if not host_id:
            continue
        if host_id not in target:
            target[host_id] = host


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
        if (len(text) < 3 and not _is_port_shape_token(text)) or key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _pick_best_host(hosts: list[dict], query: str) -> dict:
    query_norm = query.casefold()
    ranked = sorted(
        hosts,
        key=lambda host: (
            -_score_host_match(host, query_norm),
            str(host.get("host") or "").casefold(),
        ),
    )
    return ranked[0]


def _score_host_match(host: dict, query_norm: str) -> int:
    host_name = str(host.get("host") or "").casefold()
    visible_name = str(host.get("name") or "").casefold()
    preferred_ip = _extract_preferred_ip(host.get("interfaces", []))
    host_tokens = set(_tokenize_search_text(f"{host_name} {visible_name}"))
    query_tokens = _tokenize_search_text(query_norm)
    query_family = vendor_family(infer_vendor_from_name(query_norm))
    candidate_families = {
        vendor_family(infer_vendor_from_name(name))
        for name in (host_name, visible_name)
        if name
    }
    query_ports = equipment_port_count(query_norm)
    candidate_ports = {
        count
        for name in (host_name, visible_name)
        if name and (count := equipment_port_count(name)) is not None
    }
    query_canonical = _canonical_search_text(query_norm)
    host_canonical = _canonical_search_text(host_name)
    visible_canonical = _canonical_search_text(visible_name)

    score = 0
    if host_name == query_norm:
        score += 120
    if visible_name == query_norm:
        score += 115
    if query_canonical and query_canonical in {host_canonical, visible_canonical}:
        score += 300
    if host_name.startswith(query_norm):
        score += 40
    if visible_name.startswith(query_norm):
        score += 35
    if query_norm in host_name:
        score += 15
    if query_norm in visible_name:
        score += 12

    query_id = extract_id_token(query_norm)
    if query_id and query_id not in host_tokens:
        score -= 200

    if query_family:
        if query_family in candidate_families:
            score += 100
        else:
            return -1_000

    if query_ports is not None and candidate_ports:
        if query_ports not in candidate_ports:
            return -1_000
        score += 100

    for token in query_tokens:
        if token not in host_tokens:
            continue
        if token.startswith("id") and token[2:].isdigit():
            score += 260
            continue
        if _is_port_shape_token(token):
            score += 60
            continue
        if len(token) >= 8:
            score += 30
        elif len(token) >= 5:
            score += 18
        else:
            score += 10

    if preferred_ip and preferred_ip.startswith(site.L3_PREFIX) and query_family in {None, "cisco"}:
        score += 25
    if preferred_ip:
        score += 5
    return score


def _tokenize_search_text(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", text.casefold())
    return [token for token in tokens if len(token) >= 3 or _is_port_shape_token(token)]


def _canonical_search_text(text: str) -> str:
    return "-".join(re.findall(r"[a-z0-9]+", text.casefold()))


def _is_port_shape_token(token: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:t|tx|te|fx|s|p|g|x)", token.casefold()))
