from __future__ import annotations

import ipaddress
import re

from vlan_tool.models import AppConfig, SwitchRecord

try:
    from pyzabbix import ZabbixAPI
    from pyzabbix import ZabbixAPIException
except ImportError:  # pragma: no cover - optional until dependencies are installed
    try:
        from pyzabbix.api import ZabbixAPI, ZabbixAPIException
    except ImportError:
        ZabbixAPI = None
        ZabbixAPIException = Exception


class SwitchResolver:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._inventory_index = {}
        self._l3_subnet_overrides: list[tuple[ipaddress.IPv4Network, str]] = []
        for switch in config.inventory:
            for name in switch.all_names:
                self._inventory_index[name.casefold()] = switch
        for rule in config.l3_mapping.overrides:
            try:
                network = ipaddress.ip_network(rule.subnet, strict=False)
            except ValueError:
                continue
            if not isinstance(network, ipaddress.IPv4Network):
                continue
            self._l3_subnet_overrides.append((network, rule.l3_ip))

    def resolve(self, query: str) -> SwitchRecord:
        direct_match = self._inventory_index.get(query.casefold())
        if direct_match:
            return direct_match

        if _is_ip_address(query):
            try:
                zabbix_ip_match = self._resolve_ip_from_zabbix(query)
            except RuntimeError:
                zabbix_ip_match = None
            if zabbix_ip_match:
                return zabbix_ip_match
            vendor = "cisco_ios" if query.startswith("10.1.1.") else "generic_telnet"
            return SwitchRecord(
                name=query,
                host=query,
                vendor=vendor,
                requires_enable=vendor == "cisco_ios",
            )

        zabbix_match = self._resolve_from_zabbix(query)
        if zabbix_match:
            return zabbix_match

        raise LookupError(f"Unable to resolve switch '{query}' from inventory or Zabbix.")

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
                    "but the L3 candidate was not found in Zabbix/inventory",
                )
            return resolved, f"configured override {source_subnet} -> {l3_ip}"

        derived_ip = derive_l3_ip_from_switch_ip(switch.host)
        if not derived_ip:
            return None, "no automatic L3 mapping rule matched this IP"

        if derived_ip == switch.host and switch.vendor == "cisco_ios":
            existing = self._resolve_existing_l3_candidate(derived_ip)
            if existing:
                return existing, "switch IP is already in L3 subnet (10.1.1.X)"
            return None, f"derived L3 candidate {derived_ip} was not found in Zabbix/inventory"

        resolved = self._resolve_existing_l3_candidate(derived_ip)
        if not resolved:
            return None, f"derived L3 candidate {derived_ip} was not found in Zabbix/inventory"
        return resolved, f"derived from {switch.host} via 10.7.X.Y -> 10.1.1.X"

    def _resolve_from_zabbix(self, query: str) -> SwitchRecord | None:
        if not self.config.zabbix.is_configured():
            return None

        if ZabbixAPI is None:
            raise RuntimeError(
                "pyzabbix is not installed. Install dependencies before using Zabbix resolution."
            )

        zabbix_url = _normalize_zabbix_base_url(self.config.zabbix.url)
        search_fields = _build_search_fields(self.config.zabbix.search_field)
        client = ZabbixAPI(zabbix_url)
        if not hasattr(client, "login"):
            raise RuntimeError(
                "Installed Zabbix client does not provide login(api_token/username,password). "
                "Install 'pyzabbix' (lukecyca/pyzabbix) in this environment."
            )
        try:
            _zabbix_login(client, self.config)
        except Exception as exc:
            raise RuntimeError(f"Zabbix authentication failed: {exc}") from exc

        try:
            hosts = _lookup_hosts(client, query, search_fields)
        except Exception as exc:
            raise RuntimeError(f"Zabbix host lookup failed: {exc}") from exc

        if not hosts:
            return None

        chosen = _pick_best_host(hosts, query)
        source_name = str(chosen.get("name") or chosen.get("host") or query)
        interface_ip = _extract_preferred_ip(chosen.get("interfaces", []))
        if not interface_ip:
            return None
        vendor = _infer_vendor_from_name(source_name)

        return SwitchRecord(
            name=source_name,
            host=interface_ip,
            vendor=vendor,
            aliases=[str(chosen.get("host") or query)],
            requires_enable=vendor == "cisco_ios",
            metadata={"zabbix_hostid": chosen.get("hostid")},
        )

    def _resolve_ip_from_zabbix(self, ip_address: str) -> SwitchRecord | None:
        if not self.config.zabbix.is_configured():
            return None
        if ZabbixAPI is None:
            raise RuntimeError(
                "pyzabbix is not installed. Install dependencies before using Zabbix resolution."
            )

        client = ZabbixAPI(_normalize_zabbix_base_url(self.config.zabbix.url))
        if not hasattr(client, "login"):
            raise RuntimeError(
                "Installed Zabbix client does not provide login(api_token/username,password). "
                "Install 'pyzabbix' (lukecyca/pyzabbix) in this environment."
            )
        try:
            _zabbix_login(client, self.config)
            interfaces = client.hostinterface.get(
                output=["interfaceid", "hostid", "ip", "dns", "main", "type"],
                filter={"ip": [ip_address]},
                selectHosts=["hostid", "host", "name"],
            )
        except Exception as exc:
            raise RuntimeError(f"Zabbix host lookup failed: {exc}") from exc

        candidates: list[dict] = []
        for interface in interfaces:
            if str(interface.get("ip") or "").strip() != ip_address:
                continue
            hosts = interface.get("hosts", [])
            if not hosts:
                continue
            host = hosts[0]
            candidates.append(
                {
                    "host": host,
                    "main": str(interface.get("main") or "0"),
                    "type": str(interface.get("type") or ""),
                    "ip": ip_address,
                }
            )

        if not candidates:
            return None

        chosen = sorted(
            candidates,
            key=lambda item: (
                item["main"] != "1",
                item["type"] != "1",
                str(item["host"].get("host") or "").casefold(),
            ),
        )[0]
        host = chosen["host"]
        source_name = str(host.get("name") or host.get("host") or ip_address)
        vendor = _infer_vendor_from_name(source_name)
        return SwitchRecord(
            name=source_name,
            host=ip_address,
            vendor=vendor,
            aliases=[str(host.get("host") or ip_address)],
            requires_enable=vendor == "cisco_ios",
            metadata={"zabbix_hostid": host.get("hostid")},
        )

    def _resolve_existing_l3_candidate(self, ip_address: str) -> SwitchRecord | None:
        inventory_match = self._resolve_ip_from_inventory(ip_address)
        if inventory_match:
            return inventory_match
        try:
            return self._resolve_ip_from_zabbix(ip_address)
        except RuntimeError:
            return None

    def _resolve_ip_from_inventory(self, ip_address: str) -> SwitchRecord | None:
        for switch in self.config.inventory:
            if switch.host == ip_address:
                return switch
        return None

    def _derive_l3_from_overrides(self, host: str) -> tuple[str, str] | None:
        if not self._l3_subnet_overrides:
            return None
        try:
            candidate_ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        if not isinstance(candidate_ip, ipaddress.IPv4Address):
            return None

        chosen_network: ipaddress.IPv4Network | None = None
        chosen_l3_ip: str | None = None
        for network, l3_ip in self._l3_subnet_overrides:
            if candidate_ip not in network:
                continue
            if chosen_network is None or network.prefixlen > chosen_network.prefixlen:
                chosen_network = network
                chosen_l3_ip = l3_ip
        if chosen_network is None or chosen_l3_ip is None:
            return None
        return chosen_l3_ip, str(chosen_network)


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
    if not interfaces:
        return None

    mgmt_prefix = "10.1.1."
    preferred = sorted(
        interfaces,
        key=lambda item: (
            not str(item.get("ip") or "").strip().startswith(mgmt_prefix),
            item.get("main") != "1",
            item.get("type") != "1",
        ),
    )
    for item in preferred:
        candidate = str(item.get("ip") or "").strip()
        if _is_ip_address(candidate):
            return candidate
    return None


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


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


def _lookup_hosts(client: ZabbixAPI, query: str, search_fields: list[str]) -> list[dict]:
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
    if merged:
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
        if len(text) < 3 or key in seen:
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

    score = 0
    if host_name == query_norm:
        score += 120
    if visible_name == query_norm:
        score += 115
    if host_name.startswith(query_norm):
        score += 40
    if visible_name.startswith(query_norm):
        score += 35
    if query_norm in host_name:
        score += 15
    if query_norm in visible_name:
        score += 12

    query_id = _extract_id_token(query_norm)
    if query_id and query_id not in host_tokens:
        score -= 200

    for token in query_tokens:
        if token not in host_tokens:
            continue
        if token.startswith("id") and token[2:].isdigit():
            score += 260
            continue
        if len(token) >= 8:
            score += 30
        elif len(token) >= 5:
            score += 18
        else:
            score += 10

    if preferred_ip and preferred_ip.startswith("10.1.1."):
        score += 25
    if preferred_ip:
        score += 5
    return score


def _extract_id_token(text: str) -> str | None:
    match = re.search(r"\bid\d{3,}\b", text.casefold())
    if not match:
        return None
    return match.group(0)


def _tokenize_search_text(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", text.casefold())
    return [token for token in tokens if len(token) >= 3]


def derive_l3_ip_from_switch_ip(host: str) -> str | None:
    if not _is_ip_address(host):
        return None
    if host.startswith("10.1.1."):
        return host

    octets = host.split(".")
    if len(octets) != 4:
        return None
    if octets[0] != "10" or octets[1] != "7":
        return None

    third_octet = octets[2]
    if not third_octet.isdigit():
        return None
    number = int(third_octet)
    if number < 0 or number > 255:
        return None
    return f"10.1.1.{number}"
