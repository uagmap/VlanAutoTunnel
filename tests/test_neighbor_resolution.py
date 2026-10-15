from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from vlan_tool.models import MacTableEntry, SwitchRecord
from vlan_tool.provisioning.ltp import process_ltp_intermediate_hop
from vlan_tool.naming import (
    canonical_neighbor_name,
    equipment_family,
    equipment_location,
    equipment_port_count,
    extract_id_token,
)
from vlan_tool.provisioning.neighbor import resolve_neighbor_from_description, score_neighbor_match
from vlan_tool.resolver import (
    SwitchResolver,
    _build_search_terms,
    _lookup_hosts,
    _pick_best_host,
)


def _switch(name: str, host: str, vendor: str, hostid: str) -> SwitchRecord:
    return SwitchRecord(
        name=name,
        host=host,
        vendor=vendor,
        aliases=[name],
        metadata={"zabbix_hostid": hostid},
    )


class _Resolver:
    def __init__(self, candidates: list[SwitchRecord]) -> None:
        self.candidates = candidates

    def resolve(self, _query: str) -> SwitchRecord:
        raise LookupError

    def resolve_candidates(self, _query: str) -> list[SwitchRecord]:
        return self.candidates


class _LtpDriver:
    vendor_key = "ltp"

    def normalize_interface(self, interface: str) -> str:
        return interface.strip().casefold()

    def lookup_mac(self, _session, _mac: str) -> list[MacTableEntry]:
        return [
            MacTableEntry(
                vlan_id=10,
                mac_address="00:11:22:33:44:55",
                interface="front-port 1",
            )
        ]


class _LtpSession:
    session_log = "ltp.log"

    def __init__(self) -> None:
        self.commands: list[str] = []

    def run_timing(self, command: str) -> str:
        self.commands.append(command)
        if command == "show running-config":
            return "\n".join(
                [
                    "interface front-port 1",
                    ' description "SNR-S2985G-24T.Somewhere"',
                    "exit",
                ]
            )
        return ""


class NeighborResolutionTests(unittest.TestCase):
    def test_ltp_missing_hyphen_in_model_still_matches(self) -> None:
        # L3 desc: LTP4x.Centralnyj_1530 (no hyphen, wavelength suffix)
        # inventory: LTP-4X-Centralnyj
        candidate = _switch("LTP-4X-Centralnyj", "10.20.4.22", "ltp", "1")
        source = _switch("c9500.core.example.net", "10.30.1.4", "cisco_ios", "2")

        self.assertEqual(
            canonical_neighbor_name("LTP4x.Centralnyj"),
            canonical_neighbor_name("LTP-4X-Centralnyj"),
        )
        score = score_neighbor_match(
            description="LTP4x.Centralnyj_1530",
            switch=candidate,
            source_switch=source,
        )
        self.assertGreaterEqual(score, 100)

        resolved = resolve_neighbor_from_description(
            _Resolver([candidate]),
            "LTP4x.Centralnyj_1530",
            source_switch=source,
        )
        self.assertEqual(resolved, candidate)

    def test_ltp_separator_drift_selects_ltp_not_same_site_l3(self) -> None:
        source = _switch("c4500.Plaza.example.net", "10.30.1.66", "cisco_ios", "1")
        wrong = source
        expected = _switch("LTP-4X-Plaza", "10.20.66.8", "ltp", "2")

        resolved = resolve_neighbor_from_description(
            _Resolver([wrong, expected]),
            "LTP-4X.Plaza",
            source_switch=source,
        )

        self.assertEqual(resolved, expected)
        self.assertEqual(
            canonical_neighbor_name("LTP-4X.Plaza"),
            canonical_neighbor_name("LTP-4X-Plaza"),
        )

    def test_abbreviated_street_stem_matches_same_building(self) -> None:
        # Port desc trims Riverside → River; building 98-26 must still match.
        candidate = _switch(
            "mes2324b.Riverside98-26",
            "10.20.14.101",
            "eltex_mes",
            "1",
        )
        score = score_neighbor_match(
            description="mes2324b.River98-26",
            switch=candidate,
            source_switch=None,
        )
        self.assertGreaterEqual(score, 100)

        resolved = resolve_neighbor_from_description(
            _Resolver([candidate]),
            "mes2324b.River98-26",
            source_switch=_switch(
                "mes2348b.site12c_id1005",
                "10.20.14.50",
                "eltex_mes",
                "1005",
            ),
        )
        self.assertEqual(resolved, candidate)

    def test_bare_trailing_id_digits_match_only_same_candidate_id(self) -> None:
        # ..._1006 vs ..._id1006: model+location match after aligning that candidate's id.
        # Bare trailing digits are NOT globally treated as inventory ids (wavelengths).
        candidate = _switch(
            "SNR-S2985G-48T.site12a_id1006",
            "10.20.42.33",
            "snr",
            "1006",
        )
        wrong = _switch(
            "SNR-S2985G-48T.site12b_id1007",
            "10.20.113.10",
            "snr",
            "1007",
        )
        source = _switch(
            "SNR-S2995G-12FX.site12a_id1008",
            "10.20.42.36",
            "snr",
            "1008",
        )

        score = score_neighbor_match(
            description="SNR-S2985G-48T.site12a_1006",
            switch=candidate,
            source_switch=source,
        )
        self.assertGreaterEqual(score, 100)

        # Wavelength-looking trailing number must not invent an id token.
        self.assertIsNone(extract_id_token("SNR-S2985G-48T.Campus_1310"))
        # Unrelated trailing digits (not this candidate's id, not optical) → no match.
        self.assertEqual(
            score_neighbor_match(
                description="SNR-S2985G-48T.site12a_9999",
                switch=candidate,
                source_switch=source,
            ),
            0,
        )

        resolved = resolve_neighbor_from_description(
            _Resolver([wrong, candidate]),
            "SNR-S2985G-48T.site12a_1006",
            source_switch=source,
        )
        self.assertEqual(resolved, candidate)

    def test_family_mismatch_is_rejected_even_when_location_matches(self) -> None:
        l3 = _switch("c4500.Plaza.example.net", "10.30.1.66", "cisco_ios", "1")

        score = score_neighbor_match(
            description="LTP-4X.Plaza",
            switch=l3,
            source_switch=None,
        )

        self.assertEqual(score, 0)

    def test_same_switch_is_never_a_neighbor(self) -> None:
        source = _switch("mes2324fb.Harbor78-33", "10.20.90.5", "eltex_mes", "1")
        alias = _switch("MES alias", "10.20.90.5", "eltex_mes", "1")

        score = score_neighbor_match(
            description="mes2324fb.Harbor78-33",
            switch=alias,
            source_switch=source,
        )

        self.assertEqual(score, 0)

    def test_exact_self_match_vetoes_weaker_same_site_candidate(self) -> None:
        source = _switch(
            "SNR-S2985G-24T.Cedar9-1",
            "10.20.66.9",
            "snr",
            "1",
        )
        weaker = _switch(
            "SNR-S2965G-24T.Cedar9-1",
            "10.20.66.10",
            "snr",
            "2",
        )

        resolved = resolve_neighbor_from_description(
            _Resolver([source, weaker]),
            "SNR-S2985G-24T.Cedar9-1",
            source_switch=source,
        )

        self.assertIsNone(resolved)

    def test_port_count_outweighs_incorrect_series(self) -> None:
        wrong_ports = _switch(
            "SNR-S2985G-8T.Cedar9-1",
            "10.20.66.9",
            "snr",
            "1",
        )
        wrong_series_right_ports = _switch(
            "SNR-S2965G-24T.Cedar9-1",
            "10.20.66.10",
            "snr",
            "2",
        )

        resolved = resolve_neighbor_from_description(
            _Resolver([wrong_ports, wrong_series_right_ports]),
            "SNR-S2985G-24T.Cedar9-1",
        )

        self.assertEqual(resolved, wrong_series_right_ports)

    def test_same_family_count_location_with_no_series_match_is_ambiguous(self) -> None:
        left = _switch(
            "SNR-S2965G-24T.Cedar9-1",
            "10.20.66.9",
            "snr",
            "1",
        )
        right = _switch(
            "SNR-S2995G-24T.Cedar9-1",
            "10.20.66.10",
            "snr",
            "2",
        )

        resolved = resolve_neighbor_from_description(
            _Resolver([left, right]),
            "SNR-S2985G-24T.Cedar9-1",
        )

        self.assertIsNone(resolved)

    def test_different_building_number_is_not_a_location_match(self) -> None:
        candidate = _switch(
            "mes2324fb.Harbor78-32",
            "10.20.90.5",
            "eltex_mes",
            "1",
        )

        score = score_neighbor_match(
            description="mes2324fb.Harbor78-33",
            switch=candidate,
            source_switch=None,
        )

        self.assertEqual(score, 0)

    def test_different_location_suffix_is_not_fuzzy_matched(self) -> None:
        candidate = _switch(
            "SNR-S2985G-24T.Campus-West",
            "10.20.66.9",
            "snr",
            "1",
        )

        score = score_neighbor_match(
            description="SNR-S2985G-24T.Campus-East",
            switch=candidate,
            source_switch=None,
        )

        self.assertEqual(score, 0)

    def test_known_port_count_mismatch_is_rejected(self) -> None:
        candidate = _switch(
            "SNR-S2985G-8T.Cedar9-1",
            "10.20.66.9",
            "snr",
            "1",
        )

        resolved = resolve_neighbor_from_description(
            _Resolver([candidate]),
            "SNR-S2965G-24T.Cedar9-1",
        )

        self.assertIsNone(resolved)

    def test_direction_annotation_is_ignored(self) -> None:
        candidate = _switch(
            "SNR-S2965G-24T.Cedar9-1",
            "10.20.66.9",
            "snr",
            "1",
        )

        score = score_neighbor_match(
            description="downlink: SNR-S2985G-24T.Cedar9-1",
            switch=candidate,
            source_switch=None,
        )

        self.assertGreaterEqual(score, 100)

    def test_stacked_direction_annotations_are_ignored(self) -> None:
        candidate = _switch(
            "SNR-S2965G-24T.Cedar9-1",
            "10.20.66.9",
            "snr",
            "1",
        )

        score = score_neighbor_match(
            description="uplink to SNR-S2985G-24T.Cedar9-1",
            switch=candidate,
            source_switch=None,
        )

        self.assertGreaterEqual(score, 100)

    def test_location_prefix_does_not_match_longer_location(self) -> None:
        candidate = _switch(
            "SNR-S2985G-24T.Campus-West",
            "10.20.66.9",
            "snr",
            "1",
        )

        score = score_neighbor_match(
            description="SNR-S2985G-24T.Campus",
            switch=candidate,
            source_switch=None,
        )

        self.assertEqual(score, 0)

    def test_model_without_location_is_not_enough(self) -> None:
        candidate = _switch(
            "SNR-S2985G-24T.Campus-West",
            "10.20.66.9",
            "snr",
            "1",
        )

        score = score_neighbor_match(
            description="SNR-S2985G-24T",
            switch=candidate,
            source_switch=None,
        )

        self.assertEqual(score, 0)

    def test_ip_description_can_match_resolved_host(self) -> None:
        candidate = _switch(
            "SNR-S2965G-24T.Cedar9-1",
            "10.20.66.9",
            "snr",
            "1",
        )

        score = score_neighbor_match(
            description="10.20.66.9",
            switch=candidate,
            source_switch=None,
        )

        self.assertGreaterEqual(score, 100)

    def test_no_id_search_terms_do_not_include_bare_location(self) -> None:
        terms = _build_search_terms(canonical_neighbor_name("LTP-4X.Plaza"))

        self.assertNotIn("Plaza", terms)
        self.assertIn("ltp-4x-plaza", terms)

    def test_fingerprint_extracts_family_ports_and_location(self) -> None:
        self.assertEqual(equipment_family("S2995G-24FX.Plaza"), "snr")
        self.assertEqual(equipment_port_count("SNR-S2995G-24FX.Plaza"), 24)
        self.assertEqual(equipment_port_count("mes2324fb.Harbor78-33"), 24)
        self.assertEqual(equipment_port_count("LTP-4X.Plaza"), 4)
        self.assertEqual(equipment_location("LTP-4X.Plaza"), "plaza")

    def test_wavelength_and_id_are_not_part_of_location(self) -> None:
        self.assertEqual(
            equipment_location("mes2324b.site12a_id1009_1330nm"),
            "site12a",
        )

    def test_generic_zabbix_ranking_normalizes_ltp_separator(self) -> None:
        hosts = [
            {
                "hostid": "1",
                "host": "c4500.Plaza.example.net",
                "name": "c4500.Plaza.example.net",
                "interfaces": [{"ip": "10.30.1.66", "main": "1", "type": "1"}],
            },
            {
                "hostid": "2",
                "host": "LTP-4X-Plaza",
                "name": "LTP-4X-Plaza",
                "interfaces": [{"ip": "10.20.66.8", "main": "1", "type": "1"}],
            },
        ]

        chosen = _pick_best_host(hosts, "LTP-4X.Plaza")

        self.assertEqual(chosen["hostid"], "2")
        self.assertIn("4X", _build_search_terms("LTP-4X.Plaza"))

    def test_generic_zabbix_ranking_prefers_port_count_over_series(self) -> None:
        hosts = [
            {
                "hostid": "1",
                "host": "mes2348b.Harbor78-33",
                "name": "mes2348b.Harbor78-33",
                "interfaces": [{"ip": "10.20.90.6", "main": "1", "type": "1"}],
            },
            {
                "hostid": "2",
                "host": "mes1124mb.Harbor78-33",
                "name": "mes1124mb.Harbor78-33",
                "interfaces": [{"ip": "10.20.90.7", "main": "1", "type": "1"}],
            },
        ]

        chosen = _pick_best_host(hosts, "mes2324fb.Harbor78-33")

        self.assertEqual(chosen["hostid"], "2")

    def test_resolve_candidates_returns_all_zabbix_hosts(self) -> None:
        hosts = [
            {
                "hostid": "1",
                "host": "c4500.Plaza.example.net",
                "name": "c4500.Plaza.example.net",
                "interfaces": [{"ip": "10.30.1.66", "main": "1", "type": "1"}],
            },
            {
                "hostid": "2",
                "host": "LTP-4X-Plaza",
                "name": "LTP-4X-Plaza",
                "interfaces": [{"ip": "10.20.66.8", "main": "1", "type": "1"}],
            },
        ]
        resolver = object.__new__(SwitchResolver)

        with patch.object(resolver, "_lookup_zabbix_hosts", return_value=hosts):
            records = resolver.resolve_candidates("LTP-4X.Plaza")

        self.assertEqual([record.host for record in records], ["10.30.1.66", "10.20.66.8"])

    def test_candidate_search_keeps_partial_results_after_exact_match(self) -> None:
        exact = {
            "hostid": "1",
            "host": "LTP-4X.Plaza",
            "name": "LTP-4X.Plaza",
            "interfaces": [{"ip": "10.20.66.7", "main": "1", "type": "1"}],
        }
        punctuation_twin = {
            "hostid": "2",
            "host": "LTP-4X-Plaza",
            "name": "LTP-4X-Plaza",
            "interfaces": [{"ip": "10.20.66.8", "main": "1", "type": "1"}],
        }
        client = Mock()

        def _host_get(**kwargs):
            if "filter" in kwargs:
                values = next(iter(kwargs["filter"].values()))
                return [exact] if values == ["LTP-4X.Plaza"] else []
            term = next(iter(kwargs["search"].values()))
            return [exact, punctuation_twin] if term.casefold() == "ltp" else []

        client.host.get.side_effect = _host_get

        hosts = _lookup_hosts(
            client,
            "LTP-4X.Plaza",
            ["host", "name"],
            include_partial_after_exact=True,
        )

        self.assertEqual({host["hostid"] for host in hosts}, {"1", "2"})

    def test_ltp_neighbor_failure_happens_before_vlan_commands(self) -> None:
        session = _LtpSession()
        switch = _switch("LTP-4X-Test", "10.20.1.2", "ltp", "1")

        with self.assertRaises(RuntimeError):
            process_ltp_intermediate_hop(
                session=session,
                resolver=_Resolver([]),
                switch=switch,
                driver=_LtpDriver(),
                chosen_vlan=118,
                target_mac="00:11:22:33:44:55",
                l3_trace_mac="00:aa:bb:cc:dd:ee",
                apply_changes=True,
                debug=False,
            )

        self.assertEqual(session.commands, ["show running-config"])


if __name__ == "__main__":
    unittest.main()
