from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from vlan_tool.cli import build_parser
from vlan_tool.commands.client_check import LiveCheckDisplay
from vlan_tool.diagnostics.port import scan_port_log_flap
from vlan_tool.diagnostics.physical import _parse_mes_copper, _parse_snr_transceiver
from vlan_tool.diagnostics.mgmt import probe_cpe_management
from vlan_tool.diagnostics.report import CheckLine, ClientCheckReport
from vlan_tool.diagnostics.report import derive_verdict
from vlan_tool.diagnostics.runner import run_client_check
from vlan_tool.diagnostics.vlan_policy import expected_vlans_for_port
from vlan_tool.models import AppConfig, L3MappingSettings, TelnetSettings, ZabbixSettings
from vlan_tool.vendors.eltex_mes import EltexMESDriver, _parse_eltex_interface_statuses_output


class _Driver:
    def __init__(self, vendor_key: str) -> None:
        self.vendor_key = vendor_key


class _Session:
    def __init__(self) -> None:
        self.commands: list[tuple[str, str]] = []

    def run_show(self, command: str) -> str:
        self.commands.append(("show", command))
        return "%Aug 18 10:05:47:964 2026 Ethernet1/0/15 changed state to UP"

    def run_timing(self, command: str) -> str:
        self.commands.append(("timing", command))
        return "%Aug 18 10:05:47:964 2026 Ethernet1/0/15 changed state to UP"


class _OutputSession(_Session):
    def __init__(self, output: str) -> None:
        super().__init__()
        self.output = output

    def run_show(self, command: str) -> str:
        self.commands.append(("show", command))
        return self.output

    def run_timing(self, command: str) -> str:
        self.commands.append(("timing", command))
        return self.output


class _SequenceSession(_Session):
    def __init__(self, outputs: list[str]) -> None:
        super().__init__()
        self.outputs = list(outputs)

    def run_show(self, command: str) -> str:
        self.commands.append(("show", command))
        return self.outputs.pop(0) if self.outputs else ""

    def run_timing(self, command: str) -> str:
        self.commands.append(("timing", command))
        return self.outputs.pop(0) if self.outputs else ""


class _TTYStream(io.StringIO):
    def isatty(self) -> bool:
        return True


def _config() -> AppConfig:
    return AppConfig(
        path=Path("config.yaml"),
        log_directory=Path("."),
        telnet=TelnetSettings(
            username="user",
            password="pass",
            secret=None,
            port=23,
            timeout_seconds=20,
            global_delay_factor=1.5,
        ),
        zabbix=ZabbixSettings(),
        l3_mapping=L3MappingSettings(),
        vlan_ranges=[],
    )


class ClientCheckTests(unittest.TestCase):
    def test_check_is_the_cli_command_name(self) -> None:
        args = build_parser().parse_args(["check", "id1010", "1/0/15"])
        self.assertEqual(args.command, "check")

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(["check-client", "id1010", "1/0/15"])

    def test_each_vendor_uses_one_port_log_command(self) -> None:
        cases = {
            "snr": ("timing", "show log | include 1/0/15"),
            "snr_s2970": ("timing", "show logging | include 1/0/15"),
            "snr_s5xxx": ("timing", "show log | include 1/0/15"),
            "cisco_ios": ("show", "show logging | include 1/0/15"),
            "eltex_mes": ("timing", "show log | include 1/0/15"),
            "arista": ("timing", "show logging | include 1/0/15"),
        }
        for vendor, expected in cases.items():
            with self.subTest(vendor=vendor):
                session = _Session()
                scan_port_log_flap(
                    session=session,
                    driver=_Driver(vendor),
                    interface="1/0/15",
                )
                self.assertEqual(session.commands, [expected])

    def test_non_tty_display_streams_only_completed_summary(self) -> None:
        stream = io.StringIO()
        display = LiveCheckDisplay(stream)
        report = ClientCheckReport(
            switch_name="access-1",
            switch_host="10.20.25.56",
            port="1/0/15",
            description="U96109",
            line_callback=display.complete,
        )

        with display:
            display.start("Port link: checking")
            display.begin(report)
            report.add("PASS", "Port link: admin UP, link UP")
            report.verdict = "Access and L3 checks look healthy"
            report.session_logs.append("logs/access.log")
            display.finish(report)

        output = stream.getvalue()
        self.assertIn(
            "Client check: access-1 (10.20.25.56) port 1/0/15 — U96109",
            output,
        )
        self.assertIn("[PASS] Port link: admin UP, link UP", output)
        self.assertIn("Likely cause: Access and L3 checks look healthy", output)
        self.assertNotIn("Port link: checking", output)
        self.assertNotIn("\r", output)

    def test_tty_display_uses_the_status_slot_for_spinner(self) -> None:
        stream = _TTYStream()
        display = LiveCheckDisplay(stream)
        report = ClientCheckReport("access-1", "10.20.25.56", "1/0/15")

        with display:
            display.start("Port link: checking")
            display.begin(report)
            display.complete(CheckLine("PASS", "Port link: admin UP, link UP"))
            display.finish(report)

        self.assertIn("\r[-] Port link: checking", stream.getvalue())
        self.assertIn("[PASS] Port link: admin UP, link UP", stream.getvalue())

    def test_connection_failure_becomes_fail_report_line(self) -> None:
        class _AccessSwitch:
            name = "dead-switch"
            host = "10.0.0.1"
            vendor = "snr"

        class _Resolver:
            def resolve(self, _switch_query: str):
                return _AccessSwitch()

        steps: list[str] = []

        with (
            patch("vlan_tool.diagnostics.runner.SwitchResolver", return_value=_Resolver()),
            patch("vlan_tool.diagnostics.runner.get_driver", return_value=object()),
            patch(
                "vlan_tool.diagnostics.runner.open_switch_session",
                side_effect=RuntimeError("Telnet port 10.0.0.1:23 did not answer within 3s"),
            ),
        ):
            report = run_client_check(
                _config(),
                switch_query="dead-switch",
                port="1/0/15",
                debug=False,
                on_step=steps.append,
            )

        self.assertEqual(report.lines[0].status, "FAIL")
        self.assertIn("Connection: access switch dead-switch (10.0.0.1)", report.lines[0].message)
        self.assertEqual(report.verdict, "Access switch unreachable or not answering on Telnet")
        self.assertIn("Connection: access switch", steps)

    def test_eltex_log_flap_is_warned(self) -> None:
        session = _OutputSession(
            "\n".join(
                [
                    "19-Aug-2026 14:58:21 :%LINK-I-Up:  fa1/0/5, 100Mbps FULL duplex",
                    "19-Aug-2026 14:58:19 :%LINK-W-Down:  fa1/0/5",
                    "19-Aug-2026 14:58:17 :%LINK-I-Up:  fa1/0/5, 100Mbps FULL duplex",
                    "19-Aug-2026 14:58:15 :%LINK-W-Down:  fa1/0/5",
                ]
            )
        )
        scan = scan_port_log_flap(
            session=session,
            driver=_Driver("eltex_mes"),
            interface="fa1/0/5",
            interface_detail="fastethernet 1/0/5 is up (connected)\n  Link is up for 2 seconds",
        )

        self.assertEqual(session.commands, [("timing", "show log | include fa1/0/5")])
        self.assertEqual(scan.status, "WARN")
        self.assertIn("Port link unstable", scan.summary)

    def test_snr_falls_back_to_logging_buffered_when_show_log_rejected(self) -> None:
        session = _SequenceSession(
            [
                "% Unrecognized command",
                "%Aug 20 14:58:21:000 2026 Line protocol on Interface Ethernet1/0/4, changed state to UP",
            ]
        )
        scan = scan_port_log_flap(
            session=session,
            driver=_Driver("snr"),
            interface="1/0/4",
        )

        self.assertEqual(
            session.commands,
            [
                ("timing", "show log | include 1/0/4"),
                ("timing", "show logging buffered level warnings | i 1/0/4"),
            ],
        )
        self.assertIn("1 link events", scan.summary)

    def test_eltex_interface_description_columns_parse_correctly(self) -> None:
        output = "\n".join(
            [
                "         Admin Link",
                "Port     State State       Description",
                "-------- ----- ----------- -----------",
                "fa1/0/5  Up    Down        u56951_IP_ClientA",
                "fa1/0/6  Up    Up          ip_ClientB",
            ]
        )

        results = _parse_eltex_interface_statuses_output(EltexMESDriver(), output)

        self.assertEqual(results["fa1/0/5"].admin_state, "Up")
        self.assertEqual(results["fa1/0/5"].link_state, "Down")
        self.assertIsNone(results["fa1/0/5"].mode)
        self.assertEqual(results["fa1/0/5"].description, "u56951_IP_ClientA")
        self.assertEqual(results["fa1/0/6"].link_state, "Up")

    def test_eltex_mes2324_mode_vlan_columns_parse_correctly(self) -> None:
        output = "\n".join(
            [
                "                                  Admin Link",
                "Port     Port Mode (VLAN)         State State       Description",
                "-------- ------------------------ ----- ----------- -----------",
                "gi1/0/21 Access (20)             Up    Up          F47264_ClientC",
                "gi1/0/24 Trunk                    Up    Up          SNR-S2982G-24TE.site12a_id1011",
                "Po1      Access (1)               Up    Not Present",
            ]
        )

        results = _parse_eltex_interface_statuses_output(EltexMESDriver(), output)

        self.assertEqual(results["gi1/0/21"].admin_state, "Up")
        self.assertEqual(results["gi1/0/21"].link_state, "Up")
        self.assertEqual(results["gi1/0/21"].mode, "access")
        self.assertEqual(results["gi1/0/21"].access_vlan, 20)
        self.assertEqual(results["gi1/0/21"].description, "F47264_ClientC")
        self.assertEqual(results["gi1/0/24"].mode, "trunk")
        self.assertEqual(results["po1"].link_state, "Not Present")
        vlans, rule = expected_vlans_for_port(results["gi1/0/21"].description, access_vlan=20)
        self.assertEqual(vlans, {20, 21})
        self.assertIn("F-port", rule)

    def test_eltex_cable_length_channel_table_is_ok(self) -> None:
        output = "\n".join(
            [
                " Port       Length [m] Pair Channel Polarity Pair Skew [ns]",
                "----------- ---------- ---- ------- -------- --------------",
                "gi1/0/21    51         1-2     A     normal  0",
                "                       3-6     B     normal  0",
                "                       4-5     C     normal  0",
                "                       7-8     D     normal  0",
            ]
        )

        check = _parse_mes_copper(output, link_up=True)

        self.assertEqual(check.status, "PASS")
        self.assertIn("~51m", check.summary)
        self.assertIn("normal", check.summary)

    def test_eltex_cable_uniform_negative_polarity_is_ok(self) -> None:
        output = "\n".join(
            [
                " Port       Length [m] Pair Channel Polarity Pair Skew [ns]",
                "----------- ---------- ---- ------- -------- --------------",
                "gi1/0/22    36         1-2     A    negative 36",
                "                       3-6     B    negative 36",
                "                       4-5     C    negative 36",
                "                       7-8     D    negative 36",
            ]
        )

        check = _parse_mes_copper(output, link_up=True)

        self.assertEqual(check.status, "PASS")
        self.assertIn("~36m", check.summary)
        self.assertIn("negative", check.summary)

    def test_eltex_cable_mixed_polarity_is_warned(self) -> None:
        output = "\n".join(
            [
                "gi1/0/22    36         1-2     A     normal  0",
                "                       3-6     B    negative 0",
                "                       4-5     C     normal  0",
                "                       7-8     D    negative 0",
            ]
        )

        check = _parse_mes_copper(output, link_up=True)

        self.assertEqual(check.status, "WARN")
        self.assertIn("mixed polarity", check.summary)

    def test_eltex_cable_high_pair_skew_is_warned(self) -> None:
        output = "\n".join(
            [
                "gi1/0/22    36         1-2     A    negative 80",
                "                       3-6     B    negative 80",
                "                       4-5     C    negative 80",
                "                       7-8     D    negative 80",
            ]
        )

        check = _parse_mes_copper(output, link_up=True)

        self.assertEqual(check.status, "WARN")
        self.assertIn("skew 80ns", check.summary)

    def test_eltex_historical_flap_burst_is_pass_when_link_stable(self) -> None:
        session = _OutputSession(
            "\n".join(
                [
                    "24-Aug-2026 14:51:04 :%GCLI-I-CMD-EXEC: source:10.20.8.76 destination:10.20.5.35 user:ops cmd:show interfaces gi1/0/21",
                    "24-Aug-2026 14:07:45 :%LINK-I-Up:  gi1/0/21",
                    "24-Aug-2026 14:07:35 :%LINK-W-Down:  gi1/0/21",
                    "24-Aug-2026 14:07:26 :%LINK-I-Up:  gi1/0/21",
                    "24-Aug-2026 14:07:14 :%LINK-W-Down:  gi1/0/21",
                ]
            )
        )
        scan = scan_port_log_flap(
            session=session,
            driver=_Driver("eltex_mes"),
            interface="gi1/0/21",
            interface_detail="Link is up for 0 days, 0 hours, 43 minutes and 18 seconds",
        )

        self.assertEqual(scan.status, "PASS")
        self.assertIn("4 link events", scan.summary)
        self.assertIn("stable", scan.summary)

    def test_eltex_invalid_cable_diagnostics_does_not_fake_length(self) -> None:
        output = "\n".join(
            [
                "show cable-diagnostics cable-length interface fa1/0",
                "mes1124MB.Site_Do...#\x1b[K$iagnostics cable-length interface fa1/0/5",
                "",
                "% Wrong number of parameters or invalid range, size or characters entered",
            ]
        )

        check = _parse_mes_copper(output, link_up=False)

        self.assertEqual(check.status, "SKIP")
        self.assertEqual(check.summary, "Cable diagnostics: could not parse output")

    def test_cpe_management_warns_when_all_ports_filtered(self) -> None:
        with patch(
            "vlan_tool.diagnostics.mgmt._tcp_connect_state",
            return_value="filtered",
        ):
            result = probe_cpe_management("10.20.50.169")

        self.assertEqual(result.status, "WARN")
        self.assertIn("10.20.50.169", result.summary)
        self.assertIn("not reachable for management", result.summary)

    def test_cpe_management_passes_when_any_port_is_open(self) -> None:
        def fake_state(_ip: str, port: int) -> str:
            return "open" if port == 443 else "filtered"

        with patch("vlan_tool.diagnostics.mgmt._tcp_connect_state", side_effect=fake_state):
            result = probe_cpe_management("10.20.50.169")

        self.assertEqual(result.status, "PASS")
        self.assertIn("reachable on TCP 443", result.summary)

    def test_snr_transceiver_na_is_skipped(self) -> None:
        output = "\n".join(
            [
                "Interface            Temp(C)            Voltage(V)            Bias(mA)            RX Power(dBM)            TX Power(dBM)",
                "---------            --------            ----------            --------            -------------            -------------",
                "1/0/4                N/A                 N/A                   N/A                 N/A                      N/A",
            ]
        )
        check = _parse_snr_transceiver(output)
        self.assertEqual(check.status, "SKIP")
        self.assertIn("DOM unavailable", check.summary)

    def test_soft_counter_warn_does_not_own_verdict(self) -> None:
        report = ClientCheckReport("sw", "10.20.45.2", "1/0/4")
        report.add("PASS", "Port link: admin UP, link UP")
        report.add("WARN", "Interface error counters: crc=1, input_errors=1")
        report.add("PASS", "MAC on port: d4-53-2a-3d-cf-88")
        self.assertEqual(
            derive_verdict(report),
            "Access and L3 checks look healthy; if client still offline, check CPE/billing/auth",
        )


if __name__ == "__main__":
    unittest.main()
