from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vlan_tool.models import AppConfig, L3MappingSettings, SwitchRecord, TelnetSettings, ZabbixSettings
from vlan_tool.session import (
    MES_PROMPT_EXPECT,
    SwitchSession,
    _is_interactive_cli_command,
    _open_connection,
    _preflight_telnet_port,
    open_switch_session,
)
from vlan_tool.provisioning.executor import looks_like_write_confirmation_prompt


def _config() -> AppConfig:
    return AppConfig(
        path=Path("config.yaml"),
        log_directory=Path(tempfile.gettempdir()),
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


def _switch(vendor: str = "snr") -> SwitchRecord:
    return SwitchRecord(name="dead-switch", host="10.0.0.1", vendor=vendor)


class SessionTests(unittest.TestCase):
    def test_preflight_caps_timeout_for_fast_failure(self) -> None:
        observed: dict[str, object] = {}

        def fake_create_connection(address: tuple[str, int], timeout: float):
            observed["address"] = address
            observed["timeout"] = timeout

            class _Conn:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            return _Conn()

        with patch("vlan_tool.session.socket.create_connection", side_effect=fake_create_connection):
            _preflight_telnet_port("10.0.0.1", 23, 20)

        self.assertEqual(observed["address"], ("10.0.0.1", 23))
        self.assertEqual(observed["timeout"], 3.0)

    def test_open_switch_session_fails_before_netmiko_when_telnet_port_is_dead(self) -> None:
        with (
            patch(
                "vlan_tool.session.socket.create_connection",
                side_effect=socket.timeout("timed out"),
            ),
            patch("vlan_tool.session.ConnectHandler") as connect_handler,
            self.assertRaisesRegex(RuntimeError, r"did not answer within 3s"),
        ):
            with open_switch_session(_config(), _switch(), debug=False):
                self.fail("session should not open when TCP/23 is unreachable")

        connect_handler.assert_not_called()

    def test_eltex_skips_tcp_preflight(self) -> None:
        connection = MagicMock()
        connection.find_prompt.return_value = "mes2324#"
        connection.std_login = MagicMock()

        with (
            patch("vlan_tool.session.socket.create_connection") as create_connection,
            patch("vlan_tool.session.ConnectHandler", return_value=connection),
            patch("vlan_tool.session._perform_generic_telnet_login"),
        ):
            with open_switch_session(_config(), _switch("eltex_mes"), debug=False):
                pass

        create_connection.assert_not_called()

    def test_generic_telnet_does_not_session_prepare_before_login(self) -> None:
        connection = MagicMock()

        with patch("vlan_tool.session.ConnectHandler", return_value=connection):
            opened = _open_connection(
                "generic_telnet",
                {
                    "device_type": "generic_telnet",
                    "host": "10.0.0.1",
                    "username": "user",
                    "password": "pass",
                },
            )

        self.assertIs(opened, connection)
        connection._modify_connection_params.assert_called_once()
        connection.establish_connection.assert_called_once()
        connection._try_session_preparation.assert_not_called()

    def test_mes_show_commands_wait_for_prompt(self) -> None:
        connection = MagicMock()
        connection.send_command.return_value = "mac table\nmes#"
        session = SwitchSession(
            connection=connection,
            switch=_switch("eltex_mes"),
            session_log=Path("mes.log"),
            debug=False,
        )

        output = session.run_timing("show mac address-table address aa-bb-cc-dd-ee-ff")

        self.assertEqual(output, "mac table\nmes#")
        connection.send_command.assert_called_once()
        kwargs = connection.send_command.call_args.kwargs
        self.assertEqual(kwargs["expect_string"], MES_PROMPT_EXPECT)
        self.assertFalse(kwargs["cmd_verify"])
        self.assertEqual(kwargs["read_timeout"], 30)
        connection.clear_buffer.assert_called()
        connection.send_command_timing.assert_not_called()
        # Syslog glued after prompt must still match (no end-of-string required).
        glued = (
            "switchport trunk allowed vlan add 150\n"
            "mes2324b.site12a_id1001(config-if)#30-Sep-2026 17:00:56 %LINK-I-Up:  Vlan 150"
        )
        self.assertRegex(glued, MES_PROMPT_EXPECT)
        # Ticket/# in interface descriptions must not look like a prompt.
        desc = (
            "gi1/0/5  Access (20)             Up    Up          k501_ClientA_#20249\n"
            "gi1/0/6  Access (20)             Up    Up          #39226_ClientB\n"
        )
        self.assertNotRegex(desc, MES_PROMPT_EXPECT)
        self.assertRegex(desc + "mes2324b.site12a_id1001#", MES_PROMPT_EXPECT)
        # Command-wrap redisplay must not count as the final prompt.
        wrapped = (
            "show mac address-table address f8-f0-82-d1-35\n"
            "mes2324b.site12a_id1001#\x1b[K$ress-table address f8-f0-82-d1-35-42\n"
            "Flags: I - Internal usage VLAN\n"
        )
        self.assertNotRegex(wrapped, MES_PROMPT_EXPECT)
        self.assertRegex(wrapped + "mes2324b.site12a_id1001#", MES_PROMPT_EXPECT)
        # Hostname may contain (floor) before _id..., not only Cisco (config) mode.
        self.assertRegex(
            "terminal datadump\nmes2324fb.site12a(10)_id1002#",
            MES_PROMPT_EXPECT,
        )
        self.assertRegex(
            "mes2324fb.site12a(10)_id1002#07-Oct-2026 10:51:01 %AAA-I-CONNECT: x",
            MES_PROMPT_EXPECT,
        )

    def test_mes_enable_password_uses_prompt_sync_not_timing(self) -> None:
        # LINK flaps poison timing (waits for silence); password must expect #.
        connection = MagicMock()
        connection.send_command.return_value = "mes2324b.host#07-Oct %LINK-I-Up: gi1/0/24"
        session = SwitchSession(
            connection=connection,
            switch=_switch("eltex_mes"),
            session_log=Path("mes.log"),
            debug=False,
        )

        session.run_timing("secret", confirm_label="send enable password", sensitive=True)

        connection.send_command.assert_called_once()
        connection.send_command_timing.assert_not_called()

    def test_mes_enable_still_uses_timing(self) -> None:
        connection = MagicMock()
        connection.send_command_timing.return_value = "Password:"
        session = SwitchSession(
            connection=connection,
            switch=_switch("eltex_mes"),
            session_log=Path("mes.log"),
            debug=False,
        )

        output = session.run_timing("enable", confirm_label="enter enable mode")

        self.assertEqual(output, "Password:")
        connection.send_command_timing.assert_called_once()
        connection.send_command.assert_not_called()

    def test_mes_write_uses_timing_not_prompt_sync(self) -> None:
        connection = MagicMock()
        connection.send_command_timing.return_value = (
            "Overwrite file [startup-config] ?[Yes/press any key for no]...."
        )
        session = SwitchSession(
            connection=connection,
            switch=_switch("eltex_mes"),
            session_log=Path("mes.log"),
            debug=False,
        )

        output = session.run_timing("write")

        self.assertIn("Overwrite", output)
        connection.send_command_timing.assert_called_once()
        connection.send_command.assert_not_called()
        self.assertTrue(_is_interactive_cli_command("write"))
        self.assertTrue(_is_interactive_cli_command("wr"))


class WriteConfirmTests(unittest.TestCase):
    def test_mes_dots_confirm_prompt(self) -> None:
        output = "Overwrite file [startup-config] ?[Yes/press any key for no]...."
        self.assertTrue(looks_like_write_confirmation_prompt(output))

    def test_already_back_at_prompt_does_not_confirm(self) -> None:
        output = (
            "Overwrite file [startup-config] ?[Yes/press any key for no]....\n"
            "mes1124mb.site12b_id1003#"
        )
        self.assertFalse(looks_like_write_confirmation_prompt(output))

    def test_classic_yn_still_detected(self) -> None:
        self.assertTrue(looks_like_write_confirmation_prompt("Overwrite? [y/n]"))


if __name__ == "__main__":
    unittest.main()