"""Telnet/Netmiko connection wrapper: open a switch, run commands, write session logs.

Not planning/deploy logic — just the transport layer used by commands and provisioning.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import os
from pathlib import Path
import re
import socket
import time
from typing import Iterator

from vlan_tool.models import AppConfig, SwitchRecord
from vlan_tool.trace_panel import ui_print

try:
    from netmiko import ConnectHandler
except ImportError:  # pragma: no cover - optional until dependencies are installed
    ConnectHandler = None


DEFAULT_DEVICE_TYPES = {
    "arista": "arista_eos_telnet",
    "arista_eos": "arista_eos_telnet",
    "bdcom": "generic_telnet",
    "bdcom_gpon": "generic_telnet",
    "cisco_ios": "cisco_ios_telnet",
    "generic_telnet": "generic_telnet",
    "gr_ep_olt1": "generic_telnet",
    "gr_ep_olt2": "generic_telnet",
    "snr": "generic_telnet",
    "snr_s2970": "generic_telnet",
    "snr_s5xxx": "generic_telnet",
    "eltex_mes": "generic_telnet",
    "fd160": "generic_telnet",
    "ltp": "generic_telnet",
}
LOCAL_AUTH_REQUIRED_VENDORS = {"gr_ep_olt1"}
LOCAL_AUTH_DEFAULT_USERNAMES = {"gr_ep_olt1": "root"}

TRANSIENT_TELNET_ERRORS = (ConnectionResetError, TimeoutError, OSError, EOFError)
TELNET_USERNAME_PROMPT_RE = re.compile(
    r"(?:user\s*name|username|user|login)\s*[:>]",
    re.IGNORECASE,
)
TELNET_PASSWORD_PROMPT_RE = re.compile(
    r"(?:password|passcode)\s*[:>]",
    re.IGNORECASE,
)
# Line-start non-space run ending in #/>. Covers:
#   sw-name.site(10)_id1234#   (parens mid-hostname)
#   hostname(config-if)#30-Sep...           (glued syslog)
# Rejects:
#   mid-line ticket markers (client_#20249)
#   wrap redisplays (hostname#\x1b[K$rest)
MES_PROMPT_EXPECT = r"(?m)^\S+[>#](?!\$|\x1b)"


class SwitchSession:
    def __init__(
        self,
        connection,
        switch: SwitchRecord,
        session_log: Path,
        *,
        debug: bool = True,
    ) -> None:
        self.connection = connection
        self.switch = switch
        self.session_log = session_log
        self.debug = debug

    def run_show(self, command: str, *, expect_string: str | None = None) -> str:
        self._debug_command(command)
        output = self.connection.send_command(
            command,
            expect_string=expect_string,
            strip_prompt=False,
            strip_command=False,
        )
        self._debug_command_result(output)
        return output

    def run_timing(
        self,
        command: str,
        *,
        confirm_label: str | None = None,
        sensitive: bool = False,
    ) -> str:
        self._debug_command(
            command,
            sensitive=sensitive,
            confirm_label=confirm_label,
        )
        # ponytail: MES timing waits for silence; LINK flaps every ~1s reset that
        # timer for minutes. Prompt-expect returns on first hostname# even if
        # syslog keeps arriving. Keep timing only for interactive prompts
        # (enable → Password:, write → Overwrite?....).
        use_prompt_sync = (
            self.switch.vendor == "eltex_mes"
            and not _is_interactive_cli_command(command)
        )
        if use_prompt_sync:
            # Discard unread flap/syslog lines left from the previous command.
            clear_buffer = getattr(self.connection, "clear_buffer", None)
            if callable(clear_buffer):
                try:
                    clear_buffer()
                except Exception:
                    pass
            # ponytail: MES truncates/wraps long echoes (mac lookups); cmd_verify then
            # never finds the full command string. Prompt expect is enough.
            # Also: async syslog can glue onto the prompt line
            # (...(config-if)#30-Sep... %LINK-I-Up), so do not require end-of-string.
            output = self.connection.send_command(
                command,
                expect_string=MES_PROMPT_EXPECT,
                read_timeout=30,
                strip_prompt=False,
                strip_command=False,
                cmd_verify=False,
            )
        else:
            output = self.connection.send_command_timing(
                command,
                strip_prompt=False,
                strip_command=False,
            )
        self._debug_command_result(output)
        return output

    def run_config_set(self, commands: list[str]) -> str:
        for command in commands:
            self._debug_command(command)
        output = self.connection.send_config_set(commands)
        self._debug_command_result(output)
        return output

    def disconnect(self) -> None:
        self.connection.disconnect()

    def _debug_command(
        self,
        command: str,
        *,
        sensitive: bool = False,
        confirm_label: str | None = None,
    ) -> None:
        if not self.debug:
            return
        if sensitive:
            shown = confirm_label or "<sensitive>"
        else:
            shown = command
        ui_print(f"{self.switch.name} ({self.switch.host}) >> {shown}")

    def _debug_command_result(self, output: str) -> None:
        if not self.debug:
            return
        length = len(output or "")
        ui_print(f"{self.switch.name} ({self.switch.host}) << output chars: {length}")


@contextmanager
def open_switch_session(
    config: AppConfig,
    switch: SwitchRecord,
    *,
    debug: bool = True,
) -> Iterator[SwitchSession]:
    if ConnectHandler is None:
        raise RuntimeError("netmiko is not installed. Install dependencies before connecting.")

    device_type = switch.device_type or DEFAULT_DEVICE_TYPES.get(switch.vendor, "generic_telnet")
    session_log = build_session_log_path(config.log_directory, switch.host)
    # Eltex AAA logs every incomplete TCP/login attempt; never retry-spam it.
    max_attempts = 1 if switch.vendor == "eltex_mes" else 3
    if debug:
        ui_print(f"Connecting to {switch.name} ({switch.host}) via {device_type}")
    # Eltex logs a naked TCP connect/close as "user unknown" REJECTED — skip preflight there.
    if "telnet" in device_type and switch.vendor != "eltex_mes":
        _preflight_telnet_port(switch.host, config.telnet.port, config.telnet.timeout_seconds)

    connection = None
    last_transient_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            username, password, secret = _resolve_telnet_credentials(config, switch)
            connection_kwargs = dict(
                device_type=device_type,
                host=switch.host,
                username=username,
                password=password,
                secret=secret,
                port=config.telnet.port,
                conn_timeout=config.telnet.timeout_seconds,
                auth_timeout=config.telnet.timeout_seconds,
                banner_timeout=config.telnet.timeout_seconds,
                fast_cli=False,
                global_delay_factor=config.telnet.global_delay_factor,
                session_log=str(session_log),
                session_log_record_writes=True,
            )
            connection = _open_connection(device_type, connection_kwargs)

            # Some telnet devices are flaky on first handshake; give prompt engine a short settle delay.
            if device_type == "generic_telnet":
                _perform_generic_telnet_login(
                    connection,
                    config,
                    switch=switch,
                )
                # Prompt discovery is only safe after credentials — never during Username:.
                try:
                    connection.set_base_prompt()
                except Exception:
                    pass

            if switch.requires_enable:
                connection.enable()

            # Fail fast when telnet login did not complete, so commands do not run at Username:/Password: prompts.
            prompt = connection.find_prompt()
            if _looks_like_login_prompt(prompt):
                raise RuntimeError(
                    "Telnet authentication did not complete. "
                    "The device is still showing a login prompt. Check VLAN_TELNET_USERNAME / VLAN_TELNET_PASSWORD."
                )
            break
        except TRANSIENT_TELNET_ERRORS as exc:
            last_transient_error = exc
            if connection is not None:
                try:
                    connection.disconnect()
                except Exception:
                    pass
                connection = None
            if attempt < max_attempts:
                if debug:
                    ui_print(
                        f"Telnet transient error on {switch.name} ({switch.host}), "
                        f"attempt {attempt}/{max_attempts}: {exc}. Retrying..."
                    )
                time.sleep(1.0 * attempt)
                continue
            raise RuntimeError(
                f"Telnet session to {switch.name} ({switch.host}) was reset during login/connect: {exc}. "
                "The host resolved correctly, but the remote side closed the socket (often session-limit or transient). "
                "Retry once; if it persists, connect manually and check concurrent telnet sessions/ACLs."
            ) from exc

    if connection is None:
        if last_transient_error is not None:
            raise RuntimeError(
                f"Unable to establish Telnet session to {switch.name} ({switch.host}) "
                f"after {max_attempts} attempts: {last_transient_error}"
            ) from last_transient_error
        raise RuntimeError(f"Unable to establish Telnet session to {switch.name} ({switch.host}).")

    try:
        if debug:
            ui_print(f"Connected to {switch.name} ({switch.host}), session log: {session_log}")

        yield SwitchSession(
            connection=connection,
            switch=switch,
            session_log=session_log,
            debug=debug,
        )
    finally:
        try:
            connection.disconnect()
        except Exception:
            pass
        if debug:
            ui_print(f"Disconnected from {switch.name} ({switch.host})")


def _looks_like_login_prompt(prompt: str) -> bool:
    text = prompt.strip().casefold()
    if not text:
        return False
    return bool(re.search(r"\b(username|password|login)\b", text))


def _is_interactive_cli_command(command: str) -> bool:
    first = command.strip().casefold().split(maxsplit=1)[0] if command.strip() else ""
    # write/wr sit on Overwrite?[Yes/...] and must not wait for a # prompt.
    return first in {
        "enable",
        "disable",
        "exit",
        "end",
        "configure",
        "conf",
        "config",
        "write",
        "wr",
        "y",
        "n",
    }


def _perform_generic_telnet_login(
    connection,
    config: AppConfig,
    *,
    switch: SwitchRecord,
) -> None:
    login_fn = getattr(connection, "std_login", None) or getattr(connection, "telnet_login", None)
    if login_fn is None:
        return

    max_loops = 8 if _is_eltex_legacy_model(switch) else 40
    login_fn(
        pri_prompt_terminator=r"#\s*$",
        alt_prompt_terminator=r">\s*$",
        username_pattern=TELNET_USERNAME_PROMPT_RE.pattern,
        pwd_pattern=TELNET_PASSWORD_PROMPT_RE.pattern,
        delay_factor=max(1.0, config.telnet.global_delay_factor),
        max_loops=max_loops,
    )


def _preflight_telnet_port(host: str, port: int, timeout_seconds: int | float) -> None:
    timeout = max(1.0, min(float(timeout_seconds), 3.0))
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as exc:
        raise RuntimeError(
            f"Telnet port {host}:{port} did not answer within {timeout:g}s: {exc}. "
            "The switch may be powered off, unreachable, or blocking TCP/23."
        ) from exc


def _open_connection(device_type: str, connection_kwargs: dict):
    if device_type != "generic_telnet":
        return ConnectHandler(**connection_kwargs)

    # For generic_telnet: connect only. Netmiko session_preparation() calls
    # _test_channel_read/set_base_prompt which write bare RETURN at Username:,
    # which Eltex logs as "user unknown" / local REJECTED before real login.
    connection = ConnectHandler(auto_connect=False, **connection_kwargs)
    connection._modify_connection_params()
    connection.establish_connection()
    return connection


def _resolve_telnet_credentials(config: AppConfig, switch: SwitchRecord) -> tuple[str, str, str | None]:
    vendor_key = re.sub(r"[^A-Za-z0-9]+", "_", switch.vendor or "").strip("_").upper()
    username_override = _first_env_value(
        f"VLAN_{vendor_key}_TELNET_USERNAME",
        f"VLAN_{vendor_key}_USERNAME",
    )
    password_override = _first_env_value(
        f"VLAN_{vendor_key}_TELNET_PASSWORD",
        f"VLAN_{vendor_key}_PASSWORD",
    )
    secret_override = _first_env_value(
        f"VLAN_{vendor_key}_TELNET_SECRET",
        f"VLAN_{vendor_key}_SECRET",
    )

    if switch.vendor in LOCAL_AUTH_REQUIRED_VENDORS:
        username = username_override or LOCAL_AUTH_DEFAULT_USERNAMES.get(switch.vendor) or config.telnet.username
        if not password_override:
            raise RuntimeError(
                f"Vendor '{switch.vendor}' requires local Telnet credentials. "
                f"Set VLAN_{vendor_key}_TELNET_PASSWORD or VLAN_{vendor_key}_PASSWORD in .env."
            )
        return username, password_override, secret_override

    return (
        username_override or config.telnet.username,
        password_override or config.telnet.password,
        secret_override if secret_override is not None else config.telnet.secret,
    )


def _first_env_value(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value is None:
            continue
        text = value.strip()
        if text:
            return text
    return None


def _is_eltex_legacy_model(switch: SwitchRecord) -> bool:
    if switch.vendor != "eltex_mes":
        return False
    return "mes1124" in switch.name.casefold()


def build_session_log_path(log_directory: Path, host: str) -> Path:
    log_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = "".join(
        character if character.isalnum() or character in "._-" else "_" for character in host
    )
    return log_directory / f"{safe_host}_{timestamp}.log"
