"""Telnet/Netmiko connection wrapper: open a switch, run commands, write session logs.

Not planning/deploy logic — just the transport layer used by commands and provisioning.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import time
from typing import Iterator

from vlan_tool.logging_utils import build_session_log_path
from vlan_tool.models import AppConfig, SwitchRecord

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
CLI_PROMPT_RE = re.compile(r"[>#]\s*$")


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
        print(f"[debug] {self.switch.name} ({self.switch.host}) >> {shown}")

    def _debug_command_result(self, output: str) -> None:
        if not self.debug:
            return
        length = len(output or "")
        print(f"[debug] {self.switch.name} ({self.switch.host}) << output chars: {length}")


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
    max_attempts = 1 if _is_eltex_legacy_model(switch) else 3
    if debug:
        print(f"[debug] Connecting to {switch.name} ({switch.host}) via {device_type}")

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
                    print(
                        f"[debug] Telnet transient error on {switch.name} ({switch.host}), "
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
            print(f"[debug] Connected to {switch.name} ({switch.host}), session log: {session_log}")

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
            print(f"[debug] Disconnected from {switch.name} ({switch.host})")


def _looks_like_login_prompt(prompt: str) -> bool:
    text = prompt.strip().casefold()
    if not text:
        return False
    return bool(re.search(r"\b(username|password|login)\b", text))


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


def _open_connection(device_type: str, connection_kwargs: dict):
    if device_type != "generic_telnet":
        return ConnectHandler(**connection_kwargs)

    # For generic_telnet we disable auto_connect so Netmiko doesn't send
    # an initial '\r\n' from _try_session_preparation(force_data=True)
    # before authentication prompts are handled.
    connection = ConnectHandler(auto_connect=False, **connection_kwargs)
    connection._modify_connection_params()
    connection.establish_connection()
    try:
        connection._try_session_preparation(force_data=False)
    except TypeError:
        connection._try_session_preparation()
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
