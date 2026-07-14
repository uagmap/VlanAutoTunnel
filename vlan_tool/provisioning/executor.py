"""Run queued CLI action strings on an already-open switch session (config mode + save).

live_path decides *what* to change; this module pushes the commands.
"""

from __future__ import annotations

import re

from vlan_tool.models import SwitchRecord


def execute_actions_in_current_session(*, session, switch: SwitchRecord, actions: list[str]) -> int:
    """
    Execute action bundles in the current switch session in a single config pass.
    This keeps the workflow hop-local and avoids repeated config-mode enter/exit churn.
    """
    if not actions:
        return 0

    commands, used_config = flatten_actions_for_single_config_session(actions, switch.vendor)
    executed = 0
    if used_config:
        if not commands:
            return 0
        enter_command = commands[0]
        payload = commands[1:]
        executed += enter_config_mode_with_retry(
            session=session,
            switch=switch,
            enter_command=enter_command,
        )
        for command in payload:
            output = session.run_timing(command)
            if looks_like_command_failure(output) and not is_benign_command_failure(
                command=command,
                output=output,
                vendor_key=switch.vendor,
            ):
                raise RuntimeError(
                    "Deployment failed on "
                    f"{switch.name} ({switch.host}) while running '{command}'. "
                    "Review session log for details."
                )
            executed += 1
    else:
        for command in commands:
            output = session.run_timing(command)
            if looks_like_command_failure(output) and not is_benign_command_failure(
                command=command,
                output=output,
                vendor_key=switch.vendor,
            ):
                raise RuntimeError(
                    "Deployment failed on "
                    f"{switch.name} ({switch.host}) while running '{command}'. "
                    "Review session log for details."
                )
            executed += 1

    # Some devices silently drop config context. Count only commands actually sent.
    if used_config and executed == 0:
        raise RuntimeError(
            f"Deployment on {switch.name} ({switch.host}) produced no executable commands."
        )
    return executed


def enter_config_mode_with_retry(*, session, switch: SwitchRecord, enter_command: str) -> int:
    attempts = build_config_entry_attempts(switch.vendor, enter_command)
    executed = 0
    for command in attempts:
        output = session.run_timing(command)
        executed += 1
        if looks_like_command_failure(output):
            continue
        if output_or_prompt_is_config_mode(session, output):
            return executed

    raise RuntimeError(
        "Deployment failed on "
        f"{switch.name} ({switch.host}): unable to enter configuration mode "
        f"using {', '.join(repr(item) for item in attempts)}. Review session log for details."
    )


def build_config_entry_attempts(vendor_key: str, preferred: str) -> list[str]:
    preferred_text = preferred.strip()
    attempts: list[str] = [preferred_text]
    candidates = {
        "cisco_ios": ["conf t", "configure terminal"],
        "arista": ["conf t", "configure terminal"],
        "snr": ["config terminal", "configure terminal"],
        "snr_s2970": ["config", "configure terminal", "config terminal", "conf"],
        "snr_s5xxx": ["conf", "config", "configure terminal", "conf t", "config terminal"],
        "eltex_mes": ["configure terminal", "config terminal", "conf t"],
        "fd160": ["conf", "configure terminal", "config terminal", "conf t"],
        "gr_ep_olt2": ["config", "conf", "configure terminal", "config terminal", "conf t"],
        "ltp": ["configure terminal", "config terminal", "conf t", "conf"],
        "bdcom": ["conf", "configure terminal", "config terminal", "conf t"],
        "bdcom_gpon": ["conf", "configure terminal", "config terminal", "conf t"],
    }.get(vendor_key, ["configure terminal", "conf t", "config terminal"])
    for candidate in candidates:
        if candidate.casefold() == preferred_text.casefold():
            continue
        attempts.append(candidate)
    return attempts


def output_or_prompt_is_config_mode(session, output: str) -> bool:
    if looks_like_config_prompt(output):
        return True
    try:
        prompt = session.connection.find_prompt()
    except Exception:
        return False
    return looks_like_config_prompt(prompt)


def looks_like_config_prompt(text: str) -> bool:
    if not text:
        return False
    return bool(
        re.search(
            r"(?:\(config(?:-[^)]+)?\)|_config(?:_[^#>\s]+)?)\s*[>#]\s*$",
            text.strip(),
            flags=re.IGNORECASE | re.MULTILINE,
        )
    )


def flatten_actions_for_single_config_session(actions: list[str], vendor_key: str) -> tuple[list[str], bool]:
    payloads: list[str] = []
    enter_config: str | None = None
    for action in actions:
        commands = split_action_commands(action)
        if not commands:
            continue
        payload, action_enter = extract_action_payload(commands)
        if action_enter and enter_config is None:
            enter_config = action_enter
        payloads.extend(payload)

    if enter_config is None:
        return payloads, False

    # For most vendors, trailing "exit" before final "end" is redundant and noisy.
    if vendor_key not in {"bdcom", "bdcom_gpon", "fd160", "gr_ep_olt2", "snr_s2970"}:
        while payloads and payloads[-1].strip().casefold() == "exit":
            payloads.pop()

    result = [enter_config, *payloads]
    if vendor_key in {"bdcom", "bdcom_gpon", "gr_ep_olt2", "snr_s2970"}:
        # These platforms leave config hierarchy with "exit" instead of "end".
        result.append("exit")
    elif vendor_key == "fd160":
        # FD160 persists changes only from config mode.
        result.extend(["save", "exit"])
    else:
        result.append("end")
    return result, True


def extract_action_payload(commands: list[str]) -> tuple[list[str], str | None]:
    if not commands:
        return [], None

    payload = [item.strip() for item in commands if item.strip()]
    if not payload:
        return [], None

    enter_config: str | None = None
    if is_config_enter_command(payload[0]):
        enter_config = payload.pop(0)

    while payload and payload[-1].casefold() == "end":
        payload.pop()

    # Keep submode exits, but trim one trailing config exit only when action already has double-exit.
    if (
        enter_config
        and len(payload) >= 2
        and payload[-1].casefold() == "exit"
        and payload[-2].casefold() == "exit"
    ):
        payload.pop()

    return payload, enter_config


def is_config_enter_command(command: str) -> bool:
    text = command.strip().casefold()
    return text in {"conf", "conf t", "configure terminal", "config terminal", "config"}


def split_action_commands(action: str) -> list[str]:
    return [item.strip() for item in action.split(";") if item.strip()]


def looks_like_command_failure(output: str) -> bool:
    text = output.casefold()
    failure_markers = (
        "invalid input",
        "unknown command",
        "unrecognized command",
        "incomplete command",
        "ambiguous command",
        "% invalid",
        "% incomplete",
        "% ambiguous",
        "error:",
    )
    return any(marker in text for marker in failure_markers)


def is_benign_vlan_exists_output(command: str, output: str) -> bool:
    cmd = command.strip().casefold()
    if not cmd.startswith("vlan "):
        return False
    text = output.casefold()
    benign_markers = (
        "already exist",
        "already configured",
        "has been configured",
        "vlan exists",
        "already created",
        "create vlan successfully",
    )
    return any(marker in text for marker in benign_markers)


def is_benign_command_failure(*, command: str, output: str, vendor_key: str) -> bool:
    if is_benign_vlan_exists_output(command, output):
        return True

    text = output.casefold()
    cmd = command.strip().casefold()
    if vendor_key == "eltex_mes" and cmd == "vlan database":
        return "unrecognized command" in text or "unknown command" in text

    return False


def save_running_config_if_needed(*, session, switch: SwitchRecord, debug: bool) -> int:
    if switch.vendor not in {
        "eltex_mes",
        "snr",
        "snr_s2970",
        "snr_s5xxx",
        "bdcom",
        "bdcom_gpon",
        "gr_ep_olt1",
    }:
        return 0

    debug_note(debug, f"Saving running-config on {switch.name} ({switch.host})")
    executed = 0

    if switch.vendor in {"bdcom", "bdcom_gpon"}:
        save_commands = ["wr all", "write all", "wr", "write"]
    elif switch.vendor == "gr_ep_olt1":
        save_commands = ["system save all"]
    else:
        save_commands = ["write", "wr"]

    output = ""
    success = False
    for command in save_commands:
        output = session.run_timing(command)
        executed += 1
        if looks_like_command_failure(output):
            continue
        success = True
        break

    if not success:
        raise RuntimeError(
            "Deployment failed on "
            f"{switch.name} ({switch.host}) while running save command "
            f"({', '.join(repr(cmd) for cmd in save_commands)}). "
            "Review session log for details."
        )

    if looks_like_write_confirmation_prompt(output):
        confirm_output = session.run_timing("y", confirm_label="confirm write")
        executed += 1
        if looks_like_command_failure(confirm_output):
            raise RuntimeError(
                "Deployment failed on "
                f"{switch.name} ({switch.host}) while confirming save operation with 'y'. "
                "Review session log for details."
            )

    return executed


def looks_like_write_confirmation_prompt(output: str) -> bool:
    if not output:
        return False
    text = output.casefold()
    return bool(
        re.search(
            r"(overwrite|confirm\s+to\s+overwrite|\[\s*y\s*/\s*n\s*\]|\(\s*y\s*/\s*n\s*\))",
            text,
        )
    )


def debug_note(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[debug] {message}")
