from __future__ import annotations

from vlan_tool.provisioning.common import looks_like_login_output
from vlan_tool.resolver import SwitchResolver
from vlan_tool.session import open_switch_session
from vlan_tool.vendors import get_driver

try:
    from netmiko.exceptions import ReadTimeout
except ImportError:  # pragma: no cover - optional until dependencies are installed
    class ReadTimeout(Exception):
        pass


def run(
    config,
    switch_query: str,
    l3_override: str | None = None,
    *,
    confirm_steps: bool = False,
    debug: bool = False,
) -> int:
    resolver = SwitchResolver(config)
    switch = resolver.resolve(switch_query)
    matched_l3, l3_reason = resolver.resolve_matched_l3(switch, override=l3_override)
    driver = get_driver(switch.vendor)

    with open_switch_session(
        config,
        switch,
        confirm_connect=confirm_steps,
        confirm_commands=confirm_steps,
        debug=debug,
    ) as session:
        driver.prepare_session(session)
        print(f"Connected to {switch.name} ({switch.host})")
        print(f"Driver: {driver.summary()}")
        if matched_l3:
            print(f"Matched L3: {matched_l3.name} ({matched_l3.host})")
            print(f"L3 match rule: {l3_reason}")
        else:
            print("Matched L3: not found")
            print(f"L3 match rule: {l3_reason}")
        print(f"Session log: {session.session_log}")
        for command in driver.probe_commands():
            print("")
            print(f"$ {command}")
            if driver.vendor_key in {"generic_telnet", "snr", "snr_s5xxx", "eltex_mes", "arista"}:
                output = session.run_timing(command)
                if looks_like_login_output(output):
                    raise RuntimeError(
                        "Device is still requesting Username/Password during probe. "
                        "Credentials likely rejected or prompt flow is non-standard."
                    )
            else:
                try:
                    output = session.run_show(command)
                except ReadTimeout:
                    # Some telnet prompts are noisy; timing mode is a safe fallback for probe output.
                    output = session.run_timing(command)
            print(output.rstrip())

    return 0
