from __future__ import annotations

import re

from vlan_tool.provisioning.actions import to_snr_ethernet_name
from vlan_tool.provisioning.common import looks_like_invalid_command
from vlan_tool.provisioning.ltp import extract_ltp_tagged_interfaces_from_vlan_block, extract_ltp_vlan_block


def collect_vlan_snapshot(*, session, driver, vlan_id: int) -> str:
    if driver.vendor_key == "cisco_ios":
        return session.run_show(f"show vlan id {vlan_id}")
    if driver.vendor_key == "snr":
        return session.run_timing(f"show vlan id {vlan_id}")
    if driver.vendor_key == "snr_s5xxx":
        output = session.run_timing(f"show vlan {vlan_id}")
        if looks_like_invalid_command(output):
            output = session.run_timing(f"show vlan id {vlan_id}")
        return output
    if driver.vendor_key == "eltex_mes":
        return session.run_timing(f"show vlan tag {vlan_id}")
    if driver.vendor_key == "bdcom":
        return session.run_timing(f"show vlan id {vlan_id}")
    if driver.vendor_key == "ltp":
        return session.run_timing("show running-config")
    if driver.vendor_key == "arista":
        return session.run_timing(f"show vlan id {vlan_id}")
    return session.run_timing(f"show vlan id {vlan_id}")


def snapshot_vlan_exists(*, driver, vlan_id: int, snapshot: str) -> bool:
    text = snapshot.casefold()
    if driver.vendor_key == "cisco_ios":
        missing_markers = (
            "not found in current vlan database",
            "vlan id not found",
            "invalid input",
            "incomplete command",
        )
        if any(marker in text for marker in missing_markers):
            return False
    if driver.vendor_key == "snr":
        if "invalid" in text and "input" in text:
            return False
    if driver.vendor_key == "snr_s5xxx":
        missing_markers = (
            "not found in current vlan database",
            "vlan id not found",
            "invalid input",
            "incomplete command",
        )
        if any(marker in text for marker in missing_markers):
            return False
        if re.search(rf"^\s*\S+\s+{vlan_id}\s+\S+", snapshot, flags=re.IGNORECASE | re.MULTILINE):
            return True
    if driver.vendor_key == "eltex_mes":
        if "invalid" in text and "input" in text:
            return False
    if driver.vendor_key == "bdcom":
        if "invalid" in text and "input" in text:
            return False
        if re.search(rf"vlan\s+id\s*:\s*{vlan_id}\b", text, flags=re.IGNORECASE):
            return True
    if driver.vendor_key == "ltp":
        return extract_ltp_vlan_block(running_config=snapshot, vlan_id=vlan_id) is not None
    return bool(re.search(rf"^\s*{vlan_id}\s+", snapshot, flags=re.IGNORECASE | re.MULTILINE))


def snapshot_interface_tagged(*, driver, vlan_id: int, interface: str | None, snapshot: str) -> bool | None:
    if not interface:
        return None
    if not snapshot_vlan_exists(driver=driver, vlan_id=vlan_id, snapshot=snapshot):
        return False

    wanted = driver.normalize_interface(interface)
    if driver.vendor_key == "snr_s5xxx":
        for match in re.finditer(
            r"(?P<intf>[A-Za-z]+[0-9]+(?:/[0-9]+)*)\((?P<mode>[TtUu])\)",
            snapshot,
        ):
            if driver.normalize_interface(match.group("intf")) != wanted:
                continue
            return match.group("mode").casefold() == "t"

    if driver.vendor_key == "snr":
        full = to_snr_ethernet_name(interface)
        return bool(re.search(rf"{re.escape(full)}\s*\(T\)", snapshot, flags=re.IGNORECASE))

    if driver.vendor_key == "eltex_mes":
        # Parse interfaces from the full VLAN snapshot.
        # Splitting on "UnTagged Ports" cuts off the table data itself because
        # that phrase appears in the header line.
        tagged_section = snapshot
        tokens = re.findall(
            r"(?:gi|te|fa)\d+/\d+/\d+(?:-\d+)?|po\d+(?:-\d+)?",
            tagged_section,
            flags=re.IGNORECASE,
        )
        expanded: list[str] = []
        for token in tokens:
            expanded.extend(expand_eltex_interface_token(token))
        return any(driver.normalize_interface(token) == wanted for token in expanded)

    if driver.vendor_key == "bdcom":
        for line in snapshot.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parts = re.split(r"\s+", stripped, maxsplit=1)
            if len(parts) < 2:
                continue
            interface_token = parts[0]
            if driver.normalize_interface(interface_token) != wanted:
                continue
            attributes = parts[1].casefold()
            return "tagged" in attributes
    if driver.vendor_key == "ltp":
        vlan_block = extract_ltp_vlan_block(running_config=snapshot, vlan_id=vlan_id)
        if vlan_block is None:
            return False
        tagged = extract_ltp_tagged_interfaces_from_vlan_block(vlan_block=vlan_block, driver=driver)
        return wanted in tagged

    tokens = re.findall(r"(?:[A-Za-z]+[0-9]+(?:/[0-9]+)*)", snapshot)
    return any(driver.normalize_interface(token) == wanted for token in tokens)


def expand_eltex_interface_token(token: str) -> list[str]:
    stripped = token.strip()
    range_match = re.match(
        r"^(?P<prefix>[A-Za-z]+)(?P<a>\d+)/(?P<b>\d+)/(?P<start>\d+)-(?P<end>\d+)$",
        stripped,
    )
    if range_match:
        start = int(range_match.group("start"))
        end = int(range_match.group("end"))
        if end >= start and end - start <= 96:
            base = f"{range_match.group('prefix')}{range_match.group('a')}/{range_match.group('b')}/"
            return [f"{base}{port}" for port in range(start, end + 1)]

    po_range_match = re.match(r"^(?P<prefix>po)(?P<start>\d+)-(?P<end>\d+)$", stripped, flags=re.IGNORECASE)
    if po_range_match:
        start = int(po_range_match.group("start"))
        end = int(po_range_match.group("end"))
        if end >= start and end - start <= 256:
            prefix = po_range_match.group("prefix")
            return [f"{prefix}{index}" for index in range(start, end + 1)]
    return [stripped]
