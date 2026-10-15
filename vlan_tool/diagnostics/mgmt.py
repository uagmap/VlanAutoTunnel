"""CPE management reachability: TCP connect probe on common web/admin ports."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import socket

# Same set operators use with: nmap -p 80,443,8000,8080,8443,8888 -Pn <ip>
MGMT_PORTS = (80, 443, 8000, 8080, 8443, 8888)
_PROBE_TIMEOUT_SECONDS = 1.0


@dataclass(slots=True)
class MgmtProbe:
    status: str
    summary: str


def probe_cpe_management(ip_address: str) -> MgmtProbe:
    """Report whether any common CPE management TCP port is open from this host."""
    states = _probe_ports(ip_address, MGMT_PORTS)
    open_ports = [port for port, state in states.items() if state == "open"]
    closed_ports = [port for port, state in states.items() if state == "closed"]
    filtered_ports = [port for port, state in states.items() if state == "filtered"]

    if open_ports:
        ports_text = ", ".join(str(port) for port in open_ports)
        return MgmtProbe(
            "PASS",
            f"CPE management: {ip_address} reachable on TCP {ports_text}",
        )

    parts: list[str] = []
    if closed_ports:
        parts.append(f"closed {', '.join(str(port) for port in closed_ports)}")
    if filtered_ports:
        parts.append(f"filtered/timeout {', '.join(str(port) for port in filtered_ports)}")
    detail = "; ".join(parts) if parts else "no ports answered"
    return MgmtProbe(
        "WARN",
        f"CPE management: {ip_address} not reachable for management ({detail})",
    )


def _probe_ports(ip_address: str, ports: tuple[int, ...]) -> dict[int, str]:
    # ponytail: parallel connects keep wall time ~1s; sequential would be 6x timeout.
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        futures = {
            pool.submit(_tcp_connect_state, ip_address, port): port for port in ports
        }
        return {futures[future]: future.result() for future in futures}


def _tcp_connect_state(ip_address: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_PROBE_TIMEOUT_SECONDS)
    try:
        sock.connect((ip_address, port))
        return "open"
    except ConnectionRefusedError:
        return "closed"
    except (TimeoutError, OSError, socket.timeout):
        return "filtered"
    finally:
        sock.close()
