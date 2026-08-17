"""Open-port scanning.

Prefers a real `nmap` binary (via subprocess) for speed and accuracy.
If nmap isn't installed on the host, falls back to a plain-socket
connect scan over a small, common port list so the tool still works
out of the box.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465,
    587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017,
]

PORT_SERVICE_HINTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _scan_with_nmap(target: str, ports: List[int], timeout: int) -> List[Dict[str, str]]:
    port_arg = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-Pn", "-T4", "-p", port_arg, "-oX", "-", target]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    results: List[Dict[str, str]] = []
    try:
        root = ET.fromstring(proc.stdout)
        for port_el in root.iter("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            results.append(
                {
                    "port": port_el.get("portid"),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": "OPEN",
                    "service": (service_el.get("name") if service_el is not None else "")
                    or "unknown",
                }
            )
    except ET.ParseError:
        return []

    return sorted(results, key=lambda r: int(r["port"]))


def _check_socket(target: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _scan_with_sockets(target: str, ports: List[int], per_port_timeout: float = 1.5) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=min(32, len(ports))) as executor:
        future_to_port = {
            executor.submit(_check_socket, target, port, per_port_timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                results.append(
                    {
                        "port": str(port),
                        "protocol": "tcp",
                        "state": "OPEN",
                        "service": PORT_SERVICE_HINTS.get(port, "unknown"),
                    }
                )
    return sorted(results, key=lambda r: int(r["port"]))


def scan_ports(
    target: str, ports: List[int] | None = None, timeout: int = 60
) -> Dict[str, object]:
    """Scan `target` for open ports. Returns results plus which method was used."""
    ports = ports or COMMON_PORTS

    if _nmap_available():
        results = _scan_with_nmap(target, ports, timeout)
        return {"method": "nmap", "open_ports": results}

    results = _scan_with_sockets(target, ports)
    return {"method": "socket-fallback", "open_ports": results}
