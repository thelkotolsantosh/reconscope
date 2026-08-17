"""Terminal rendering and JSON/CSV export for a completed scan."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def print_banner(target: str) -> None:
    console.print(
        Panel.fit(
            "[bold cyan]ReconScope v1.0[/bold cyan]\n[dim]Website Reconnaissance & Security Profiling[/dim]",
            border_style="cyan",
        )
    )
    console.print(f"[bold]Target:[/bold] {target}\n")


def print_report(results: Dict[str, Any]) -> None:
    """Render the full scan result set as a readable terminal report."""

    # DNS
    dns_data = results.get("dns", {})
    if dns_data:
        table = Table(title="[+] DNS Records", show_header=True, header_style="bold cyan")
        table.add_column("Type")
        table.add_column("Value")
        for record_type, values in dns_data.items():
            for value in values:
                table.add_row(record_type, value)
        console.print(table)
    else:
        console.print("[+] DNS: [yellow]no records resolved[/yellow]")

    # WHOIS
    whois_data = results.get("whois", {})
    console.print("\n[bold]\\[+] WHOIS[/bold]")
    if whois_data.get("error"):
        console.print(f"    [yellow]{whois_data['error']}[/yellow]")
    else:
        for key in ("registrar", "creation_date", "expiration_date", "org", "country"):
            if whois_data.get(key):
                console.print(f"    {key:<16}: {whois_data[key]}")

    # Subdomains
    subdomains = results.get("subdomains", [])
    console.print(f"\n[bold]\\[+] Subdomains[/bold] ({len(subdomains)} found)")
    for sub in subdomains[:25]:
        console.print(f"    {sub}")
    if len(subdomains) > 25:
        console.print(f"    ... and {len(subdomains) - 25} more (see report file)")

    # HTTP + technologies
    http_data = results.get("http", {})
    console.print("\n[bold]\\[+] HTTP[/bold]")
    if http_data.get("reachable"):
        console.print(f"    Scheme       : {http_data.get('scheme')}")
        console.print(f"    Status       : {http_data.get('status_code')}")
        console.print(f"    Server       : {http_data.get('server') or 'unknown'}")
        if http_data.get("tls_warning"):
            console.print(f"    [yellow]TLS warning  : {http_data['tls_warning']}[/yellow]")
    else:
        console.print("    [yellow]Target did not respond over HTTP or HTTPS[/yellow]")

    technologies = results.get("technologies", [])
    console.print("\n[bold]\\[+] Technologies[/bold]")
    if technologies:
        for tech in technologies:
            console.print(f"    {tech}")
    else:
        console.print("    [dim]none confidently detected[/dim]")

    # Security headers
    sec_headers = results.get("security_headers", {})
    if sec_headers:
        table = Table(title="[+] Security Headers", show_header=True, header_style="bold cyan")
        table.add_column("Header")
        table.add_column("Status")
        for header, status in sec_headers.items():
            style = "green" if status.startswith("PRESENT") else "red"
            table.add_row(header, f"[{style}]{status}[/{style}]")
        console.print(table)

    # TLS
    tls_data = results.get("tls", {})
    if tls_data and not tls_data.get("error"):
        console.print("\n[bold]\\[+] TLS Certificate[/bold]")
        console.print(f"    Issuer       : {tls_data.get('issuer')}")
        console.print(f"    Subject      : {tls_data.get('subject')}")
        console.print(f"    Expires      : {tls_data.get('not_after')} ({tls_data.get('expires_in_days')} days)")
        console.print(f"    TLS version  : {tls_data.get('tls_version')}")
    elif tls_data.get("error"):
        console.print(f"\n[bold]\\[+] TLS Certificate[/bold]\n    [yellow]{tls_data['error']}[/yellow]")

    # Robots.txt
    robots = results.get("robots", {})
    console.print("\n[bold]\\[+] robots.txt[/bold]")
    if robots.get("found"):
        console.print(f"    Disallowed paths : {len(robots.get('disallowed_paths', []))}")
        console.print(f"    Sitemaps         : {len(robots.get('sitemaps', []))}")
    else:
        console.print("    [dim]not found[/dim]")

    # Ports
    port_data = results.get("ports", {})
    open_ports = port_data.get("open_ports", [])
    table = Table(
        title=f"[+] Ports (method: {port_data.get('method', 'n/a')})",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Port")
    table.add_column("Protocol")
    table.add_column("State")
    table.add_column("Service")
    for entry in open_ports:
        table.add_row(entry["port"], entry["protocol"], f"[green]{entry['state']}[/green]", entry["service"])
    console.print(table)
    if not open_ports:
        console.print("    [dim]no open ports found in scanned range[/dim]")


def export_json(results: Dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    return path


def export_csv(results: Dict[str, Any], path: Path) -> Path:
    """Flatten the scan into a simple category/key/value CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    for record_type, values in results.get("dns", {}).items():
        for value in values:
            rows.append(("dns", record_type, value))

    for key, value in results.get("whois", {}).items():
        rows.append(("whois", key, value))

    for sub in results.get("subdomains", []):
        rows.append(("subdomain", "host", sub))

    for key, value in results.get("http", {}).items():
        if key != "headers":
            rows.append(("http", key, value))

    for tech in results.get("technologies", []):
        rows.append(("technology", "detected", tech))

    for header, status in results.get("security_headers", {}).items():
        rows.append(("security_header", header, status))

    for key, value in results.get("tls", {}).items():
        rows.append(("tls", key, value))

    robots = results.get("robots", {})
    rows.append(("robots", "found", robots.get("found", False)))
    for p in robots.get("disallowed_paths", []):
        rows.append(("robots", "disallowed_path", p))

    for entry in results.get("ports", {}).get("open_ports", []):
        rows.append(("port", entry["port"], f"{entry['service']} ({entry['state']})"))

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["category", "key", "value"])
        writer.writerows(rows)

    return path


def build_metadata(target: str) -> Dict[str, str]:
    return {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "tool": "ReconScope",
        "version": "1.0.0",
    }
