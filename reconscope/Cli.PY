"""ReconScope command-line entrypoint."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict

from . import __version__
from .dns_enum import enumerate_dns
from .headers import analyze_security_headers, detect_http, fetch_robots_txt, get_tls_info
from .ports import scan_ports
from .reporter import build_metadata, export_csv, export_json, print_banner, print_report, console
from .subdomains import discover_subdomains
from .technologies import fingerprint
from .whois_lookup import lookup_whois

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    if not DOMAIN_RE.match(domain):
        raise argparse.ArgumentTypeError(f"'{domain}' does not look like a valid domain")
    return domain


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconscope",
        description="ReconScope — Website Reconnaissance & Security Profiling CLI",
    )
    parser.add_argument("domain", type=validate_domain, help="Target domain, e.g. example.com")
    parser.add_argument(
        "-o", "--output-dir", default="reports", help="Directory for exported reports (default: reports/)"
    )
    parser.add_argument(
        "--skip-ports", action="store_true", help="Skip the port scan (useful for slow/blocked networks)"
    )
    parser.add_argument(
        "--skip-subdomains", action="store_true", help="Skip certificate-transparency subdomain discovery"
    )
    parser.add_argument(
        "--no-export", action="store_true", help="Print the report only; don't write JSON/CSV files"
    )
    parser.add_argument("--version", action="version", version=f"ReconScope {__version__}")
    return parser


def run_scan(domain: str, skip_ports: bool = False, skip_subdomains: bool = False) -> Dict[str, Any]:
    results: Dict[str, Any] = {"metadata": build_metadata(domain)}

    with console.status("[cyan]Enumerating DNS records...[/cyan]"):
        results["dns"] = enumerate_dns(domain)

    with console.status("[cyan]Running WHOIS lookup...[/cyan]"):
        results["whois"] = lookup_whois(domain)

    if not skip_subdomains:
        with console.status("[cyan]Discovering subdomains via certificate transparency...[/cyan]"):
            results["subdomains"] = discover_subdomains(domain)
    else:
        results["subdomains"] = []

    with console.status("[cyan]Probing HTTP/HTTPS...[/cyan]"):
        http_data = detect_http(domain)
        results["http"] = http_data

    scheme = http_data.get("scheme") or "https"

    results["security_headers"] = analyze_security_headers(http_data.get("headers", {}))

    with console.status("[cyan]Fingerprinting technologies...[/cyan]"):
        results["technologies"] = fingerprint(domain, scheme=scheme)

    with console.status("[cyan]Fetching robots.txt...[/cyan]"):
        results["robots"] = fetch_robots_txt(domain, scheme=scheme)

    with console.status("[cyan]Reading TLS certificate...[/cyan]"):
        results["tls"] = get_tls_info(domain) or {}

    if not skip_ports:
        with console.status("[cyan]Scanning common ports...[/cyan]"):
            results["ports"] = scan_ports(domain)
    else:
        results["ports"] = {"method": "skipped", "open_ports": []}

    return results


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print_banner(args.domain)

    try:
        results = run_scan(
            args.domain, skip_ports=args.skip_ports, skip_subdomains=args.skip_subdomains
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return 130
    except Exception as exc:  # last-resort guard so users get a clean error, not a traceback
        console.print(f"\n[bold red]Scan failed:[/bold red] {exc}")
        return 1

    print_report(results)

    if not args.no_export:
        output_dir = Path(args.output_dir)
        json_path = export_json(results, output_dir / f"{args.domain}_report.json")
        csv_path = export_csv(results, output_dir / f"{args.domain}_report.csv")
        console.print("\n[bold]\\[+] Report[/bold]")
        console.print(f"    {json_path}")
        console.print(f"    {csv_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
