"""HTTP/HTTPS probing: reachability, security headers, robots.txt, TLS info."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

USER_AGENT = "ReconScope/1.0 (+https://github.com/)"

# Security headers we check for, and what a missing header implies.
SECURITY_HEADERS: List[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


def detect_http(domain: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Try HTTPS first, fall back to HTTP. Returns connection + header info."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = session.get(
                url, timeout=timeout, allow_redirects=True, verify=True
            )
            return {
                "scheme": scheme,
                "reachable": True,
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "server": response.headers.get("Server"),
            }
        except requests.exceptions.SSLError:
            # Site answers on HTTPS but with a bad cert — still worth noting.
            try:
                response = session.get(
                    url, timeout=timeout, allow_redirects=True, verify=False
                )
                return {
                    "scheme": scheme,
                    "reachable": True,
                    "final_url": response.url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "server": response.headers.get("Server"),
                    "tls_warning": "Certificate validation failed",
                }
            except requests.RequestException:
                continue
        except requests.RequestException:
            continue

    return {"scheme": None, "reachable": False}


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return PRESENT/MISSING for each header we care about (case-insensitive)."""
    lowered = {key.lower(): value for key, value in headers.items()}
    result: Dict[str, str] = {}
    for header in SECURITY_HEADERS:
        if header.lower() in lowered:
            result[header] = f"PRESENT ({lowered[header.lower()]})"
        else:
            result[header] = "MISSING"
    return result


def fetch_robots_txt(domain: str, scheme: str = "https", timeout: float = 10.0) -> Dict[str, Any]:
    """Fetch and lightly parse robots.txt, if present."""
    url = f"{scheme}://{domain}/robots.txt"
    try:
        response = requests.get(
            url, timeout=timeout, headers={"User-Agent": USER_AGENT}
        )
        if response.status_code != 200:
            return {"found": False, "url": url, "status_code": response.status_code}

        lines = [line.strip() for line in response.text.splitlines()]
        disallowed = [
            line.split(":", 1)[1].strip()
            for line in lines
            if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
        ]
        sitemaps = [
            line.split(":", 1)[1].strip()
            for line in lines
            if line.lower().startswith("sitemap:")
        ]
        return {
            "found": True,
            "url": url,
            "disallowed_paths": disallowed,
            "sitemaps": sitemaps,
            "raw_length": len(response.text),
        }
    except requests.RequestException as exc:
        return {"found": False, "url": url, "error": str(exc)}


def get_tls_info(domain: str, port: int = 443, timeout: float = 8.0) -> Optional[Dict[str, Any]]:
    """Grab basic certificate info via a raw TLS handshake."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        expires_in_days = None
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expires_in_days = (expiry - datetime.utcnow()).days
            except ValueError:
                pass

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject": subject.get("commonName"),
            "not_before": not_before,
            "not_after": not_after,
            "expires_in_days": expires_in_days,
            "tls_version": cipher[1] if cipher else None,
            "cipher": cipher[0] if cipher else None,
            "san": [entry[1] for entry in cert.get("subjectAltName", [])],
        }
    except Exception as exc:
        return {"error": str(exc)}
