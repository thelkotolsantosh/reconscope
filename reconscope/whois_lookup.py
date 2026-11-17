"""WHOIS lookup for a target domain."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import whois as whois_lib


def _first(value: Any) -> Optional[Any]:
    """WHOIS fields are sometimes a single value, sometimes a list."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _stringify(value: Any) -> Optional[str]:
    value = _first(value)
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def lookup_whois(domain: str) -> Dict[str, Any]:
    """Return a normalized subset of WHOIS data, or an error entry."""
    try:
        record = whois_lib.whois(domain)
    except Exception as exc:  # library raises broadly on parse/network issues
        return {"error": f"WHOIS lookup failed: {exc}"}

    if not record or not record.get("domain_name"):
        return {"error": "No WHOIS data found for this domain."}

    registrar = _stringify(record.get("registrar"))
    creation_date = _stringify(record.get("creation_date"))
    expiration_date = _stringify(record.get("expiration_date"))
    updated_date = _stringify(record.get("updated_date"))

    name_servers: List[str] = []
    raw_ns = record.get("name_servers")
    if isinstance(raw_ns, list):
        name_servers = sorted({ns.lower() for ns in raw_ns if ns})
    elif isinstance(raw_ns, str):
        name_servers = [raw_ns.lower()]

    status = record.get("status")
    if isinstance(status, str):
        status = [status]

    return {
        "registrar": registrar,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "name_servers": name_servers,
        "status": status or [],
        "emails": _first(record.get("emails")) and record.get("emails"),
        "org": _stringify(record.get("org")),
        "country": _stringify(record.get("country")),
    }
