"""Subdomain discovery via certificate transparency logs (crt.sh).

crt.sh exposes a public JSON API over Postgres-backed cert transparency
data. We query it, extract every unique hostname mentioned in the
matched certificates, and filter to those under the target domain.
"""

from __future__ import annotations

import json
from typing import List, Set

import requests

CRT_SH_URL = "https://crt.sh/"


def discover_subdomains(domain: str, timeout: float = 15.0) -> List[str]:
    """Return a sorted list of unique subdomains found for `domain`.

    Returns an empty list (never raises) if the lookup fails — cert
    transparency is a best-effort enrichment step, not a hard
    dependency of the scan.
    """
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": "ReconScope/1.0 (+https://github.com/)"}

    try:
        response = requests.get(
            CRT_SH_URL, params=params, headers=headers, timeout=timeout
        )
        response.raise_for_status()
        data = json.loads(response.text)
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []

    found: Set[str] = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            candidate = line.strip().lower().lstrip("*.")
            if not candidate:
                continue
            if candidate == domain or candidate.endswith(f".{domain}"):
                found.add(candidate)
            elif candidate == domain.lower():
                found.add(candidate)

    return sorted(found)
