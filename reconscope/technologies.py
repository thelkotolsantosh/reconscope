"""Lightweight technology fingerprinting.

Not a replacement for Wappalyzer — this uses response headers, cookie
names, and simple substring signatures in the HTML body to make
reasonable guesses about the server stack, frameworks, and CDNs in
use. Every signature is intentionally conservative to avoid false
positives.
"""

from __future__ import annotations

from typing import Dict, List, Set

import requests

USER_AGENT = "ReconScope/1.0 (+https://github.com/)"

# header_name -> (substring_to_match_lower_or_None, label)
HEADER_SIGNATURES = [
    ("server", "nginx", "Nginx"),
    ("server", "apache", "Apache"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "microsoft-iis", "IIS"),
    ("x-powered-by", "express", "Express.js"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-generator", "wordpress", "WordPress"),
    ("via", "varnish", "Varnish"),
    ("cf-ray", None, "Cloudflare"),
    ("x-vercel-id", None, "Vercel"),
    ("x-amz-cf-id", None, "Amazon CloudFront"),
    ("x-served-by", "fastly", "Fastly"),
]

COOKIE_SIGNATURES = [
    ("wordpress_", "WordPress"),
    ("csrftoken", "Django"),
    ("laravel_session", "Laravel"),
    ("phpsessid", "PHP"),
    ("jsessionid", "Java (Servlet/JSP)"),
    ("connect.sid", "Express.js"),
]

BODY_SIGNATURES = [
    ("__next_data__", "Next.js"),
    ("data-reactroot", "React"),
    ("ng-version", "Angular"),
    ("id=\"__nuxt\"", "Nuxt.js"),
    ("wp-content", "WordPress"),
    ("cdn.shopify.com", "Shopify"),
    ("data-vue", "Vue.js"),
    ("csrfmiddlewaretoken", "Django"),
]


def fingerprint(domain: str, scheme: str = "https", timeout: float = 10.0) -> List[str]:
    """Return a sorted list of detected technology labels."""
    found: Set[str] = set()

    try:
        response = requests.get(
            f"{scheme}://{domain}",
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException:
        return []

    headers_lower: Dict[str, str] = {
        key.lower(): value.lower() for key, value in response.headers.items()
    }

    for header_name, needle, label in HEADER_SIGNATURES:
        value = headers_lower.get(header_name)
        if value is None:
            continue
        if needle is None or needle in value:
            found.add(label)

    for cookie in response.cookies:
        name = cookie.name.lower()
        for needle, label in COOKIE_SIGNATURES:
            if needle in name:
                found.add(label)

    body_lower = response.text.lower()[:200_000]  # cap for very large pages
    for needle, label in BODY_SIGNATURES:
        if needle in body_lower:
            found.add(label)

    return sorted(found)
