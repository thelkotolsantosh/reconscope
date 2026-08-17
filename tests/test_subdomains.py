import json

import responses

from reconscope.subdomains import discover_subdomains


@responses.activate
def test_discover_subdomains_parses_and_dedupes():
    payload = [
        {"name_value": "api.example.com"},
        {"name_value": "dev.example.com\napi.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "unrelated.org"},
    ]
    responses.add(
        responses.GET,
        "https://crt.sh/",
        body=json.dumps(payload),
        status=200,
        content_type="application/json",
    )

    result = discover_subdomains("example.com")

    assert result == ["api.example.com", "dev.example.com", "example.com"]


@responses.activate
def test_discover_subdomains_returns_empty_on_failure():
    responses.add(responses.GET, "https://crt.sh/", status=500)

    result = discover_subdomains("example.com")

    assert result == []


@responses.activate
def test_discover_subdomains_handles_bad_json():
    responses.add(
        responses.GET,
        "https://crt.sh/",
        body="not json",
        status=200,
    )

    result = discover_subdomains("example.com")

    assert result == []
