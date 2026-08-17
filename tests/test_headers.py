from reconscope.headers import analyze_security_headers


def test_all_headers_missing():
    result = analyze_security_headers({})
    assert all(status == "MISSING" for status in result.values())


def test_detects_present_headers_case_insensitively():
    headers = {
        "strict-transport-security": "max-age=63072000",
        "X-Frame-Options": "DENY",
    }
    result = analyze_security_headers(headers)
    assert result["Strict-Transport-Security"].startswith("PRESENT")
    assert result["X-Frame-Options"].startswith("PRESENT")
    assert result["Content-Security-Policy"] == "MISSING"


def test_present_value_included_in_status():
    headers = {"X-Content-Type-Options": "nosniff"}
    result = analyze_security_headers(headers)
    assert "nosniff" in result["X-Content-Type-Options"]
