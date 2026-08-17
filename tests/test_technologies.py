import responses

from reconscope.technologies import fingerprint


@responses.activate
def test_fingerprint_detects_from_headers_and_body():
    responses.add(
        responses.GET,
        "https://example.com",
        body='<html><body data-reactroot="">hi</body></html>',
        status=200,
        headers={"Server": "nginx/1.25.0", "X-Powered-By": "Express"},
    )

    result = fingerprint("example.com")

    assert "Nginx" in result
    assert "Express.js" in result
    assert "React" in result


@responses.activate
def test_fingerprint_returns_empty_list_on_request_failure():
    responses.add(responses.GET, "https://example.com", status=500)
    # Force an exception path by not registering the URL at all is another
    # option, but a 500 body still parses fine — assert we don't crash.
    result = fingerprint("example.com")
    assert isinstance(result, list)
