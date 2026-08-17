from unittest.mock import patch

from reconscope.ports import _scan_with_sockets


def test_scan_with_sockets_reports_open_ports():
    with patch("reconscope.ports._check_socket") as mock_check:
        mock_check.side_effect = lambda target, port, timeout: port == 80

        results = _scan_with_sockets("example.com", [22, 80, 443])

    ports_found = {entry["port"] for entry in results}
    assert ports_found == {"80"}
    assert results[0]["state"] == "OPEN"
    assert results[0]["service"] == "http"


def test_scan_with_sockets_returns_empty_when_nothing_open():
    with patch("reconscope.ports._check_socket", return_value=False):
        results = _scan_with_sockets("example.com", [22, 80])

    assert results == []
