import argparse

import pytest

from reconscope.cli import validate_domain


def test_validate_domain_accepts_plain_domain():
    assert validate_domain("example.com") == "example.com"


def test_validate_domain_strips_scheme_and_path():
    assert validate_domain("https://example.com/some/path") == "example.com"


def test_validate_domain_lowercases():
    assert validate_domain("EXAMPLE.com") == "example.com"


def test_validate_domain_rejects_garbage():
    with pytest.raises(argparse.ArgumentTypeError):
        validate_domain("not a domain!!")
