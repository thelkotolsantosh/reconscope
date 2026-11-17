from unittest.mock import patch
from reconscope.dns_enum import enumerate_dns


def test_collects_records_after_an_empty_lookup():
    with patch('reconscope.dns_enum._resolve', side_effect=[[], ['::1'], [], [], ['sample'], [], []]):
        assert enumerate_dns('example.com') == {'AAAA': ['::1'], 'TXT': ['sample']}
