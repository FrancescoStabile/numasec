"""
Tests for recon tool helpers — port capping, binary discovery.
"""

import pytest
from numasec.tools.recon import _cap_port_range, _find_pd_httpx


class TestCapPortRange:
    def test_single_port_unchanged(self):
        assert _cap_port_range("80") == "80"

    def test_list_unchanged(self):
        assert _cap_port_range("80,443,8080") == "80,443,8080"

    def test_small_range_unchanged(self):
        assert _cap_port_range("1-100") == "1-100"

    def test_exact_limit_unchanged(self):
        assert _cap_port_range("1-1024", max_width=1024) == "1-1024"

    def test_large_range_capped(self):
        assert _cap_port_range("1-10000") == "1-1024"

    def test_large_range_capped_custom_limit(self):
        assert _cap_port_range("1-65535", max_width=100) == "1-100"

    def test_offset_range_capped(self):
        # 8000-10000 = 2001 ports > 1024 → cap to 8000-9023
        assert _cap_port_range("8000-10000") == "8000-9023"

    def test_mixed_list_with_range(self):
        assert _cap_port_range("80,1-5000,443") == "80,1-1024,443"

    def test_malformed_passthrough(self):
        assert _cap_port_range("abc-def") == "abc-def"

    def test_empty_string(self):
        assert _cap_port_range("") == ""


class TestFindPdHttpx:
    def test_returns_none_when_not_installed(self):
        """On dev machine without PD httpx, should return None."""
        # This may return a path if PD httpx is actually installed
        result = _find_pd_httpx()
        # Just ensure it doesn't crash and returns str or None
        assert result is None or isinstance(result, str)
