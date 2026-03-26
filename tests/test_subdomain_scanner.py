"""Tests for security_mcp.scanners.subdomain_scanner."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from security_mcp.scanners.subdomain_scanner import (
    COMMON_PREFIXES,
    PythonSubdomainScanner,
    SubdomainEntry,
    SubdomainResult,
    python_subdomain_scan,
)


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------


class TestSubdomainEntry:
    def test_defaults(self):
        e = SubdomainEntry(name="www.example.com")
        assert e.name == "www.example.com"
        assert e.ip == ""
        assert e.source == ""


class TestSubdomainResult:
    def test_to_dict_empty(self):
        r = SubdomainResult(domain="example.com")
        d = r.to_dict()
        assert d["domain"] == "example.com"
        assert d["subdomains"] == []
        assert d["total_found"] == 0

    def test_to_dict_with_entries(self):
        r = SubdomainResult(
            domain="example.com",
            subdomains=[
                SubdomainEntry(name="www.example.com", ip="1.2.3.4", source="dns"),
                SubdomainEntry(name="api.example.com", ip="", source="ct"),
            ],
            total_found=2,
            dns_checked=1,
            ct_found=1,
            duration_ms=1234.56,
        )
        d = r.to_dict()
        assert len(d["subdomains"]) == 2
        assert d["subdomains"][0]["source"] == "dns"
        assert d["subdomains"][1]["source"] == "ct"


# ---------------------------------------------------------------------------
# PythonSubdomainScanner — DNS brute-force
# ---------------------------------------------------------------------------


class TestDNSBruteForce:
    @pytest.mark.asyncio
    async def test_dns_resolves_found_subdomains(self):
        """DNS brute-force should find subdomains that resolve."""
        import dns.asyncresolver as _async_resolver

        scanner = PythonSubdomainScanner(dns_concurrency=10, timeout=5.0)

        # Mock answer object
        mock_answer = AsyncMock()
        mock_answer.__getitem__ = lambda self, idx: "1.2.3.4"
        mock_answer.__iter__ = lambda self: iter(["1.2.3.4"])

        # www and api resolve, xyz does not
        async def mock_resolve(fqdn, rdtype):
            if fqdn.startswith("www.") or fqdn.startswith("api."):
                return mock_answer
            raise _async_resolver.NXDOMAIN()

        mock_resolver_instance = AsyncMock()
        mock_resolver_instance.resolve = mock_resolve
        mock_resolver_instance.timeout = 5.0
        mock_resolver_instance.lifetime = 5.0

        with patch.object(_async_resolver, "Resolver", return_value=mock_resolver_instance):
            entries = await scanner._dns_brute_force("example.com", ["www", "api", "xyz"])

        assert len(entries) == 2
        names = {e.name for e in entries}
        assert "www.example.com" in names
        assert "api.example.com" in names
        assert all(e.source == "dns" for e in entries)

    @pytest.mark.asyncio
    async def test_dns_handles_timeout(self):
        """DNS timeout should not crash, just skip the prefix."""
        import dns.asyncresolver as _async_resolver
        import dns.exception

        scanner = PythonSubdomainScanner(dns_concurrency=10, timeout=1.0)

        async def mock_resolve(fqdn, rdtype):
            raise dns.exception.Timeout()

        mock_resolver_instance = AsyncMock()
        mock_resolver_instance.resolve = mock_resolve
        mock_resolver_instance.timeout = 1.0
        mock_resolver_instance.lifetime = 1.0

        with patch.object(_async_resolver, "Resolver", return_value=mock_resolver_instance):
            entries = await scanner._dns_brute_force("example.com", ["www"])

        assert len(entries) == 0


# ---------------------------------------------------------------------------
# PythonSubdomainScanner — Certificate Transparency
# ---------------------------------------------------------------------------


class TestCTLookup:
    @pytest.mark.asyncio
    async def test_ct_parses_crtsh_response(self):
        """CT lookup should parse crt.sh JSON response correctly."""
        ct_response = [
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"},  # Wildcard
            {"name_value": "mail.example.com\nftp.example.com"},  # Multi-line
            {"name_value": "other.domain.com"},  # Different domain, should be filtered
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=ct_response)

        transport = httpx.MockTransport(handler)
        scanner = PythonSubdomainScanner()

        # Use real httpx.AsyncClient with MockTransport
        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("timeout", None)
            original_init(self, *args, timeout=30.0, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            entries = await scanner._ct_lookup("example.com")

        assert len(entries) >= 4  # www, api, example.com (from wildcard), mail, ftp
        names = {e.name for e in entries}
        assert "www.example.com" in names
        assert "api.example.com" in names
        assert all(e.source == "ct" for e in entries)
        # other.domain.com should be filtered
        assert "other.domain.com" not in names

    @pytest.mark.asyncio
    async def test_ct_handles_api_error(self):
        """CT lookup should handle API errors gracefully."""
        scanner = PythonSubdomainScanner()

        def error_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        transport = httpx.MockTransport(error_handler)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("timeout", None)
            original_init(self, *args, timeout=30.0, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            entries = await scanner._ct_lookup("example.com")

        assert entries == []


# ---------------------------------------------------------------------------
# Common prefixes
# ---------------------------------------------------------------------------


class TestCommonPrefixes:
    def test_prefixes_not_empty(self):
        """Built-in prefix list should have reasonable size."""
        assert len(COMMON_PREFIXES) >= 200

    def test_common_prefixes_present(self):
        """Essential prefixes should be in the list."""
        for prefix in ["www", "mail", "api", "dev", "staging", "admin", "vpn"]:
            assert prefix in COMMON_PREFIXES


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


class TestSubdomainToolRegistration:
    def test_registry_has_recon(self):
        """recon (replaces subdomain_scan) should be registered in the default tool registry."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "recon" in registry.available_tools

        schemas = registry.get_schemas()
        recon_schema = next(s for s in schemas if s["function"]["name"] == "recon")
        params = recon_schema["function"]["parameters"]
        assert "target" in params["properties"]
        assert params["required"] == ["target"]
