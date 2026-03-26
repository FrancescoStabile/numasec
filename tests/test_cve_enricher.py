"""Tests for security_mcp.scanners.cve_enricher — CVE enrichment engine."""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_mcp.scanners.cve_enricher import (
    CVEEnricher,
    CVEMatch,
    _BANNER_PATTERNS,
    _CACHE_TTL_SECONDS,
    _CPE_VENDOR_MAP,
    _SERVICE_ALIASES,
)


# ---------------------------------------------------------------------------
# KB lookup
# ---------------------------------------------------------------------------


class TestLocalKbLookupKnownService:
    @pytest.mark.asyncio
    async def test_known_service_returns_cves(self):
        """A service with KB entries (e.g. Apache 2.4.49) returns matching CVEs."""
        enricher = CVEEnricher.__new__(CVEEnricher)
        enricher._kb_loaded = True
        enricher._kb_entries = {
            "apache": [
                {
                    "version": "2.4.49",
                    "cve_id": "CVE-2021-41773",
                    "cvss_score": 7.5,
                    "exploit": True,
                    "summary": "Path traversal in Apache HTTP Server 2.4.49",
                },
                {
                    "version": "2.4.50",
                    "cve_id": "CVE-2021-42013",
                    "cvss_score": 9.8,
                    "exploit": True,
                    "summary": "RCE via path traversal in Apache 2.4.50",
                },
            ],
        }

        matches = await enricher.lookup("apache", "2.4.49")
        assert len(matches) == 1
        assert matches[0].cve_id == "CVE-2021-41773"
        assert matches[0].cvss_score == 7.5
        assert matches[0].source == "kb"


class TestLocalKbLookupUnknownService:
    @pytest.mark.asyncio
    async def test_unknown_service_returns_empty(self):
        """A service not in the KB returns an empty list."""
        enricher = CVEEnricher.__new__(CVEEnricher)
        enricher._kb_loaded = True
        enricher._kb_entries = {}

        matches = await enricher.lookup("totally_unknown_service", "1.0.0")
        assert matches == []


# ---------------------------------------------------------------------------
# Banner parsing
# ---------------------------------------------------------------------------


class TestBannerParsing:
    def test_ssh_banner(self):
        svc, ver = CVEEnricher._parse_version("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        assert svc == "openssh"
        assert ver == "8.2"

    def test_apache_banner(self):
        svc, ver = CVEEnricher._parse_version("Apache/2.4.49 (Unix)")
        assert svc == "apache"
        assert ver == "2.4.49"

    def test_nginx_banner(self):
        svc, ver = CVEEnricher._parse_version("nginx/1.18.0")
        assert svc == "nginx"
        assert ver == "1.18.0"

    def test_mysql_banner(self):
        svc, ver = CVEEnricher._parse_version("MySQL 5.7.38")
        assert svc == "mysql"
        assert ver == "5.7.38"

    def test_redis_banner(self):
        svc, ver = CVEEnricher._parse_version("Redis v=7.0.11")
        assert svc == "redis"
        assert ver == "7.0.11"

    def test_empty_banner(self):
        svc, ver = CVEEnricher._parse_version("")
        assert svc == ""
        assert ver == ""

    def test_unknown_banner(self):
        svc, ver = CVEEnricher._parse_version("Some Random Banner With No Pattern")
        assert svc == ""
        assert ver == ""


# ---------------------------------------------------------------------------
# CPE string generation
# ---------------------------------------------------------------------------


class TestCpeStringGeneration:
    def test_known_service_cpe(self):
        """Known services map to correct CPE vendor:product pair."""
        assert _CPE_VENDOR_MAP["apache"] == ("apache", "http_server")
        assert _CPE_VENDOR_MAP["nginx"] == ("f5", "nginx")
        assert _CPE_VENDOR_MAP["openssh"] == ("openbsd", "openssh")
        assert _CPE_VENDOR_MAP["redis"] == ("redis", "redis")

    def test_cpe_format_in_nvd_query(self):
        """Verify CPE 2.3 format string is correctly constructed."""
        vendor, product = _CPE_VENDOR_MAP["apache"]
        version = "2.4.49"
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        assert cpe == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


# ---------------------------------------------------------------------------
# NVD API
# ---------------------------------------------------------------------------


class TestNvdApiLookup:
    @pytest.mark.asyncio
    async def test_nvd_api_returns_cve_matches(self):
        """Mock a successful NVD API response and verify parsing."""
        enricher = CVEEnricher.__new__(CVEEnricher)
        enricher._kb_loaded = True
        enricher._kb_entries = {}

        nvd_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                        },
                        "descriptions": [
                            {"lang": "en", "value": "Critical RCE in test service"}
                        ],
                        "references": [{"tags": ["Exploit"], "url": "https://exploit.example.com"}],
                    }
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = nvd_response

        with patch.dict("os.environ", {"SECMCP_NVD_API_KEY": "test-key"}):
            with patch.object(enricher, "_cache_get", return_value=None):
                with patch.object(enricher, "_cache_set", new_callable=AsyncMock):
                    with patch("httpx.AsyncClient") as mock_client_cls:
                        mock_client = AsyncMock()
                        mock_client.get = AsyncMock(return_value=mock_resp)
                        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                        mock_client.__aexit__ = AsyncMock(return_value=False)
                        mock_client_cls.return_value = mock_client

                        matches = await enricher.lookup("testservice", "1.0.0")

        assert len(matches) == 1
        assert matches[0].cve_id == "CVE-2023-12345"
        assert matches[0].cvss_score == 9.8
        assert matches[0].severity == "critical"
        assert matches[0].exploit_available is True
        assert matches[0].source == "nvd"


class TestNvdApiRateLimited:
    @pytest.mark.asyncio
    async def test_nvd_429_triggers_retry(self):
        """HTTP 429 from NVD triggers exponential backoff retry."""
        enricher = CVEEnricher.__new__(CVEEnricher)
        enricher._kb_loaded = True
        enricher._kb_entries = {}

        mock_resp_429 = MagicMock()
        mock_resp_429.status_code = 429

        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200
        mock_resp_200.json.return_value = {"vulnerabilities": []}

        call_count = 0

        async def mock_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return mock_resp_429
            return mock_resp_200

        with patch.dict("os.environ", {"SECMCP_NVD_API_KEY": "test-key"}):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with patch("httpx.AsyncClient") as mock_client_cls:
                    mock_client = AsyncMock()
                    mock_client.get = mock_get
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=False)
                    mock_client_cls.return_value = mock_client

                    matches = await enricher._query_nvd("apache", "2.4.49")

        assert matches == []
        assert call_count == 3  # 2 retries + 1 success


class TestNvdApiDisabledWithoutKey:
    @pytest.mark.asyncio
    async def test_no_api_key_skips_nvd(self):
        """Without SECMCP_NVD_API_KEY, lookup returns empty (no API calls)."""
        enricher = CVEEnricher.__new__(CVEEnricher)
        enricher._kb_loaded = True
        enricher._kb_entries = {}

        with patch.dict("os.environ", {}, clear=True):
            # Remove the key if present
            import os
            os.environ.pop("SECMCP_NVD_API_KEY", None)

            with patch.object(enricher, "_query_nvd", new_callable=AsyncMock) as mock_nvd:
                matches = await enricher.lookup("apache", "2.4.49")

        assert matches == []
        mock_nvd.assert_not_called()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class TestCacheHit:
    @pytest.mark.asyncio
    async def test_cached_results_returned(self):
        """Cached CVE results are returned without triggering an API call."""
        enricher = CVEEnricher.__new__(CVEEnricher)
        enricher._kb_loaded = True
        enricher._kb_entries = {}

        cached_match = CVEMatch(
            cve_id="CVE-2023-99999",
            cvss_score=8.0,
            severity="high",
            summary="Cached vuln",
            exploit_available=False,
            source="nvd",
        )

        with patch.dict("os.environ", {"SECMCP_NVD_API_KEY": "test-key"}):
            with patch.object(enricher, "_cache_get", return_value=[cached_match]):
                with patch.object(enricher, "_query_nvd", new_callable=AsyncMock) as mock_nvd:
                    matches = await enricher.lookup("apache", "2.4.49")

        assert len(matches) == 1
        assert matches[0].cve_id == "CVE-2023-99999"
        mock_nvd.assert_not_called()


class TestCacheExpiry:
    @pytest.mark.asyncio
    async def test_expired_cache_triggers_fresh_lookup(self):
        """Expired cache entries return None, triggering a fresh NVD query."""
        enricher = CVEEnricher.__new__(CVEEnricher)
        enricher._kb_loaded = True
        enricher._kb_entries = {}

        with patch.dict("os.environ", {"SECMCP_NVD_API_KEY": "test-key"}):
            # _cache_get returns None for expired
            with patch.object(enricher, "_cache_get", return_value=None):
                with patch.object(enricher, "_cache_set", new_callable=AsyncMock):
                    with patch.object(enricher, "_query_nvd", return_value=[]) as mock_nvd:
                        matches = await enricher.lookup("apache", "2.4.49")

        mock_nvd.assert_called_once()
        assert matches == []


# ---------------------------------------------------------------------------
# Service name normalization
# ---------------------------------------------------------------------------


class TestServiceNameNormalization:
    def test_httpd_to_apache(self):
        assert CVEEnricher._normalize_service("httpd") == "apache"

    def test_apache_httpd_to_apache(self):
        assert CVEEnricher._normalize_service("Apache httpd") == "apache"

    def test_ssh_to_openssh(self):
        assert CVEEnricher._normalize_service("ssh") == "openssh"

    def test_microsoft_iis(self):
        assert CVEEnricher._normalize_service("Microsoft-IIS") == "iis"

    def test_postgres_to_postgresql(self):
        assert CVEEnricher._normalize_service("postgres") == "postgresql"

    def test_node_to_nodejs(self):
        assert CVEEnricher._normalize_service("node") == "nodejs"

    def test_empty_string(self):
        assert CVEEnricher._normalize_service("") == ""
