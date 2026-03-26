"""Tests for composite_crawl.py — OpenAPI import path and backward compatibility."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_mcp.scanners.openapi_parser import OpenAPIEndpoint, OpenAPISpec


# ---------------------------------------------------------------------------
# Helper: mock OpenAPI spec result
# ---------------------------------------------------------------------------


def _mock_openapi_spec() -> OpenAPISpec:
    """Build a minimal OpenAPISpec with 2 endpoints for testing."""
    return OpenAPISpec(
        title="Test API",
        version="1.0.0",
        base_url="https://api.example.com",
        endpoints=[
            OpenAPIEndpoint(
                path="/users",
                method="GET",
                auth_required=True,
                auth_schemes=["bearer"],
                tags=["users"],
                summary="List users",
            ),
            OpenAPIEndpoint(
                path="/users/{id}",
                method="GET",
                auth_required=True,
                auth_schemes=["bearer"],
                tags=["users"],
                summary="Get user by ID",
            ),
        ],
        security_schemes={"bearerAuth": {"type": "http", "scheme": "bearer"}},
        total_endpoints=2,
        spec_version="3.0",
    )


# ---------------------------------------------------------------------------
# OpenAPI URL returns endpoints
# ---------------------------------------------------------------------------


class TestCrawlOpenapiUrlReturnsEndpoints:
    @pytest.mark.asyncio
    async def test_openapi_url_produces_endpoints(self):
        """When openapi_url is provided, crawl returns OpenAPI-sourced endpoints."""
        from security_mcp.tools.composite_crawl import crawl

        mock_spec = _mock_openapi_spec()

        mock_parser = AsyncMock()
        mock_parser.fetch_and_parse = AsyncMock(return_value=mock_spec)

        with patch("security_mcp.scanners.openapi_parser.OpenAPIParser", return_value=mock_parser):
            result = await crawl(
                url="https://api.example.com",
                openapi_url="https://api.example.com/openapi.json",
            )

        assert result["crawler"] == "openapi"
        assert result["openapi_source"] is True
        assert result["openapi_url"] == "https://api.example.com/openapi.json"
        assert len(result["api_endpoints"]) == 2
        assert "/users" in result["urls"]
        assert "/users/{id}" in result["urls"]
        mock_parser.fetch_and_parse.assert_called_once_with("https://api.example.com/openapi.json")


# ---------------------------------------------------------------------------
# OpenAPI fallback to HTTP crawl
# ---------------------------------------------------------------------------


class TestCrawlOpenapiFallbackToHttp:
    @pytest.mark.asyncio
    async def test_openapi_failure_falls_back_to_crawl(self):
        """When OpenAPI import fails, crawl falls back to standard HTTP crawl."""
        from security_mcp.tools.composite_crawl import crawl

        # Return enough URLs (>3) to avoid SPA detection triggering browser crawl
        mock_crawl_result = MagicMock()
        mock_crawl_result.to_dict.return_value = {
            "urls": [
                "https://api.example.com/",
                "https://api.example.com/about",
                "https://api.example.com/contact",
                "https://api.example.com/help",
            ],
            "api_endpoints": [],
            "forms": [],
            "js_files": [],
        }

        mock_parser = AsyncMock()
        mock_parser.fetch_and_parse = AsyncMock(side_effect=Exception("Connection refused"))

        mock_crawler = AsyncMock()
        mock_crawler.crawl = AsyncMock(return_value=mock_crawl_result)

        with patch("security_mcp.scanners.openapi_parser.OpenAPIParser", return_value=mock_parser):
            with patch("security_mcp.scanners.crawler.PythonWebCrawler", return_value=mock_crawler):
                result = await crawl(
                    url="https://api.example.com",
                    openapi_url="https://api.example.com/openapi.json",
                )

        # Should have fallen back to HTTP crawl (not browser since >3 URLs found)
        assert result["crawler"] == "http"
        mock_crawler.crawl.assert_called_once()


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestCrawlBackwardCompatible:
    @pytest.mark.asyncio
    async def test_standard_crawl_without_openapi(self):
        """Crawl without openapi_url uses standard HTTP crawler (unchanged behavior)."""
        from security_mcp.tools.composite_crawl import crawl

        # Return >3 URLs to avoid SPA detection
        mock_crawl_result = MagicMock()
        mock_crawl_result.to_dict.return_value = {
            "urls": [
                "http://example.com/",
                "http://example.com/about",
                "http://example.com/contact",
                "http://example.com/faq",
            ],
            "api_endpoints": [],
            "forms": [{"action": "/login", "method": "POST"}],
            "js_files": ["http://example.com/app.js"],
        }

        mock_crawler = AsyncMock()
        mock_crawler.crawl = AsyncMock(return_value=mock_crawl_result)

        with patch("security_mcp.scanners.crawler.PythonWebCrawler", return_value=mock_crawler) as mock_cls:
            result = await crawl(url="http://example.com", depth=2, max_pages=50)

        assert result["crawler"] == "http"
        assert "openapi_source" not in result
        assert len(result["urls"]) == 4
        mock_cls.assert_called_once_with(max_depth=2, max_pages=50)
        mock_crawler.crawl.assert_called_once_with("http://example.com")

    @pytest.mark.asyncio
    async def test_empty_openapi_url_uses_http_crawl(self):
        """Empty string openapi_url is treated as not provided."""
        from security_mcp.tools.composite_crawl import crawl

        # Return >3 URLs to avoid SPA detection
        mock_crawl_result = MagicMock()
        mock_crawl_result.to_dict.return_value = {
            "urls": [
                "http://example.com/",
                "http://example.com/about",
                "http://example.com/contact",
                "http://example.com/faq",
            ],
            "api_endpoints": [],
            "forms": [],
            "js_files": [],
        }

        mock_crawler = AsyncMock()
        mock_crawler.crawl = AsyncMock(return_value=mock_crawl_result)

        with patch("security_mcp.scanners.crawler.PythonWebCrawler", return_value=mock_crawler):
            result = await crawl(url="http://example.com", openapi_url="")

        assert result["crawler"] == "http"
        mock_crawler.crawl.assert_called_once()
