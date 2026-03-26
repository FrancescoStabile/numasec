"""Composite crawl tool — auto-detects SPA and uses browser if needed, supports OpenAPI import."""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

logger = logging.getLogger(__name__)


async def crawl(
    url: str,
    depth: int = 2,
    max_pages: int = 50,
    force_browser: bool = False,
    openapi_url: str = "",
) -> dict[str, Any]:
    """Smart crawl: auto-detects SPA and uses browser crawl if needed.
    Optionally imports endpoints from an OpenAPI/Swagger specification.

    Args:
        url: Starting URL for the crawl.
        depth: Maximum crawl depth (default: 2).
        max_pages: Maximum pages to crawl (default: 50).
        force_browser: Force browser-based crawling even for non-SPA sites.
        openapi_url: URL to an OpenAPI/Swagger spec (JSON or YAML). When provided,
            endpoints are extracted from the spec and returned in standard crawl format.
    """
    # ------------------------------------------------------------------
    # OpenAPI import path — fast, deterministic, no crawling needed
    # ------------------------------------------------------------------
    if openapi_url:
        try:
            from security_mcp.scanners.openapi_parser import OpenAPIParser

            parser = OpenAPIParser()
            spec = await parser.fetch_and_parse(openapi_url)
            endpoints = spec.endpoints
            api_eps = [asdict(ep) for ep in endpoints]
            return {
                "crawler": "openapi",
                "openapi_source": True,
                "openapi_url": openapi_url,
                "spec_title": spec.title,
                "spec_version": spec.spec_version,
                "base_url": spec.base_url,
                "urls": list({ep.path for ep in endpoints}),
                "api_endpoints": api_eps,
                "security_schemes": spec.security_schemes,
                "forms": [],
                "js_files": [],
                "endpoint_count": spec.total_endpoints,
            }
        except Exception as exc:
            logger.warning("OpenAPI import failed, falling back to HTTP crawl: %s", exc)
            # Fall through to standard crawl on failure

    from security_mcp.scanners.crawler import PythonWebCrawler

    # Step 1: HTTP-based crawl (max_depth and max_pages are constructor args)
    crawler = PythonWebCrawler(max_depth=depth, max_pages=max_pages)
    crawl_result = await crawler.crawl(url)
    result_dict = crawl_result.to_dict()
    result_dict["crawler"] = "http"

    # Step 2: Detect SPA or sparse results
    urls_found = len(result_dict.get("urls", []))
    is_spa = urls_found <= 3

    if is_spa or force_browser:
        try:
            from security_mcp.scanners.browser_crawler import BrowserCrawler

            browser_crawler = BrowserCrawler(max_pages=max_pages)
            browser_result = await browser_crawler.crawl(url)
            browser_dict = browser_result.to_dict()

            # Merge results — deduplicate URLs and JS files
            existing_urls = set(result_dict.get("urls", []))
            for u in browser_dict.get("urls", []):
                if u not in existing_urls:
                    result_dict.setdefault("urls", []).append(u)
                    existing_urls.add(u)

            for ep in browser_dict.get("api_endpoints", []):
                result_dict.setdefault("api_endpoints", []).append(ep)

            for f in browser_dict.get("forms", []):
                result_dict.setdefault("forms", []).append(f)

            existing_js = set(result_dict.get("js_files", []))
            for js in browser_dict.get("js_files", []):
                if js not in existing_js:
                    result_dict.setdefault("js_files", []).append(js)
                    existing_js.add(js)

            # Include browser-specific fields
            if browser_dict.get("fragment_routes"):
                result_dict["fragment_routes"] = browser_dict["fragment_routes"]
            if browser_dict.get("technologies"):
                result_dict["spa_technologies"] = browser_dict["technologies"]

            result_dict["crawler"] = "browser"
            result_dict["spa_detected"] = True
        except ImportError:
            result_dict["browser_crawl_note"] = "Playwright not available; used HTTP-only crawl"
        except Exception as exc:
            result_dict["browser_crawl_error"] = str(exc)

    return result_dict
