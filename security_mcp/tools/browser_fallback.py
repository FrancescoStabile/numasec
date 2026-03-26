"""Lightweight browser fallback using httpx for non-JS pages."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger("security_mcp.tools.browser_fallback")


async def fetch_page(url: str, timeout: float = 30.0) -> dict[str, Any]:
    """Fetch page content via httpx (no JS execution).

    Lightweight alternative to Playwright for pages that don't require
    JavaScript rendering.
    """
    logger.info("Fetching (no-JS): %s", url)
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-mcp/1.0)"},
        ) as client:
            resp = await client.get(url)
    except httpx.TimeoutException:
        return {
            "success": False,
            "error": f"Timeout after {timeout}s",
            "url": url,
            "body": "",
        }
    except httpx.RequestError as exc:
        return {
            "success": False,
            "error": str(exc),
            "url": url,
            "body": "",
        }

    elapsed_ms = round((time.monotonic() - start) * 1000)

    return {
        "success": True,
        "url": str(resp.url),
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "body": resp.text[:500_000],
        "elapsed_ms": elapsed_ms,
        "content_type": resp.headers.get("content-type", ""),
    }
