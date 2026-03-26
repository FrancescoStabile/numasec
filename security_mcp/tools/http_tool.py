"""HTTP request tool for web testing."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger("security_mcp.tools.http")


async def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    follow_redirects: bool = True,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Execute an HTTP request and return structured response.

    Returns dict with status_code, headers, body, elapsed_ms,
    redirect_chain, and success flag.
    """
    method = method.upper()
    request_headers = dict(headers) if headers else {}
    if "User-Agent" not in request_headers:
        request_headers["User-Agent"] = "Mozilla/5.0 (compatible; security-mcp/1.0)"

    logger.info("%s %s", method, url)
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=False,
        ) as client:
            resp = await client.request(
                method,
                url,
                headers=request_headers,
                content=body.encode() if body else None,
            )
    except httpx.TimeoutException:
        return {
            "success": False,
            "error": f"Timeout after {timeout}s",
            "url": url,
            "status_code": 0,
            "headers": {},
            "body": "",
            "elapsed_ms": round((time.monotonic() - start) * 1000),
        }
    except httpx.RequestError as exc:
        return {
            "success": False,
            "error": str(exc),
            "url": url,
            "status_code": 0,
            "headers": {},
            "body": "",
            "elapsed_ms": round((time.monotonic() - start) * 1000),
        }

    elapsed_ms = round((time.monotonic() - start) * 1000)
    resp_headers = dict(resp.headers)
    body_text = resp.text[:500_000]  # Cap at 500KB

    redirect_chain = []
    if resp.history:
        redirect_chain = [{"url": str(r.url), "status_code": r.status_code} for r in resp.history]

    # Build request dump for evidence chain (S5).
    # httpx.Response.request holds the actual Request object sent on the wire.
    req = resp.request
    req_headers_lines = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
    req_body_str = req.content.decode("utf-8", errors="replace") if req.content else ""
    request_dump = f"{req.method} {req.url}\n{req_headers_lines}"
    if req_body_str:
        request_dump += f"\n\n{req_body_str}"

    return {
        "success": True,
        "url": str(resp.url),
        "status_code": resp.status_code,
        "headers": resp_headers,
        "body": body_text,
        "elapsed_ms": elapsed_ms,
        "redirect_chain": redirect_chain,
        "content_type": resp_headers.get("content-type", ""),
        "content_length": len(resp.content),
        # Evidence chain fields — consumed by extractor pipeline
        "request_dump": request_dump,
        "response_status": resp.status_code,
    }
