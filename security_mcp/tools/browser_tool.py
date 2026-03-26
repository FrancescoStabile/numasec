"""Browser automation tool using Playwright.

Uses a ``BrowserManager`` class instead of a module-level singleton to
support session-scoped browser lifecycle and safe cleanup.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

logger = logging.getLogger("security_mcp.tools.browser")


class BrowserManager:
    """Session-scoped browser lifecycle manager.

    Create one instance per assessment session.  Call :meth:`ensure_page`
    to lazily start a Chromium browser, reuse it across tool calls, and
    :meth:`close` to tear it down on session end or error.
    """

    def __init__(self) -> None:
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    async def ensure_page(self, headless: bool = True) -> Any:
        """Return an open Playwright page, launching the browser if needed."""
        if self._page is not None and not self._page.is_closed():
            return self._page

        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Playwright not installed. Run: pip install security-mcp[mcp] && playwright install chromium"
            ) from exc

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=headless)
        self._context = await self._browser.new_context(
            user_agent="Mozilla/5.0 (compatible; security-mcp/1.0)",
            ignore_https_errors=True,
        )
        self._page = await self._context.new_page()
        return self._page

    async def close(self) -> None:
        """Tear down the browser, context, and Playwright connection."""
        if self._page and not self._page.is_closed():
            try:
                await self._page.close()
            except Exception:
                pass
        if self._context:
            try:
                await self._context.close()
            except Exception:
                pass
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
        self._page = self._context = self._browser = self._playwright = None

    @property
    def is_open(self) -> bool:
        return self._page is not None and not self._page.is_closed()


# ---------------------------------------------------------------------------
# Default manager (backwards-compatible singleton for non-session callers)
# ---------------------------------------------------------------------------

_default_manager = BrowserManager()


async def _get_page(headless: bool = True) -> Any:
    """Get or create a Playwright page via the default manager."""
    return await _default_manager.ensure_page(headless=headless)


async def browser_navigate(
    url: str,
    wait_for: str = "load",
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Navigate to URL and return page content.

    Parameters
    ----------
    url:
        URL to navigate to.
    wait_for:
        Wait condition: ``load``, ``domcontentloaded``, or ``networkidle``.
    timeout:
        Max wait time in seconds.
    """
    try:
        page = await _get_page()
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    logger.info("Navigating to %s (wait=%s)", url, wait_for)

    try:
        resp = await page.goto(url, wait_until=wait_for, timeout=timeout * 1000)
    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "url": url,
            "body": "",
            "title": "",
        }

    body = await page.content()
    title = await page.title()

    return {
        "success": True,
        "url": str(page.url),
        "status_code": resp.status if resp else 0,
        "title": title,
        "body": body[:500_000],
        "cookies": await page.context.cookies(),
    }


async def browser_click(selector: str) -> dict[str, Any]:
    """Click an element on the page.

    Parameters
    ----------
    selector:
        CSS selector or text selector (e.g. ``text=Login``).
    """
    try:
        page = await _get_page()
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    logger.info("Clicking: %s", selector)

    try:
        await page.click(selector, timeout=10_000)
        await page.wait_for_load_state("domcontentloaded", timeout=5_000)
    except Exception as exc:
        return {"success": False, "error": str(exc), "selector": selector}

    return {
        "success": True,
        "selector": selector,
        "url": str(page.url),
        "title": await page.title(),
    }


async def browser_fill(selector: str, value: str) -> dict[str, Any]:
    """Fill a form field.

    Parameters
    ----------
    selector:
        CSS selector of the input element.
    value:
        Value to type into the field.
    """
    try:
        page = await _get_page()
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    logger.info("Filling %s", selector)

    try:
        await page.fill(selector, value, timeout=10_000)
    except Exception as exc:
        return {"success": False, "error": str(exc), "selector": selector}

    return {
        "success": True,
        "selector": selector,
        "value": value,
    }


async def browser_screenshot() -> dict[str, Any]:
    """Take a screenshot of the current page.

    Returns the screenshot as a base64-encoded PNG.
    """
    try:
        page = await _get_page()
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    logger.info("Taking screenshot")

    try:
        raw = await page.screenshot(full_page=True)
        b64 = base64.b64encode(raw).decode()
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    return {
        "success": True,
        "url": str(page.url),
        "screenshot_b64": b64,
        "size_bytes": len(raw),
    }
