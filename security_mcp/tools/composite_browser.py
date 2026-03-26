"""Composite browser tool — navigate, click, fill, screenshot in one tool."""

from __future__ import annotations

import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)


async def browser(
    action: Literal["navigate", "click", "fill", "screenshot"],
    url: str = "",
    selector: str = "",
    value: str = "",
    wait_for: str = "load",
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Interact with a headless browser: navigate, click, fill forms, take screenshots.

    Args:
        action: Browser action — navigate, click, fill, or screenshot.
        url: URL to navigate to (required for navigate action).
        selector: CSS or text selector (required for click and fill actions).
        value: Value to type (required for fill action).
        wait_for: Wait condition for navigate: load, domcontentloaded, networkidle.
        timeout: Navigation timeout in seconds.
    """
    from security_mcp.tools.browser_tool import (
        browser_click,
        browser_fill,
        browser_navigate,
        browser_screenshot,
    )

    if action == "navigate":
        if not url:
            return {"error": "url is required for navigate action"}
        return await browser_navigate(url=url, wait_for=wait_for, timeout=timeout)
    elif action == "click":
        if not selector:
            return {"error": "selector is required for click action"}
        return await browser_click(selector=selector)
    elif action == "fill":
        if not selector or not value:
            return {"error": "selector and value are required for fill action"}
        return await browser_fill(selector=selector, value=value)
    elif action == "screenshot":
        return await browser_screenshot()
    else:
        return {"error": f"Unknown action: {action}. Use: navigate, click, fill, screenshot"}
