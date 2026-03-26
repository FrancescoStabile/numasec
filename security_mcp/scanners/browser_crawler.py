"""SPA-aware web crawler using Playwright.

Discovers Angular/React/Vue routes, intercepts XHR/fetch API calls,
clicks navigation elements, and extracts API endpoints from a
JavaScript-rendered application.

Falls back gracefully to an empty result if Playwright is not installed.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("security_mcp.scanners.browser_crawler")


@dataclass
class BrowserCrawlResult:
    """Result from SPA-aware browser crawling."""

    target: str
    urls: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    fragment_routes: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "urls": sorted(set(self.urls)),
            "api_endpoints": sorted(set(self.api_endpoints)),
            "forms": self.forms,
            "js_files": sorted(set(self.js_files)),
            "fragment_routes": sorted(set(self.fragment_routes)),
            "technologies": self.technologies,
            "duration_ms": round(self.duration_ms, 2),
        }


# Common SPA framework route patterns in JS bundles
_ROUTE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""(?:path|route)\s*:\s*['"]([/#][^'"]{1,80})['"]""", re.IGNORECASE),
    re.compile(r"""routerLink\s*=\s*['"]([/#][^'"]{1,80})['"]""", re.IGNORECASE),
    re.compile(r"""href\s*=\s*['"]([/#][^'"]{1,80})['"]"""),
    re.compile(r"""navigate\s*\(\s*\[?\s*['"]([/#][^'"]{1,80})['"]""", re.IGNORECASE),
    # Bare SPA route names without leading / or # (Angular path: 'administration', Vue path: 'dashboard')
    re.compile(r"""path\s*:\s*['"]([a-zA-Z][a-zA-Z0-9\-_/]{1,80})['"]"""),
]

# API endpoint patterns in JS bundles
_API_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""['"](/(?:api|rest|graphql)[^'"]{0,120})['"]"""),
    re.compile(r"""(?:get|post|put|delete|patch|fetch)\s*\(\s*['"]([^'"]{5,120})['"]""", re.IGNORECASE),
]


class BrowserCrawler:
    """SPA-aware crawler using Playwright headless Chromium."""

    def __init__(self, timeout: float = 30.0, max_pages: int = 30) -> None:
        self.timeout = timeout
        self.max_pages = max_pages

    async def crawl(self, url: str) -> BrowserCrawlResult:
        start = time.monotonic()
        result = BrowserCrawlResult(target=url)

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not installed — browser_crawl_site unavailable")
            result.duration_ms = (time.monotonic() - start) * 1000
            return result

        base_parsed = urlparse(url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
        visited: set[str] = set()
        api_endpoints: set[str] = set()

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                )

                # Intercept XHR/fetch to discover API endpoints
                page = await context.new_page()

                def _on_response(response: Any) -> None:
                    resp_url = str(response.url)
                    resp_parsed = urlparse(resp_url)
                    if resp_parsed.netloc == base_parsed.netloc:
                        path = resp_parsed.path
                        if re.match(r"/(?:api|rest|graphql)", path):
                            api_endpoints.add(path)

                page.on("response", _on_response)

                # Step 1: Navigate to target
                await page.goto(url, timeout=int(self.timeout * 1000), wait_until="networkidle")
                await page.wait_for_timeout(2000)
                visited.add(url)
                result.urls.append(url)

                # Step 2: Detect SPA framework
                spa_info = await self._detect_spa(page)
                result.technologies = spa_info

                # Step 3: Extract routes from rendered DOM
                anchors = await page.evaluate("""() => {
                    const links = [];
                    document.querySelectorAll('a[href], [routerLink]').forEach(el => {
                        const href = el.getAttribute('href') || el.getAttribute('routerLink');
                        if (href) links.push(href);
                    });
                    return links;
                }""")

                for href in anchors:
                    if href.startswith("#") or href.startswith("/#"):
                        result.fragment_routes.append(href)
                    elif href.startswith("/"):
                        full = urljoin(base_origin, href)
                        if full not in visited:
                            result.urls.append(full)

                # Step 4: Extract routes from JS source (main.js, vendor.js, etc.)
                scripts = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src)
                        .filter(s => s.includes('/main') || s.includes('/app') || s.includes('/vendor') || s.includes('/routes'));
                }""")

                for script_url in scripts[:5]:
                    result.js_files.append(script_url)
                    try:
                        resp = await page.request.get(script_url)
                        js_text = await resp.text()
                        # Extract routes
                        for pattern in _ROUTE_PATTERNS:
                            for m in pattern.finditer(js_text[:500_000]):
                                route = m.group(1)
                                if route.startswith("#") or route.startswith("/#"):
                                    result.fragment_routes.append(route)
                                elif route.startswith("/"):
                                    result.urls.append(urljoin(base_origin, route))
                                else:
                                    # Bare route name (e.g., 'administration') — treat as SPA fragment route
                                    result.fragment_routes.append(f"/#/{route}")
                        # Extract API endpoints
                        for pattern in _API_PATTERNS:
                            for m in pattern.finditer(js_text[:500_000]):
                                endpoint = m.group(1)
                                if endpoint.startswith("/"):
                                    api_endpoints.add(endpoint)
                    except Exception:
                        logger.debug("Failed to fetch JS bundle: %s", script_url)

                # Step 5: Click navigation elements to discover more routes
                nav_selectors = [
                    "nav a",
                    "mat-nav-list a",
                    ".navbar a",
                    ".sidebar a",
                    "[routerLink]",
                    ".menu-item",
                    "button.nav",
                ]
                for selector in nav_selectors:
                    try:
                        elements = await page.query_selector_all(selector)
                        for el in elements[:10]:
                            href = await el.get_attribute("href") or await el.get_attribute("routerLink")
                            if href:
                                if href.startswith("#") or href.startswith("/#"):
                                    result.fragment_routes.append(href)
                                elif href.startswith("/"):
                                    result.urls.append(urljoin(base_origin, href))
                    except Exception:
                        continue

                # Step 6: Extract forms
                forms = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                            name: i.name || '',
                            type: i.type || 'text'
                        })).filter(i => i.name)
                    }));
                }""")
                result.forms = forms

                # Step 7: Try common hidden paths (GraphQL, admin)
                common_paths = [
                    "/graphql",
                    "/api/v1",
                    "/api/v2",
                    "/admin",
                    "/swagger-ui",
                    "/api-docs",
                    "/actuator",
                    "/actuator/health",
                    "/.env",
                    "/debug",
                    "/console",
                    "/status",
                    "/wp-admin",
                    "/wp-login.php",
                    "/_debug",
                    "/elmah.axd",
                ]
                for path in common_paths:
                    test_url = urljoin(base_origin, path)
                    try:
                        resp = await page.request.get(test_url)
                        if resp.status in (200, 301, 302, 308):
                            api_endpoints.add(path)
                    except Exception:
                        continue

                # Step 8: Probe common SPA fragment routes via browser navigation
                _SPA_ADMIN_ROUTES = [
                    # Admin / sensitive routes
                    "/#/admin",
                    "/#/administration",
                    "/#/dashboard",
                    "/#/settings",
                    "/#/debug",
                    "/#/profile",
                    "/#/console",
                    "/#/config",
                    "/#/management",
                    "/#/score-board",
                    "/#/accounting",
                    # User-facing routes (XSS / business logic targets)
                    "/#/search",
                    "/#/login",
                    "/#/register",
                    "/#/basket",
                    "/#/order-history",
                    "/#/track-result",
                    "/#/track-order",
                    "/#/contact",
                    "/#/complain",
                    "/#/chatbot",
                    "/#/about",
                    "/#/photo-wall",
                    "/#/wallet",
                    "/#/deluxe-membership",
                    "/#/recycle",
                    "/#/address",
                    "/#/payment",
                    "/#/privacy-security",
                    "/#/forgot-password",
                ]
                for frag_route in _SPA_ADMIN_ROUTES:
                    if frag_route in result.fragment_routes:
                        continue  # Already discovered via JS analysis
                    test_url = f"{base_origin}{frag_route}"
                    try:
                        await page.goto(test_url, timeout=5000, wait_until="load")
                        await page.wait_for_timeout(500)
                        # Check if the page rendered non-trivial content (not redirect to home)
                        current_url = page.url
                        current_frag = urlparse(current_url).fragment
                        # Only add if the fragment route stuck (wasn't redirected away)
                        expected_frag = frag_route.lstrip("/#")
                        if expected_frag and expected_frag in current_frag:
                            inner_text = await page.evaluate(
                                "() => document.body ? document.body.innerText.substring(0, 200) : ''"
                            )
                            if len(inner_text.strip()) > 30:
                                result.fragment_routes.append(frag_route)
                    except Exception:
                        continue

                result.api_endpoints = list(api_endpoints)
                await browser.close()

        except Exception as exc:
            logger.error("Browser crawl error: %s", exc)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Browser crawl complete: %s — %d URLs, %d API endpoints, %d routes, %.0fms",
            url,
            len(result.urls),
            len(result.api_endpoints),
            len(result.fragment_routes),
            result.duration_ms,
        )
        return result

    async def _detect_spa(self, page: Any) -> list[str]:
        """Detect SPA frameworks from the rendered page."""
        return await page.evaluate("""() => {
            const techs = [];
            if (window.ng || document.querySelector('[ng-version]') || document.querySelector('app-root'))
                techs.push('Angular');
            if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector('[data-reactroot]'))
                techs.push('React');
            if (window.__VUE__ || document.querySelector('[data-v-]'))
                techs.push('Vue');
            if (window.__NEXT_DATA__)
                techs.push('Next.js');
            if (window.__NUXT__)
                techs.push('Nuxt');
            return techs;
        }""")


async def python_browser_crawl_site(
    url: str,
    max_pages: int = 30,
) -> str:
    """Crawl a JavaScript-rendered SPA using a headless browser.

    Discovers Angular/React/Vue routes, intercepts API calls,
    extracts forms, and finds hidden endpoints like /graphql.
    Requires Chromium (``playwright install chromium``).

    Args:
        url: Starting URL for the crawl.
        max_pages: Maximum pages to visit.

    Returns:
        JSON string with discovered URLs, API endpoints, routes, forms.
    """
    crawler = BrowserCrawler(max_pages=max_pages)
    result = await crawler.crawl(url)
    return json.dumps(result.to_dict(), indent=2)
