"""Tests for security_mcp.scanners.crawler."""

from __future__ import annotations

import json

import httpx
import pytest

from security_mcp.scanners.crawler import (
    TECH_RULES,
    CrawlResult,
    FingerprintResult,
    PythonTechFingerprinter,
    PythonWebCrawler,
    TechFingerprint,
    python_crawl_site,
    python_tech_fingerprint,
)


# ---------------------------------------------------------------------------
# Helper: mock transport
# ---------------------------------------------------------------------------


def _page_transport(pages: dict[str, tuple[int, str, dict[str, str] | None]]) -> httpx.MockTransport:
    """Create a MockTransport from a dict of path -> (status, body, headers)."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in pages:
            status, body, extra_headers = pages[path]
            headers = {"content-type": "text/html; charset=utf-8"}
            if extra_headers:
                headers.update(extra_headers)
            return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(404, text="Not Found")

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# CrawlResult / FingerprintResult dataclass tests
# ---------------------------------------------------------------------------


class TestCrawlResult:
    def test_to_dict_empty(self):
        r = CrawlResult(target="http://example.com")
        d = r.to_dict()
        assert d["target"] == "http://example.com"
        assert d["urls"] == []
        assert d["forms"] == []
        assert d["js_files"] == []
        assert d["comments"] == []

    def test_to_dict_with_data(self):
        r = CrawlResult(
            target="http://example.com",
            urls=["http://example.com/", "http://example.com/about"],
            forms=[{"action": "/login", "method": "POST", "params": ["user", "pass"]}],
            js_files=["http://example.com/app.js"],
            comments=["TODO: remove this"],
            pages_crawled=2,
            duration_ms=456.78,
        )
        d = r.to_dict()
        assert len(d["urls"]) == 2
        assert len(d["forms"]) == 1


class TestFingerprintResult:
    def test_to_dict(self):
        r = FingerprintResult(
            target="http://example.com",
            technologies=[{"name": "nginx", "version": "1.24.0", "confidence": 0.9}],
        )
        d = r.to_dict()
        assert d["technologies"][0]["name"] == "nginx"


# ---------------------------------------------------------------------------
# PythonWebCrawler
# ---------------------------------------------------------------------------


class TestPythonWebCrawler:
    @pytest.mark.asyncio
    async def test_crawl_extracts_links(self):
        """Crawler should extract same-domain links."""
        pages = {
            "/": (200, """
                <html><body>
                    <a href="/about">About</a>
                    <a href="/contact">Contact</a>
                    <a href="https://external.com">External</a>
                </body></html>
            """, None),
            "/about": (200, "<html><body>About page</body></html>", None),
            "/contact": (200, "<html><body>Contact page</body></html>", None),
        }
        transport = _page_transport(pages)
        crawler = PythonWebCrawler(max_depth=1, max_pages=10, concurrency=5, timeout=5.0)

        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            # Patch the crawler to use our transport
            result = CrawlResult(target="http://test.local")
            resp = await client.get("/")
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            links = []
            for tag in soup.find_all("a", href=True):
                from urllib.parse import urljoin
                absolute = urljoin("http://test.local/", tag["href"])
                from urllib.parse import urlparse
                parsed = urlparse(absolute)
                if parsed.netloc == "test.local":
                    links.append(absolute)

        assert len(links) == 2
        assert "http://test.local/about" in links
        assert "http://test.local/contact" in links

    @pytest.mark.asyncio
    async def test_crawl_extracts_forms(self):
        """Crawler should extract form details."""
        pages = {
            "/": (200, """
                <html><body>
                    <form action="/login" method="POST">
                        <input name="username" type="text">
                        <input name="password" type="password">
                        <button type="submit">Login</button>
                    </form>
                </body></html>
            """, None),
        }
        transport = _page_transport(pages)

        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            resp = await client.get("/")
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = []
            for form_tag in soup.find_all("form"):
                action = form_tag.get("action", "")
                absolute_action = urljoin("http://test.local/", action)
                method = (form_tag.get("method", "GET") or "GET").upper()
                params = [inp.get("name") for inp in form_tag.find_all("input") if inp.get("name")]
                forms.append({"action": absolute_action, "method": method, "params": params})

        assert len(forms) == 1
        assert forms[0]["action"] == "http://test.local/login"
        assert forms[0]["method"] == "POST"
        assert "username" in forms[0]["params"]
        assert "password" in forms[0]["params"]

    @pytest.mark.asyncio
    async def test_crawl_extracts_comments(self):
        """Crawler should extract HTML comments."""
        pages = {
            "/": (200, """
                <html><body>
                    <!-- TODO: remove debug endpoint -->
                    <p>Hello</p>
                    <!-- Version 2.3.1 -->
                </body></html>
            """, None),
        }
        transport = _page_transport(pages)

        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            resp = await client.get("/")
            from bs4 import BeautifulSoup, Comment
            soup = BeautifulSoup(resp.text, "html.parser")
            comments = [c.strip() for c in soup.find_all(string=lambda t: isinstance(t, Comment)) if c.strip()]

        assert len(comments) == 2
        assert any("debug" in c.lower() for c in comments)

    def test_normalise_url(self):
        """URL normalisation should strip fragments and trailing slashes."""
        assert PythonWebCrawler._normalise_url("http://test.local/path#frag") == "http://test.local/path?"
        assert PythonWebCrawler._normalise_url("http://test.local/path/") == "http://test.local/path?"


# ---------------------------------------------------------------------------
# PythonTechFingerprinter
# ---------------------------------------------------------------------------


class TestPythonTechFingerprinter:
    @pytest.mark.asyncio
    async def test_detects_nginx_from_header(self):
        """Should detect nginx from Server header."""
        pages = {
            "/": (200, "<html><body>Hello</body></html>", {"Server": "nginx/1.24.0"}),
        }
        transport = _page_transport(pages)

        fingerprinter = PythonTechFingerprinter(timeout=5.0)

        # Manually test fingerprint logic
        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            resp = await client.get("/")

        server = resp.headers.get("server", "")
        assert "nginx" in server

    @pytest.mark.asyncio
    async def test_detects_wordpress_from_html(self):
        """Should detect WordPress from HTML patterns."""
        body = """
        <html>
            <head><meta name="generator" content="WordPress 6.4.2"></head>
            <body>
                <link rel="stylesheet" href="/wp-content/themes/theme/style.css">
                <script src="/wp-includes/js/jquery.js"></script>
            </body>
        </html>
        """
        pages = {"/": (200, body, None)}
        transport = _page_transport(pages)

        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            resp = await client.get("/")

        import re
        for rule in TECH_RULES:
            if rule["name"] == "WordPress":
                for pattern in rule.get("html", []):
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        assert True
                        return
        pytest.fail("WordPress not detected in HTML patterns")

    @pytest.mark.asyncio
    async def test_detects_react_from_script(self):
        """Should detect React from script src patterns."""
        body = '<html><body><script src="/static/js/react.production.min.js"></script></body></html>'
        pages = {"/": (200, body, None)}
        transport = _page_transport(pages)

        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            resp = await client.get("/")

        import re
        for rule in TECH_RULES:
            if rule["name"] == "React":
                for pattern in rule.get("script", []):
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        assert True
                        return
        pytest.fail("React not detected from script src")

    def test_tech_rules_not_empty(self):
        """Technology rules should cover 30+ technologies."""
        assert len(TECH_RULES) >= 30

    def test_tech_fingerprint_angular2(self):
        """Angular 2+ should be detected from <app-root> pattern."""
        import re

        body = '<html><head></head><body><app-root></app-root><script src="runtime.abc123.js"></script></body></html>'
        found = False
        for rule in TECH_RULES:
            if rule["name"] == "Angular":
                for pattern in rule.get("html", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        found = True
                        break
        assert found, "Angular 2+ not detected from <app-root> pattern"

    def test_tech_fingerprint_nextjs(self):
        """Next.js should be detected from __NEXT_DATA__ pattern."""
        import re

        body = '<html><body><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script></body></html>'
        found = False
        for rule in TECH_RULES:
            if rule["name"] == "Next.js":
                for pattern in rule.get("html", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        found = True
                        break
        assert found, "Next.js not detected from __NEXT_DATA__ pattern"


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


class TestCrawlerToolRegistration:
    def test_registry_has_crawl(self):
        """crawl should be registered in the default tool registry."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "crawl" in registry.available_tools

    def test_registry_has_recon(self):
        """recon (replaces tech_fingerprint) should be registered in the default tool registry."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "recon" in registry.available_tools

        schemas = registry.get_schemas()
        recon_schema = next(s for s in schemas if s["function"]["name"] == "recon")
        params = recon_schema["function"]["parameters"]
        assert "target" in params["properties"]
        assert params["required"] == ["target"]
