"""Python-native web crawler with technology fingerprinting.

Two capabilities in one module:
1. **Web Crawler**: BFS crawl using httpx + beautifulsoup4 with depth limiting,
   same-domain enforcement, and extraction of links, forms, JS files, and comments.
2. **Tech Fingerprint**: Rule-based technology detection from response headers,
   meta tags, script sources, cookie names, and HTML patterns.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup, Comment

logger = logging.getLogger("security_mcp.scanners.crawler")


# ---------------------------------------------------------------------------
# Technology fingerprint rules
# ---------------------------------------------------------------------------

TECH_RULES: list[dict[str, Any]] = [
    # Web servers
    {"name": "nginx", "category": "web_server", "header": {"Server": r"nginx(?:/(\d+\.\d+(?:\.\d+)?))?"}},
    {"name": "Apache", "category": "web_server", "header": {"Server": r"Apache(?:/(\d+\.\d+(?:\.\d+)?))?"}},
    {"name": "Microsoft-IIS", "category": "web_server", "header": {"Server": r"Microsoft-IIS/(\d+\.\d+)"}},
    {"name": "LiteSpeed", "category": "web_server", "header": {"Server": r"LiteSpeed(?:/(\d+\.\d+))?"}},
    {"name": "Caddy", "category": "web_server", "header": {"Server": r"Caddy"}},
    # Backend languages / frameworks
    {"name": "PHP", "category": "language", "header": {"X-Powered-By": r"PHP/(\d+\.\d+(?:\.\d+)?)"}},
    {
        "name": "ASP.NET",
        "category": "framework",
        "header": {"X-Powered-By": r"ASP\.NET"},
        "html": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
    },
    {"name": "Express", "category": "framework", "header": {"X-Powered-By": r"Express"}},
    {
        "name": "Django",
        "category": "framework",
        "html": [r"csrfmiddlewaretoken", r"django\.contrib"],
        "cookie": ["csrftoken", "django_language"],
    },
    {"name": "Flask", "category": "framework", "header": {"Server": r"Werkzeug"}, "cookie": ["session"]},
    {"name": "Laravel", "category": "framework", "cookie": ["laravel_session", "XSRF-TOKEN"], "html": [r"laravel"]},
    {
        "name": "Ruby on Rails",
        "category": "framework",
        "header": {"X-Powered-By": r"Phusion Passenger"},
        "cookie": ["_session_id"],
        "html": [r"csrf-token", r"authenticity_token"],
    },
    {"name": "Spring", "category": "framework", "cookie": ["JSESSIONID"], "html": [r"org\.springframework"]},
    {
        "name": "Node.js",
        "category": "runtime",
        "cookie": ["connect.sid"],
        "header": {"X-Powered-By": r"Express|NodeJS|node"},
    },
    # CMS
    {
        "name": "WordPress",
        "category": "cms",
        "html": [r"wp-content", r"wp-includes"],
        "meta_generator": r"WordPress\s*(\d+\.\d+(?:\.\d+)?)",
    },
    {
        "name": "Drupal",
        "category": "cms",
        "html": [r"Drupal\.settings", r"drupal\.js"],
        "header": {"X-Generator": r"Drupal\s*(\d+)"},
        "meta_generator": r"Drupal\s*(\d+)",
    },
    {
        "name": "Joomla",
        "category": "cms",
        "html": [r"/media/jui/", r"/media/system/"],
        "meta_generator": r"Joomla!\s*(\d+\.\d+)",
    },
    {"name": "Magento", "category": "cms", "html": [r"Mage\.Cookies", r"/skin/frontend/"], "cookie": ["frontend"]},
    # JavaScript frameworks
    {
        "name": "React",
        "category": "js_framework",
        "html": [r"__REACT_DEVTOOLS", r"data-reactroot", r"_reactRoot"],
        "script": [r"react\.production\.min\.js", r"react-dom"],
    },
    {
        "name": "AngularJS",
        "category": "js_framework",
        "html": [r"ng-app", r"ng-controller"],
        "script": [r"angular(?:\.min)?\.js"],
    },
    {
        "name": "Angular",
        "category": "js_framework",
        "html": [r"<app-root", r'ng-version="(\d+)'],
        "script": [r"runtime\.\w+\.js", r"polyfills\.\w+\.js", r"main\.\w+\.js"],
    },
    {
        "name": "Vue.js",
        "category": "js_framework",
        "html": [r"data-v-[a-f0-9]", r"__vue__"],
        "script": [r"vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js"],
    },
    {"name": "Svelte", "category": "js_framework", "html": [r"svelte-[a-z0-9]"], "script": [r"svelte"]},
    {
        "name": "Next.js",
        "category": "js_framework",
        "html": [r"__NEXT_DATA__", r"/_next/"],
        "header": {"X-Powered-By": r"Next\.js"},
    },
    {"name": "Nuxt.js", "category": "js_framework", "html": [r"__NUXT__", r"/_nuxt/"]},
    {"name": "Gatsby", "category": "js_framework", "html": [r"___gatsby", r"gatsby-"]},
    # JavaScript libraries
    {"name": "jQuery", "category": "js_library", "script": [r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js"]},
    {
        "name": "Bootstrap",
        "category": "css_framework",
        "script": [r"bootstrap[.-](\d+\.\d+\.\d+)"],
        "html": [r"bootstrap\.min\.css"],
    },
    {
        "name": "Tailwind CSS",
        "category": "css_framework",
        "html": [r"tailwindcss", r"class=\"[^\"]*(?:flex|grid|bg-|text-|p-|m-)[^\"]*\""],
    },
    # Analytics / tracking
    {
        "name": "Google Analytics",
        "category": "analytics",
        "script": [r"google-analytics\.com/analytics\.js", r"gtag/js"],
        "html": [r"UA-\d{4,10}-\d{1,4}", r"G-[A-Z0-9]{10}"],
    },
    {"name": "Google Tag Manager", "category": "analytics", "html": [r"googletagmanager\.com/gtm\.js"]},
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FormInfo:
    """Extracted form information."""

    action: str
    method: str
    params: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    """Complete crawl result."""

    target: str
    urls: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    pages_crawled: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "urls": self.urls,
            "forms": self.forms,
            "js_files": self.js_files,
            "comments": self.comments,
            "emails": self.emails,
            "pages_crawled": self.pages_crawled,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class TechFingerprint:
    """A detected technology."""

    name: str
    version: str = ""
    confidence: float = 0.0
    category: str = ""


@dataclass
class FingerprintResult:
    """Complete fingerprint result."""

    target: str
    technologies: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "technologies": self.technologies,
            "headers": self.headers,
            "cookies": self.cookies,
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Web crawler engine
# ---------------------------------------------------------------------------


class PythonWebCrawler:
    """BFS web crawler with link, form, JS file, and comment extraction.

    Parameters
    ----------
    max_depth:
        Maximum link depth from the start URL.
    max_pages:
        Maximum number of pages to crawl.
    concurrency:
        Maximum concurrent HTTP requests.
    timeout:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        max_depth: int = 2,
        max_pages: int = 50,
        concurrency: int = 10,
        timeout: float = 10.0,
    ) -> None:
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)

    async def crawl(self, url: str) -> CrawlResult:
        """Crawl a website starting from the given URL.

        Uses BFS (breadth-first search) with depth limiting and same-domain
        enforcement. Extracts links, forms, JavaScript file URLs, HTML
        comments, and email addresses.

        Args:
            url: Starting URL for the crawl.

        Returns:
            ``CrawlResult`` with all extracted data.
        """
        start = time.monotonic()
        result = CrawlResult(target=url)

        parsed_start = urlparse(url)
        base_domain = parsed_start.netloc
        base_scheme = parsed_start.scheme

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        queue.append((url, 0))

        all_js: set[str] = set()
        all_emails: set[str] = set()

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-mcp/1.0)"},
        ) as client:
            while queue and result.pages_crawled < self.max_pages:
                # Process in batches for concurrency
                batch: list[tuple[str, int]] = []
                while queue and len(batch) < self.concurrency:
                    current_url, depth = queue.popleft()
                    normalised = self._normalise_url(current_url)
                    if normalised in visited:
                        continue
                    visited.add(normalised)
                    batch.append((current_url, depth))

                if not batch:
                    break

                tasks = [
                    self._fetch_and_extract(client, page_url, depth, base_domain, base_scheme)
                    for page_url, depth in batch
                ]
                pages = await asyncio.gather(*tasks, return_exceptions=True)

                for page_data in pages:
                    if isinstance(page_data, BaseException):
                        logger.debug("Crawl error: %s", page_data)
                        continue
                    if page_data is None:
                        continue

                    page_url, links, forms, js_files, comments, emails, depth = page_data

                    result.pages_crawled += 1
                    if page_url not in result.urls:
                        result.urls.append(page_url)

                    result.forms.extend(forms)

                    for js in js_files:
                        if js not in all_js:
                            all_js.add(js)

                    for email in emails:
                        all_emails.add(email)

                    result.comments.extend(comments)

                    # Enqueue discovered links at next depth
                    if depth < self.max_depth:
                        for link in links:
                            normalised = self._normalise_url(link)
                            if normalised not in visited:
                                queue.append((link, depth + 1))

        result.js_files = sorted(all_js)
        result.emails = sorted(all_emails)

        # Deduplicate comments
        result.comments = list(dict.fromkeys(result.comments))

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Crawl complete: %s — %d pages, %d urls, %d forms, %d JS, %.0fms",
            url,
            result.pages_crawled,
            len(result.urls),
            len(result.forms),
            len(result.js_files),
            result.duration_ms,
        )
        return result

    async def _fetch_and_extract(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        base_domain: str,
        base_scheme: str,
    ) -> tuple[str, list[str], list[dict], list[str], list[str], list[str], int] | None:
        """Fetch a page and extract all interesting data.

        Returns a tuple of (url, links, forms, js_files, comments, emails, depth)
        or ``None`` on failure.
        """
        async with self._sem:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                logger.debug("Failed to fetch %s: %s", url, exc)
                return None

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return None

        body = resp.text
        soup = BeautifulSoup(body, "html.parser")

        # Extract links (same-domain only)
        links: list[str] = []
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"])
            absolute = urljoin(url, href)
            parsed = urlparse(absolute)
            if parsed.netloc == base_domain and parsed.scheme in ("http", "https"):
                # Strip fragments
                clean = absolute.split("#")[0]
                if clean:
                    links.append(clean)

        # Extract forms
        forms: list[dict[str, Any]] = []
        for form_tag in soup.find_all("form"):
            action = str(form_tag.get("action", "") or "")
            absolute_action = urljoin(url, action) if action else url
            method = str(form_tag.get("method", "GET") or "GET").upper()
            params: list[str] = []
            for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if name:
                    params.append(str(name))
            forms.append(
                {
                    "action": absolute_action,
                    "method": method,
                    "params": params,
                    "page": url,
                }
            )

        # Extract JavaScript file URLs
        js_files: list[str] = []
        for script_tag in soup.find_all("script", src=True):
            src = str(script_tag["src"])
            absolute_src = urljoin(url, src)
            js_files.append(absolute_src)

        # Extract HTML comments
        comments: list[str] = []
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            text = comment.strip()
            if text and len(text) > 5:  # Skip trivial comments
                comments.append(text[:500])

        # Extract email addresses
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        emails = email_pattern.findall(body)

        return (url, links, forms, js_files, comments, emails, depth)

    @staticmethod
    def _normalise_url(url: str) -> str:
        """Normalise URL for deduplication (strip fragment, trailing slash)."""
        url = url.split("#")[0]
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}?{parsed.query}"


# ---------------------------------------------------------------------------
# Tech fingerprinting engine
# ---------------------------------------------------------------------------


class PythonTechFingerprinter:
    """Rule-based technology fingerprinting.

    Checks:
    - HTTP response headers (Server, X-Powered-By, etc.)
    - HTML meta generator tags
    - Script src patterns
    - Cookie names
    - HTML body patterns

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def fingerprint(self, url: str) -> FingerprintResult:
        """Detect technologies used by a target URL.

        Args:
            url: Target URL to fingerprint.

        Returns:
            ``FingerprintResult`` with detected technologies.
        """
        start = time.monotonic()
        result = FingerprintResult(target=url)

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; security-mcp/1.0)"},
            ) as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:
            logger.warning("Failed to fetch %s for fingerprinting: %s", url, exc)
            result.duration_ms = (time.monotonic() - start) * 1000
            return result

        # Collect raw data
        headers = dict(resp.headers)
        result.headers = {k: v for k, v in headers.items()}
        result.cookies = list(resp.cookies.keys())
        body = resp.text[:100_000]

        # Parse HTML for meta tags and script srcs
        soup = BeautifulSoup(body, "html.parser")
        meta_generator = ""
        gen_tag = soup.find("meta", attrs={"name": "generator"})
        if gen_tag and gen_tag.get("content"):
            meta_generator = str(gen_tag["content"])

        script_srcs: list[str] = []
        for script in soup.find_all("script", src=True):
            script_srcs.append(str(script["src"]))

        # Match rules
        detected: dict[str, TechFingerprint] = {}

        for rule in TECH_RULES:
            name = rule["name"]
            category = rule.get("category", "")
            confidence = 0.0
            version = ""

            # Check headers
            for header_name, pattern in rule.get("header", {}).items():
                header_val = headers.get(header_name, "") or headers.get(header_name.lower(), "")
                if header_val:
                    match = re.search(pattern, header_val, re.IGNORECASE)
                    if match:
                        confidence = max(confidence, 0.9)
                        if match.lastindex:
                            version = match.group(1)

            # Check meta generator
            if "meta_generator" in rule and meta_generator:
                match = re.search(rule["meta_generator"], meta_generator, re.IGNORECASE)
                if match:
                    confidence = max(confidence, 0.9)
                    if match.lastindex:
                        version = version or match.group(1)

            # Check HTML patterns
            for pattern in rule.get("html", []):
                if re.search(pattern, body, re.IGNORECASE):
                    confidence = max(confidence, 0.7)
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match and match.lastindex and not version:
                        version = match.group(1)

            # Check script src patterns
            script_text = " ".join(script_srcs)
            for pattern in rule.get("script", []):
                match = re.search(pattern, script_text, re.IGNORECASE)
                if match:
                    confidence = max(confidence, 0.8)
                    if match.lastindex and not version:
                        version = match.group(1)

            # Check cookie names
            for cookie_name in rule.get("cookie", []):
                if cookie_name in result.cookies:
                    confidence = max(confidence, 0.6)

            if confidence > 0:
                if name in detected:
                    # Update if higher confidence
                    existing = detected[name]
                    if confidence > existing.confidence:
                        existing.confidence = confidence
                    if version and not existing.version:
                        existing.version = version
                else:
                    detected[name] = TechFingerprint(
                        name=name,
                        version=version,
                        confidence=confidence,
                        category=category,
                    )

        result.technologies = [
            {
                "name": t.name,
                "version": t.version,
                "confidence": round(t.confidence, 2),
                "category": t.category,
            }
            for t in sorted(detected.values(), key=lambda t: t.confidence, reverse=True)
        ]

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Tech fingerprint complete: %s — %d technologies detected, %.0fms",
            url,
            len(result.technologies),
            result.duration_ms,
        )
        return result


# ---------------------------------------------------------------------------
# Tool wrappers for ToolRegistry
# ---------------------------------------------------------------------------


async def python_crawl_site(
    url: str,
    depth: int = 2,
    max_pages: int = 50,
) -> str:
    """Crawl a website and extract links, forms, JS files, and comments.

    Args:
        url: Starting URL for the crawl.
        depth: Maximum crawl depth (default 2).
        max_pages: Maximum pages to crawl (default 50).

    Returns:
        JSON string with crawl results.
    """
    crawler = PythonWebCrawler(max_depth=depth, max_pages=max_pages)
    result = await crawler.crawl(url)
    return json.dumps(result.to_dict(), indent=2)


async def python_tech_fingerprint(url: str) -> str:
    """Detect technologies used by a target URL.

    Args:
        url: Target URL to fingerprint.

    Returns:
        JSON string with detected technologies and metadata.
    """
    fingerprinter = PythonTechFingerprinter()
    result = await fingerprinter.fingerprint(url)
    return json.dumps(result.to_dict(), indent=2)
