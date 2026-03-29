"""Python-native Server-Side Template Injection (SSTI) tester.

Detection strategy:
1. Mathematical probe: inject ``{{7*7}}`` (and engine variants) into parameters.
   If the response contains ``49``, SSTI is likely confirmed.
2. Engine disambiguation: use engine-specific probes to identify the template engine.
3. Severity: SSTI → RCE → Critical.

Engines covered:
- Jinja2 / Twig (Python / PHP): ``{{7*7}}``
- Mako / Django:                ``${7*7}``
- Smarty:                       ``{7*7}``
- Freemarker / Pebble:          ``${7*7}``
- Velocity:                     ``#set($x=7*7)${x}``
- Ruby ERB:                     ``<%= 7*7 %>``
- Handlebars / Mustache:        ``{{7*7}}``
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.ssti_tester")

# ---------------------------------------------------------------------------
# Probe definitions: (probe_string, expected_result, engine_guess)
# ---------------------------------------------------------------------------

_MATH_PROBES: list[tuple[str, str, str]] = [
    # Use large unique products to avoid false positives from prices,
    # pagination, IDs, or other naturally-occurring numbers.
    ("{{83621*91433}}", "7645846693", "Jinja2/Twig/Handlebars"),
    ("${83621*91433}", "7645846693", "Mako/Freemarker/Django"),
    ("{83621*91433}", "7645846693", "Smarty"),
    ("<%= 83621*91433 %>", "7645846693", "Ruby ERB"),
    ("#set($x=83621*91433)${x}", "7645846693", "Velocity"),
    ("{{7*'7'}}", "7777777", "Jinja2"),  # Jinja2 string multiplication
    ("${{83621*91433}}", "7645846693", "Pebble/Spring"),
]

# Engine-specific disambiguation probes (only run after a math probe hits)
_DISAMBIG_PROBES: list[tuple[str, str, str]] = [
    ("{{config}}", "SECRET_KEY", "Jinja2"),
    ("{{self.__class__.__name__}}", "Undefined", "Jinja2"),
    ("<#list 1..3 as x>${x}</#list>", "123", "Freemarker"),
    ("{$smarty.version}", "Smarty", "Smarty"),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SstiVulnerability:
    """A single SSTI finding."""

    param: str
    probe: str
    expected: str
    engine: str
    evidence: str
    location: str = "GET"


@dataclass
class SstiResult:
    """Complete SSTI test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[SstiVulnerability] = field(default_factory=list)
    params_tested: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": "ssti",
                    "param": v.param,
                    "probe": v.probe,
                    "expected_output": v.expected,
                    "engine_guess": v.engine,
                    "evidence": v.evidence,
                    "location": v.location,
                }
                for v in self.vulnerabilities
            ],
            "params_tested": self.params_tested,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"SSTI confirmed ({', '.join(v.engine or 'unknown' for v in self.vulnerabilities)})"
                if self.vulnerabilities
                else "No SSTI found"
            ),
            "next_steps": (
                ["Escalate to RCE using engine-specific payloads from kb_search"] if self.vulnerabilities else []
            ),
        }


# ---------------------------------------------------------------------------
# SSTI detection engine
# ---------------------------------------------------------------------------


class SstiTester:
    """Two-phase SSTI tester: math probe + engine disambiguation.

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
    ) -> SstiResult:
        """Run SSTI tests against a target URL.

        Args:
            url: Target URL (with or without query parameters).
            params: Specific parameter names to test. ``None`` auto-detects.
            method: HTTP method (``GET`` or ``POST``).
            body: POST body parameters.

        Returns:
            ``SstiResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = SstiResult(target=url)

        test_params = self._detect_params(url, params, body)
        result.params_tested = len(test_params)

        async with create_client(
            timeout=self.timeout,
            headers=self._extra_headers,
        ) as client:
            for param_name, location in test_params:
                vuln = await self._test_param(client, url, param_name, location, method, body)
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "SSTI test complete: %s — %d params, %d vulns, %.0fms",
            url,
            result.params_tested,
            len(result.vulnerabilities),
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
        body: dict[str, str] | None,
    ) -> list[tuple[str, str]]:
        """Detect testable parameters from URL and body."""
        params: list[tuple[str, str]] = []
        parsed = urlparse(url)
        for p in parse_qs(parsed.query):
            params.append((p, "GET"))
        if body:
            for p in body:
                params.append((p, "POST"))
        if explicit_params:
            params = [(p, loc) for p, loc in params if p in explicit_params]
        return params

    # ------------------------------------------------------------------
    # HTTP helper
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
        """Inject payload into a parameter and send the request."""
        try:
            if location == "GET":
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                injected = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                return await client.get(injected)
            else:
                injected_body = dict(body or {})
                injected_body[param] = payload
                return await client.post(url, data=injected_body)
        except httpx.HTTPError as exc:
            logger.debug("SSTI HTTP error (param=%s): %s", param, exc)
            return None

    # ------------------------------------------------------------------
    # Per-parameter testing
    # ------------------------------------------------------------------

    async def _test_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> SstiVulnerability | None:
        """Test one parameter for SSTI using math probes with baseline check.

        Phase 1 -- Baseline: fetch the original page and record its body so we
        can reject probes whose expected result already appears naturally.

        Phase 2 -- Math probe: inject the canary expression and check if the
        computed result appears in the response but was absent from baseline.

        Phase 3 -- Disambiguation: if a math probe hits, run engine-specific
        probes from ``_DISAMBIG_PROBES`` to identify the exact template engine.
        """
        # Phase 1: fetch baseline response
        baseline_resp = await self._send_with_payload(
            client,
            url,
            param,
            "secmcp_ssti_baseline_noop",
            location,
            method,
            body,
        )
        baseline_text = baseline_resp.text if baseline_resp else ""

        # Build probe list, optionally expanding with WAF evasion variants
        probes: list[tuple[str, str, str]] = list(_MATH_PROBES)
        if self._waf_evasion:
            from numasec.scanners._encoder import PayloadEncoder

            extra_probes: list[tuple[str, str, str]] = []
            for probe_str, expected_str, engine_str in probes:
                encoded = PayloadEncoder.url_encode(probe_str)
                if encoded != probe_str:
                    extra_probes.append((encoded, expected_str, engine_str))
                unicode_p = PayloadEncoder.unicode_normalize(probe_str)
                if unicode_p != probe_str:
                    extra_probes.append((unicode_p, expected_str, engine_str))
            probes.extend(extra_probes)

        # Phase 2: math probe with baseline filtering
        for probe, expected, engine in probes:
            # Skip if expected result already appears in the baseline response
            if expected in baseline_text:
                logger.debug(
                    "SSTI baseline skip: '%s' already in response for param=%s",
                    expected,
                    param,
                )
                continue

            resp = await self._send_with_payload(client, url, param, probe, location, method, body)
            if resp is None:
                continue

            if expected in resp.text:
                logger.info(
                    "SSTI confirmed: param=%s, probe=%r, engine=%s",
                    param,
                    probe,
                    engine,
                )

                # Phase 3: disambiguation -- refine engine guess
                confirmed_engine = engine
                for d_probe, d_expected, d_engine in _DISAMBIG_PROBES:
                    d_resp = await self._send_with_payload(
                        client,
                        url,
                        param,
                        d_probe,
                        location,
                        method,
                        body,
                    )
                    if d_resp and d_expected in d_resp.text:
                        confirmed_engine = d_engine
                        logger.info("SSTI engine identified: %s", d_engine)
                        break

                # Extract evidence context
                idx = resp.text.find(expected)
                snippet_start = max(0, idx - 60)
                snippet_end = min(len(resp.text), idx + len(expected) + 60)
                snippet = resp.text[snippet_start:snippet_end]

                return SstiVulnerability(
                    param=param,
                    probe=probe,
                    expected=expected,
                    engine=confirmed_engine,
                    evidence=(
                        f"Mathematical probe '{probe}' evaluated to "
                        f"'{expected}' in response (absent from baseline). "
                        f"Engine: {confirmed_engine}. "
                        f"Context: ...{snippet}..."
                    ),
                    location=location,
                )

        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_ssti_test(
    url: str,
    params: str | None = None,
    method: str = "GET",
    headers: str = "",
    waf_evasion: bool = False,
) -> str:
    """Test URL parameters for Server-Side Template Injection (SSTI).

    Args:
        url: Target URL with query parameters to test.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (``GET`` or ``POST``).
        headers: JSON string of extra HTTP headers for authenticated testing,
            e.g. ``'{"Authorization": "Bearer token123"}'``. Default: ``""``.
        waf_evasion: Enable WAF bypass encoding for payloads. Default: ``False``.

    Returns:
        JSON string with ``SstiResult`` data.
    """
    param_list = params.split(",") if params else None
    extra_headers: dict[str, str] = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    tester = SstiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
    result = await tester.test(url, params=param_list, method=method)
    return json.dumps(result.to_dict(), indent=2)
