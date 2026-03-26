"""Python-native vulnerability scanner using KB templates.

Replaces nuclei for common web vulnerability detection.
Uses KB templates as detection rules with 6 pattern types:

- header_check: missing/dangerous security headers
- technology_detect: fingerprint technologies from response
- response_match: error patterns in response body
- response_diff: content difference with injected payloads
- time_based: timing-based blind detection
- boolean_based: true/false condition comparison

The scanner loads detection templates from the knowledge base
(``security_mcp.knowledge.loader.KnowledgeLoader``) and converts
them into executable checks.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from security_mcp.knowledge.loader import KnowledgeLoader

logger = logging.getLogger("security_mcp.scanners.vuln_scanner")

# ---------------------------------------------------------------------------
# Security header catalogue — derived from misconfig-checks.yaml
# ---------------------------------------------------------------------------

SECURITY_HEADERS: list[dict[str, str]] = [
    {"name": "strict-transport-security", "severity": "high", "note": "Prevents SSL stripping attacks"},
    {"name": "content-security-policy", "severity": "high", "note": "Mitigates XSS and data injection"},
    {"name": "x-frame-options", "severity": "medium", "note": "Prevents clickjacking"},
    {"name": "x-content-type-options", "severity": "low", "note": "Prevents MIME sniffing"},
    {"name": "referrer-policy", "severity": "low", "note": "Controls referrer information leakage"},
    {"name": "permissions-policy", "severity": "low", "note": "Controls browser feature access"},
]

DANGEROUS_HEADERS: list[dict[str, str]] = [
    {"name": "server", "severity": "info", "note": "Reveals web server software and version"},
    {"name": "x-powered-by", "severity": "info", "note": "Reveals backend technology"},
    {"name": "x-aspnet-version", "severity": "medium", "note": "Reveals .NET version"},
]

# ---------------------------------------------------------------------------
# Technology fingerprints
# ---------------------------------------------------------------------------

TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress": [r"wp-content", r"wp-includes", r"WordPress\s+(\d+\.\d+)"],
    "React": [r"__REACT_DEVTOOLS", r"_reactRoot", r"react\.production\.min\.js"],
    "Angular": [r"ng-app", r"ng-version=\"(\d+)", r"angular\.min\.js"],
    "Vue.js": [r"__vue__", r"vue\.runtime", r"vue@(\d+\.\d+)"],
    "Express": [r"X-Powered-By:\s*Express"],
    "Django": [r"csrfmiddlewaretoken", r"django\.contrib"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "ASP.NET": [r"__VIEWSTATE", r"X-AspNet-Version", r"X-Powered-By:\s*ASP\.NET"],
    "PHP": [r"X-Powered-By:\s*PHP/(\d+\.\d+)", r"PHPSESSID"],
    "nginx": [r"Server:\s*nginx(?:/(\d+\.\d+))?"],
    "Apache": [r"Server:\s*Apache(?:/(\d+\.\d+))?"],
    "Node.js": [r"X-Powered-By:\s*Express", r"connect\.sid"],
    "jQuery": [r"jquery[.-](\d+\.\d+\.\d+)\.min\.js"],
    "Bootstrap": [r"bootstrap[.-](\d+\.\d+\.\d+)"],
}

# ---------------------------------------------------------------------------
# Response-match error patterns (info disclosure, debug artefacts)
# ---------------------------------------------------------------------------

ERROR_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"(?i)stack\s*trace", "Stack trace exposed", "high", "CWE-209"),
    (r"(?i)sql\s*syntax.*error", "SQL error message exposed", "high", "CWE-209"),
    (r"(?i)exception\s+in\s+thread", "Java exception exposed", "medium", "CWE-209"),
    (r"(?i)traceback\s*\(most\s+recent", "Python traceback exposed", "medium", "CWE-209"),
    (r"(?i)directory\s+listing\s+for", "Directory listing enabled", "medium", "CWE-548"),
    (r"(?i)phpinfo\(\)", "phpinfo() output exposed", "high", "CWE-200"),
    (r"(?i)debug\s*=\s*true", "Debug mode enabled", "medium", "CWE-489"),
    (r"(?i)Index\s+of\s+/", "Directory index enabled", "medium", "CWE-548"),
]

# SQL error strings from KB template sqli-patterns.yaml
SQLI_ERROR_STRINGS: list[str] = [
    "SQL syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "ORA-01756",
    "ORA-00933",
    "PostgreSQL query failed",
    "pg_query",
    "Microsoft OLE DB Provider",
    "Unclosed quotation mark",
    "SQLITE_ERROR",
    "sqlite3.OperationalError",
    "SQLSTATE[",
    "syntax error at or near",
    "com.mysql.jdbc",
    "java.sql.SQLException",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class VulnFinding:
    """A single vulnerability finding from the scanner."""

    vuln_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    url: str
    evidence: str = ""
    parameter: str = ""
    cwe_id: str = ""
    template_id: str = ""


@dataclass
class ScanResult:
    """Complete scan result."""

    target: str
    findings: list[VulnFinding] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    missing_headers: list[str] = field(default_factory=list)
    dangerous_headers: list[dict[str, str]] = field(default_factory=list)
    checks_run: int = 0
    checks_passed: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "findings": [
                {
                    "type": f.vuln_type,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "url": f.url,
                    "evidence": f.evidence,
                    "parameter": f.parameter,
                    "cwe_id": f.cwe_id,
                    "template_id": f.template_id,
                }
                for f in self.findings
            ],
            "technologies": self.technologies,
            "missing_headers": self.missing_headers,
            "dangerous_headers": self.dangerous_headers,
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Template-to-checks compiler
# ---------------------------------------------------------------------------


def _load_detection_templates() -> dict[str, dict[str, Any]]:
    """Load all KB detection templates via KnowledgeLoader."""
    loader = KnowledgeLoader()
    all_templates = loader.load_all()
    return {tid: tdata for tid, tdata in all_templates.items() if tdata.get("category") == "detection"}


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------


class PythonVulnScanner:
    """KB-driven vulnerability scanner.

    Supports 6 check types derived from KB detection templates:

    - ``headers``: missing / dangerous security headers
    - ``technologies``: response fingerprinting
    - ``response_match``: error patterns & info disclosure
    - ``response_diff``: content difference with injected payloads
    - ``time_based``: blind timing-based detection
    - ``boolean_based``: true/false condition comparison

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    max_concurrent:
        Maximum concurrent HTTP requests.
    """

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 10) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._sem = asyncio.Semaphore(max_concurrent)
        self._templates: dict[str, dict[str, Any]] = {}

    def _ensure_templates(self) -> None:
        """Lazy-load KB detection templates once."""
        if not self._templates:
            try:
                self._templates = _load_detection_templates()
                logger.info("Loaded %d KB detection templates", len(self._templates))
            except Exception as exc:
                logger.warning("Failed to load KB templates, using built-in rules: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        url: str,
        checks: list[str] | None = None,
    ) -> ScanResult:
        """Run vulnerability scan against target URL.

        Args:
            url: Target URL.
            checks: List of check types to run. ``None`` runs all safe
                passive checks (headers, technologies, response_match).
                Options: headers, technologies, response_match,
                response_diff, time_based, boolean_based.

        Returns:
            ScanResult with findings.
        """
        self._ensure_templates()
        start = time.monotonic()
        result = ScanResult(target=url)

        all_checks = checks or ["headers", "technologies", "response_match"]

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            # Run checks sequentially to be kind to the target
            if "headers" in all_checks:
                await self._check_headers(client, url, result)
            if "technologies" in all_checks:
                await self._detect_technologies(client, url, result)
            if "response_match" in all_checks:
                await self._check_response_match(client, url, result)
            if "response_diff" in all_checks:
                await self._check_response_diff(client, url, result)
            if "time_based" in all_checks:
                await self._check_time_based(client, url, result)
            if "boolean_based" in all_checks:
                await self._check_boolean_based(client, url, result)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Scan complete: %s — %d checks, %d findings, %.0fms",
            url,
            result.checks_run,
            len(result.findings),
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Check: missing / dangerous headers
    # ------------------------------------------------------------------

    async def _check_headers(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ScanResult,
    ) -> None:
        """Check for missing and dangerous security headers."""
        result.checks_run += 1
        try:
            async with self._sem:
                resp = await client.get(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            # --- Missing security headers ---
            for hdr in SECURITY_HEADERS:
                name = hdr["name"]
                if name not in headers_lower:
                    result.missing_headers.append(name)
                    result.findings.append(
                        VulnFinding(
                            vuln_type="missing_header",
                            severity=hdr["severity"],
                            title=f"Missing security header: {name}",
                            description=f"The response does not include the {name} header. {hdr['note']}.",
                            url=url,
                            evidence=f"Header '{name}' not found in response",
                            cwe_id="CWE-693",
                            template_id="security-misconfig",
                        )
                    )

            # --- Dangerous headers present ---
            for hdr in DANGEROUS_HEADERS:
                name = hdr["name"]
                if name in headers_lower:
                    result.dangerous_headers.append(
                        {
                            "name": name,
                            "value": headers_lower[name],
                            "severity": hdr["severity"],
                        }
                    )
                    result.findings.append(
                        VulnFinding(
                            vuln_type="dangerous_header",
                            severity=hdr["severity"],
                            title=f"Information disclosure: {name} header",
                            description=f"The {name} header is present and {hdr['note']}.",
                            url=url,
                            evidence=f"{name}: {headers_lower[name]}",
                            cwe_id="CWE-200",
                            template_id="security-misconfig",
                        )
                    )

            if not result.missing_headers and not result.dangerous_headers:
                result.checks_passed += 1
        except httpx.HTTPError as exc:
            logger.warning("Header check failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Check: technology fingerprinting
    # ------------------------------------------------------------------

    async def _detect_technologies(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ScanResult,
    ) -> None:
        """Fingerprint technologies from response content and headers."""
        result.checks_run += 1
        try:
            async with self._sem:
                resp = await client.get(url)
            # Combine headers and body for pattern matching
            header_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            combined = f"{header_str}\n{resp.text[:50_000]}"

            for tech_name, patterns in TECH_SIGNATURES.items():
                for pattern in patterns:
                    match = re.search(pattern, combined, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else ""
                        result.technologies.append(
                            {
                                "name": tech_name,
                                "version": version,
                                "confidence": 0.8 if version else 0.6,
                            }
                        )
                        break  # Found this tech, move to next
            result.checks_passed += 1
        except httpx.HTTPError as exc:
            logger.warning("Technology detection failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Check: response-match (error patterns, info disclosure)
    # ------------------------------------------------------------------

    async def _check_response_match(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ScanResult,
    ) -> None:
        """Check for error patterns and info disclosure in response body."""
        result.checks_run += 1
        try:
            async with self._sem:
                resp = await client.get(url)
            body = resp.text[:100_000]
            found_any = False

            # Built-in error patterns
            for pattern, title, severity, cwe in ERROR_PATTERNS:
                match = re.search(pattern, body)
                if match:
                    found_any = True
                    result.findings.append(
                        VulnFinding(
                            vuln_type="info_disclosure",
                            severity=severity,
                            title=title,
                            description=f"Sensitive information detected in response from {url}.",
                            url=url,
                            evidence=match.group(0)[:200],
                            cwe_id=cwe,
                        )
                    )

            # KB-driven SQL error string matching (from sqli-patterns.yaml)
            for error_str in SQLI_ERROR_STRINGS:
                if error_str.lower() in body.lower():
                    found_any = True
                    result.findings.append(
                        VulnFinding(
                            vuln_type="sqli_error_disclosure",
                            severity="high",
                            title="SQL error message exposed",
                            description=(
                                f"Database error string '{error_str}' found in response body, "
                                "indicating possible SQL injection or misconfigured error handling."
                            ),
                            url=url,
                            evidence=error_str,
                            cwe_id="CWE-209",
                            template_id="sqli-error-based",
                        )
                    )
                    break  # One SQL error finding is enough

            if not found_any:
                result.checks_passed += 1
        except httpx.HTTPError as exc:
            logger.warning("Response match check failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Check: response-diff (payload injection with content comparison)
    # ------------------------------------------------------------------

    async def _check_response_diff(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ScanResult,
    ) -> None:
        """Inject payloads and compare response differences.

        Sends the original request, then re-sends with each test payload
        appended to every query parameter. A significant content-length
        or body difference indicates potential injection.
        """
        result.checks_run += 1
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            result.checks_passed += 1
            return

        # Get the template payloads or use defaults
        test_payloads = ["'", "' OR '1'='1", "1 OR 1=1"]
        threshold = 0.3

        template = self._templates.get("sqli-error-based")
        if template:
            for p in template.get("patterns", []):
                if p.get("type") == "response_diff":
                    test_payloads = p.get("test_payloads", test_payloads)
                    threshold = p.get("threshold", threshold)
                    break

        try:
            # Baseline request
            async with self._sem:
                baseline_resp = await client.get(url)
            baseline_body = baseline_resp.text

            found = False
            for param_name in params:
                for payload in test_payloads:
                    modified_params = dict(params)
                    original_val = modified_params[param_name][0] if modified_params[param_name] else ""
                    modified_params[param_name] = [original_val + payload]
                    flat_params = {k: v[0] for k, v in modified_params.items()}
                    test_url = urlunparse(parsed._replace(query=urlencode(flat_params)))

                    async with self._sem:
                        test_resp = await client.get(test_url)
                    test_body = test_resp.text

                    similarity = SequenceMatcher(None, baseline_body[:5000], test_body[:5000]).ratio()
                    diff_ratio = 1.0 - similarity

                    if diff_ratio >= threshold:
                        found = True
                        result.findings.append(
                            VulnFinding(
                                vuln_type="response_diff",
                                severity="medium",
                                title=f"Response difference detected with payload in '{param_name}'",
                                description=(
                                    f"Injecting '{payload}' into parameter '{param_name}' "
                                    f"caused a {diff_ratio:.0%} response difference. "
                                    "This may indicate an injection vulnerability."
                                ),
                                url=test_url,
                                parameter=param_name,
                                evidence=f"Baseline length: {len(baseline_body)}, "
                                f"Test length: {len(test_body)}, "
                                f"Diff ratio: {diff_ratio:.2f}",
                                cwe_id="CWE-89",
                                template_id="sqli-error-based",
                            )
                        )
                        break  # One finding per parameter is enough
                if found:
                    break

            if not found:
                result.checks_passed += 1
        except httpx.HTTPError as exc:
            logger.warning("Response diff check failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Check: time-based blind detection
    # ------------------------------------------------------------------

    async def _check_time_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ScanResult,
    ) -> None:
        """Detect time-based blind injection by measuring response time.

        Injects SLEEP/WAITFOR payloads into URL parameters and checks
        if the response time increases above the delay threshold.
        """
        result.checks_run += 1
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            result.checks_passed += 1
            return

        # Get payloads from KB template or use defaults
        test_payloads = ["' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"]
        delay_threshold = 4.5

        template = self._templates.get("sqli-error-based")
        if template:
            for p in template.get("patterns", []):
                if p.get("type") == "time_based":
                    test_payloads = p.get("test_payloads", test_payloads)
                    delay_threshold = p.get("delay_threshold_seconds", delay_threshold)
                    break

        try:
            # Baseline timing
            t0 = time.monotonic()
            async with self._sem:
                await client.get(url)
            baseline_time = time.monotonic() - t0

            found = False
            for param_name in params:
                for payload in test_payloads:
                    modified_params = dict(params)
                    original_val = modified_params[param_name][0] if modified_params[param_name] else ""
                    modified_params[param_name] = [original_val + payload]
                    flat_params = {k: v[0] for k, v in modified_params.items()}
                    test_url = urlunparse(parsed._replace(query=urlencode(flat_params)))

                    t0 = time.monotonic()
                    async with self._sem:
                        await client.get(test_url)
                    elapsed = time.monotonic() - t0

                    time_diff = elapsed - baseline_time
                    if time_diff >= delay_threshold:
                        found = True
                        result.findings.append(
                            VulnFinding(
                                vuln_type="time_based_sqli",
                                severity="high",
                                title=f"Time-based blind injection in '{param_name}'",
                                description=(
                                    f"Injecting time-delay payload into '{param_name}' increased "
                                    f"response time by {time_diff:.1f}s (threshold: {delay_threshold}s). "
                                    "This strongly indicates a blind SQL injection vulnerability."
                                ),
                                url=test_url,
                                parameter=param_name,
                                evidence=f"Baseline: {baseline_time:.2f}s, "
                                f"With payload: {elapsed:.2f}s, "
                                f"Diff: {time_diff:.2f}s",
                                cwe_id="CWE-89",
                                template_id="sqli-error-based",
                            )
                        )
                        break
                if found:
                    break

            if not found:
                result.checks_passed += 1
        except httpx.HTTPError as exc:
            logger.warning("Time-based check failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Check: boolean-based blind detection
    # ------------------------------------------------------------------

    async def _check_boolean_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: ScanResult,
    ) -> None:
        """Detect boolean-based blind injection.

        Sends a true-condition and false-condition payload, then compares
        response content length. A significant difference indicates the
        application evaluates the injected condition.
        """
        result.checks_run += 1
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            result.checks_passed += 1
            return

        # Get payloads from KB template or use defaults
        true_payload = "' OR '1'='1"
        false_payload = "' OR '1'='2"

        template = self._templates.get("sqli-error-based")
        if template:
            for p in template.get("patterns", []):
                if p.get("type") == "boolean_based":
                    true_payload = p.get("true_payload", true_payload)
                    false_payload = p.get("false_payload", false_payload)
                    break

        try:
            found = False
            for param_name in params:
                original_val = params[param_name][0] if params[param_name] else ""

                # True condition
                true_params = dict(params)
                true_params[param_name] = [original_val + true_payload]
                true_flat = {k: v[0] for k, v in true_params.items()}
                true_url = urlunparse(parsed._replace(query=urlencode(true_flat)))

                # False condition
                false_params = dict(params)
                false_params[param_name] = [original_val + false_payload]
                false_flat = {k: v[0] for k, v in false_params.items()}
                false_url = urlunparse(parsed._replace(query=urlencode(false_flat)))

                async with self._sem:
                    true_resp = await client.get(true_url)
                async with self._sem:
                    false_resp = await client.get(false_url)

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                diff_pct = abs(true_len - false_len) / max(true_len, false_len, 1)

                if diff_pct > 0.1:
                    found = True
                    result.findings.append(
                        VulnFinding(
                            vuln_type="boolean_based_sqli",
                            severity="high",
                            title=f"Boolean-based blind injection in '{param_name}'",
                            description=(
                                f"True/false condition payloads produce different response "
                                f"sizes ({true_len} vs {false_len}, {diff_pct:.0%} difference). "
                                "The application evaluates the injected condition, indicating "
                                "a blind SQL injection vulnerability."
                            ),
                            url=url,
                            parameter=param_name,
                            evidence=f"True response length: {true_len}, "
                            f"False response length: {false_len}, "
                            f"Diff: {diff_pct:.0%}",
                            cwe_id="CWE-89",
                            template_id="sqli-error-based",
                        )
                    )
                    break

            if not found:
                result.checks_passed += 1
        except httpx.HTTPError as exc:
            logger.warning("Boolean-based check failed for %s: %s", url, exc)


# ---------------------------------------------------------------------------
# Tool wrapper function for ToolRegistry
# ---------------------------------------------------------------------------


async def python_vuln_scan(url: str, checks: str | None = None) -> str:
    """Run Python-native vulnerability scan.

    Parameters
    ----------
    url:
        Target URL to scan.
    checks:
        Comma-separated check types. Default: all passive checks.
        Options: headers, technologies, response_match, response_diff,
        time_based, boolean_based.

    Returns
    -------
    str
        JSON string with scan results.
    """
    import json

    check_list = [c.strip() for c in checks.split(",")] if checks else None
    scanner = PythonVulnScanner()
    result = await scanner.scan(url, check_list)
    return json.dumps(result.to_dict(), indent=2)
