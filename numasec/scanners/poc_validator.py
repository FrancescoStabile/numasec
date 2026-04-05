"""PoC validation framework — re-test confirmed findings with actual exploit attempts.

Takes existing findings and attempts to reproduce the vulnerability by:
1. Sending a baseline request (no payload)
2. Sending the exploit request (with payload)
3. Comparing responses for evidence of the vulnerability

Supports CWE-specific validation logic for SQLi, XSS, LFI, SSRF,
Command Injection, and CRLF, plus a generic baseline-diff validator.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from numasec.core.http import create_client
from numasec.scanners._envelope import wrap_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PocResult:
    """Outcome of validating a single finding."""

    finding_id: str
    validated: bool
    confidence: float  # 0.0–1.0
    evidence: str = ""
    request_dump: str = ""
    response_status: int | None = None
    response_snippet: str = ""
    technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    """Aggregate result for a batch of findings."""

    target: str
    total_tested: int = 0
    validated: int = 0
    failed: int = 0
    errors: int = 0
    results: list[PocResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total_tested": self.total_tested,
            "validated": self.validated,
            "failed": self.failed,
            "errors": self.errors,
            "results": [r.to_dict() for r in self.results],
            "summary": (
                f"{self.validated}/{self.total_tested} findings validated"
                if self.total_tested
                else "No findings tested"
            ),
        }


# ---------------------------------------------------------------------------
# SQL error / indicator patterns (CWE-89)
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\):", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQLite3::query", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"ODBC SQL Server Driver", re.I),
    re.compile(r"syntax error at or near", re.I),
    re.compile(r"unterminated string literal", re.I),
]

# ---------------------------------------------------------------------------
# LFI markers (CWE-22)
# ---------------------------------------------------------------------------

_LFI_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"root:[x*]:0:0:"),
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"\[extensions\]", re.I),
    re.compile(r"daemon:[x*]:\d+:\d+:"),
]

# ---------------------------------------------------------------------------
# SSRF indicators (CWE-918)
# ---------------------------------------------------------------------------

_SSRF_INDICATORS: list[str] = [
    "ami-id",
    "meta-data",
    "computeMetadata",
    "instance-identity",
    "iam/security-credentials",
    "169.254.169.254",
]

# ---------------------------------------------------------------------------
# Command injection output patterns (CWE-78)
# ---------------------------------------------------------------------------

_CMDI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"uid=\d+\([\w-]+\)\s+gid=\d+"),
    re.compile(r"^(?:root|www-data|nobody|[a-z_][a-z0-9_-]{0,30})$", re.M),
]


# ---------------------------------------------------------------------------
# PocValidator — core class
# ---------------------------------------------------------------------------


class PocValidator:
    """Validates findings by re-testing with targeted exploit techniques."""

    def __init__(
        self,
        timeout: float = 15.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.headers = headers or {}

    # -- public API ---------------------------------------------------------

    async def validate(self, finding: dict[str, Any]) -> PocResult:
        """Validate a single finding based on its CWE type."""
        cwe = finding.get("cwe_id", "") or finding.get("cwe", "")
        finding_id = finding.get("id", finding.get("finding_id", "unknown"))

        validators: dict[str, Any] = {
            "CWE-89": self._validate_sqli,
            "CWE-79": self._validate_xss,
            "CWE-22": self._validate_lfi,
            "CWE-918": self._validate_ssrf,
            "CWE-78": self._validate_cmdi,
            "CWE-113": self._validate_crlf,
        }

        validator = validators.get(cwe, self._validate_generic)

        try:
            return await validator(finding, finding_id)
        except httpx.HTTPError as exc:
            logger.debug("HTTP error validating %s: %s", finding_id, exc)
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence=f"HTTP error: {exc}",
                technique="error",
            )
        except Exception as exc:
            logger.exception("Unexpected error validating %s", finding_id)
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence=f"Validation error: {exc}",
                technique="error",
            )

    async def validate_findings(
        self,
        findings: list[dict[str, Any]],
        target: str = "",
    ) -> ValidationResult:
        """Validate a list of findings and collect aggregate statistics."""
        result = ValidationResult(target=target)
        result.total_tested = len(findings)

        for finding in findings:
            poc = await self.validate(finding)
            result.results.append(poc)
            if poc.technique == "error":
                result.errors += 1
            elif poc.validated:
                result.validated += 1
            else:
                result.failed += 1

        return result

    # -- HTTP helpers -------------------------------------------------------

    async def _send_baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str = "GET",
    ) -> httpx.Response | None:
        """Send a clean request with no payload to establish a baseline."""
        try:
            if method.upper() == "POST":
                return await client.post(url)
            return await client.get(url)
        except httpx.HTTPError as exc:
            logger.debug("Baseline request failed: %s", exc)
            return None

    async def _send_exploit(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
    ) -> httpx.Response | None:
        """Send the exploit payload injected into the target parameter."""
        try:
            if method.upper() == "POST":
                return await client.post(url, data={param: payload})
            # GET — inject into query string
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            injected = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return await client.get(injected)
        except httpx.HTTPError as exc:
            logger.debug("Exploit request failed: %s", exc)
            return None

    @staticmethod
    def _dump_request(url: str, param: str, payload: str, method: str = "GET") -> str:
        """Build a human-readable request dump for the PocResult."""
        if method.upper() == "POST":
            return f"POST {url}\nContent-Type: application/x-www-form-urlencoded\n\n{param}={payload}"
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        injected = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        return f"GET {injected}"

    @staticmethod
    def _snippet(text: str, max_len: int = 500) -> str:
        """Truncate response text for evidence."""
        if len(text) <= max_len:
            return text
        return text[:max_len] + "…"

    # -- CWE-89: SQL injection ----------------------------------------------

    async def _validate_sqli(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> PocResult:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "' OR '1'='1")
        method = finding.get("method", "GET")

        async with create_client(timeout=self.timeout, headers=self.headers or None) as client:
            baseline_resp = await self._send_baseline(client, url, method)
            exploit_resp = await self._send_exploit(client, url, param, payload, method)

        if exploit_resp is None:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Exploit request returned no response",
                technique="sqli",
            )

        body = exploit_resp.text

        # Check for SQL error signatures
        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.9,
                    evidence=f"SQL error detected: {match.group(0)}",
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(body),
                    technique="sqli_error",
                )

        # Boolean-based: significant content-length difference
        if baseline_resp is not None:
            baseline_len = len(baseline_resp.text)
            exploit_len = len(body)
            if baseline_len > 0:
                diff_ratio = abs(exploit_len - baseline_len) / baseline_len
                if diff_ratio > 0.3:
                    return PocResult(
                        finding_id=finding_id,
                        validated=True,
                        confidence=0.6,
                        evidence=(
                            f"Boolean-based: baseline {baseline_len} bytes vs "
                            f"exploit {exploit_len} bytes (diff {diff_ratio:.0%})"
                        ),
                        request_dump=self._dump_request(url, param, payload, method),
                        response_status=exploit_resp.status_code,
                        response_snippet=self._snippet(body),
                        technique="sqli_boolean",
                    )

        return PocResult(
            finding_id=finding_id,
            validated=False,
            confidence=0.0,
            evidence="No SQL error or boolean difference detected",
            request_dump=self._dump_request(url, param, payload, method),
            response_status=exploit_resp.status_code,
            technique="sqli",
        )

    # -- CWE-79: Cross-Site Scripting ---------------------------------------

    async def _validate_xss(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> PocResult:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "<script>alert(1)</script>")
        method = finding.get("method", "GET")

        async with create_client(timeout=self.timeout, headers=self.headers or None) as client:
            exploit_resp = await self._send_exploit(client, url, param, payload, method)

        if exploit_resp is None:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Exploit request returned no response",
                technique="xss",
            )

        body = exploit_resp.text

        # Check if payload is reflected unescaped
        if payload in body:
            return PocResult(
                finding_id=finding_id,
                validated=True,
                confidence=0.9,
                evidence=f"Payload reflected unescaped in response body: {payload}",
                request_dump=self._dump_request(url, param, payload, method),
                response_status=exploit_resp.status_code,
                response_snippet=self._snippet(body),
                technique="xss_reflected",
            )

        # Partial reflection — check for unescaped angle brackets from payload
        stripped = payload.replace("<", "").replace(">", "")
        if stripped and stripped in body and "<" in body:
            content_type = exploit_resp.headers.get("content-type", "")
            if "html" in content_type.lower():
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.5,
                    evidence="Partial payload reflection in HTML context detected",
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(body),
                    technique="xss_partial",
                )

        return PocResult(
            finding_id=finding_id,
            validated=False,
            confidence=0.0,
            evidence="Payload not reflected unescaped in response",
            request_dump=self._dump_request(url, param, payload, method),
            response_status=exploit_resp.status_code,
            technique="xss",
        )

    # -- CWE-22: Local File Inclusion / Path Traversal ----------------------

    async def _validate_lfi(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> PocResult:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "../../../etc/passwd")
        method = finding.get("method", "GET")

        async with create_client(timeout=self.timeout, headers=self.headers or None) as client:
            baseline_resp = await self._send_baseline(client, url, method)
            exploit_resp = await self._send_exploit(client, url, param, payload, method)

        if exploit_resp is None:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Exploit request returned no response",
                technique="lfi",
            )

        body = exploit_resp.text

        # Check for known file markers
        for pattern in _LFI_MARKERS:
            match = pattern.search(body)
            if match:
                idx = match.start()
                snippet_start = max(0, idx - 40)
                snippet_end = min(len(body), match.end() + 40)
                context = body[snippet_start:snippet_end]
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.9,
                    evidence=f"LFI marker detected: …{context}…",
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(body),
                    technique="lfi_marker",
                )

        # Fallback: content differs substantially from baseline
        if baseline_resp is not None and len(baseline_resp.text) > 0:
            diff_ratio = abs(len(body) - len(baseline_resp.text)) / len(baseline_resp.text)
            if diff_ratio > 0.5 and len(body) > len(baseline_resp.text):
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.4,
                    evidence=f"Response size increased significantly ({diff_ratio:.0%}) with traversal payload",
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(body),
                    technique="lfi_size_diff",
                )

        return PocResult(
            finding_id=finding_id,
            validated=False,
            confidence=0.0,
            evidence="No LFI markers or size difference detected",
            request_dump=self._dump_request(url, param, payload, method),
            response_status=exploit_resp.status_code,
            technique="lfi",
        )

    # -- CWE-918: Server-Side Request Forgery -------------------------------

    async def _validate_ssrf(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> PocResult:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "http://169.254.169.254/latest/meta-data/")
        method = finding.get("method", "GET")

        async with create_client(timeout=self.timeout, headers=self.headers or None) as client:
            baseline_resp = await self._send_baseline(client, url, method)
            exploit_resp = await self._send_exploit(client, url, param, payload, method)

        if exploit_resp is None:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Exploit request returned no response",
                technique="ssrf",
            )

        body = exploit_resp.text.lower()

        # Check cloud metadata / internal indicators
        for indicator in _SSRF_INDICATORS:
            if indicator.lower() in body:
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.8,
                    evidence=f"SSRF indicator detected: '{indicator}' found in response",
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(exploit_resp.text),
                    technique="ssrf_indicator",
                )

        # Fallback: response differs significantly from baseline
        if baseline_resp is not None and len(baseline_resp.text) > 0:
            baseline_lower = baseline_resp.text.lower()
            if body != baseline_lower and abs(len(body) - len(baseline_lower)) > 50:
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.4,
                    evidence="Response content differs from baseline with SSRF payload",
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(exploit_resp.text),
                    technique="ssrf_diff",
                )

        return PocResult(
            finding_id=finding_id,
            validated=False,
            confidence=0.0,
            evidence="No SSRF indicators or response differences detected",
            request_dump=self._dump_request(url, param, payload, method),
            response_status=exploit_resp.status_code,
            technique="ssrf",
        )

    # -- CWE-78: OS Command Injection --------------------------------------

    async def _validate_cmdi(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> PocResult:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        method = finding.get("method", "GET")

        # Use a safe canary command for validation
        validation_payloads = [
            ("; id", _CMDI_PATTERNS[0]),
            ("| id", _CMDI_PATTERNS[0]),
        ]
        # If finding has a payload, test it first
        if payload:
            validation_payloads.insert(0, (payload, _CMDI_PATTERNS[0]))

        async with create_client(timeout=self.timeout, headers=self.headers or None) as client:
            baseline_resp = await self._send_baseline(client, url, method)

            for test_payload, _pattern in validation_payloads:
                exploit_resp = await self._send_exploit(client, url, param, test_payload, method)
                if exploit_resp is None:
                    continue

                body = exploit_resp.text

                # Check for command output patterns
                for cmd_pattern in _CMDI_PATTERNS:
                    match = cmd_pattern.search(body)
                    if match:
                        # Verify it's not in baseline
                        if baseline_resp is not None and cmd_pattern.search(baseline_resp.text):
                            continue
                        return PocResult(
                            finding_id=finding_id,
                            validated=True,
                            confidence=0.85,
                            evidence=f"Command output detected: {match.group(0)}",
                            request_dump=self._dump_request(url, param, test_payload, method),
                            response_status=exploit_resp.status_code,
                            response_snippet=self._snippet(body),
                            technique="cmdi_output",
                        )

        return PocResult(
            finding_id=finding_id,
            validated=False,
            confidence=0.0,
            evidence="No command injection output detected",
            request_dump=self._dump_request(url, param, payload or "; id", method),
            technique="cmdi",
        )

    # -- CWE-113: CRLF Injection --------------------------------------------

    async def _validate_crlf(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> PocResult:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "%0d%0aX-Injected: numasec-poc")
        method = finding.get("method", "GET")

        async with create_client(timeout=self.timeout, headers=self.headers or None) as client:
            exploit_resp = await self._send_exploit(client, url, param, payload, method)

        if exploit_resp is None:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Exploit request returned no response",
                technique="crlf",
            )

        # Check for injected header in response headers
        for name, value in exploit_resp.headers.items():
            if name.lower() in ("x-injected", "x-crlf-test"):
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.95,
                    evidence=f"Injected header detected: {name}: {value}",
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(exploit_resp.text),
                    technique="crlf_header",
                )

        # Check for response splitting marker in body
        body = exploit_resp.text
        if "numasec-poc" in body or "numasec-crlf" in body:
            return PocResult(
                finding_id=finding_id,
                validated=True,
                confidence=0.8,
                evidence="CRLF payload marker found in response body (response splitting)",
                request_dump=self._dump_request(url, param, payload, method),
                response_status=exploit_resp.status_code,
                response_snippet=self._snippet(body),
                technique="crlf_splitting",
            )

        return PocResult(
            finding_id=finding_id,
            validated=False,
            confidence=0.0,
            evidence="No injected headers or response splitting detected",
            request_dump=self._dump_request(url, param, payload, method),
            response_status=exploit_resp.status_code,
            technique="crlf",
        )

    # -- Generic validator: baseline comparison -----------------------------

    async def _validate_generic(
        self,
        finding: dict[str, Any],
        finding_id: str,
    ) -> PocResult:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        method = finding.get("method", "GET")

        if not url or not param or not payload:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Insufficient finding data (missing url, parameter, or payload)",
                technique="generic",
            )

        async with create_client(timeout=self.timeout, headers=self.headers or None) as client:
            baseline_resp = await self._send_baseline(client, url, method)
            exploit_resp = await self._send_exploit(client, url, param, payload, method)

        if exploit_resp is None:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Exploit request returned no response",
                technique="generic",
            )

        if baseline_resp is None:
            return PocResult(
                finding_id=finding_id,
                validated=False,
                confidence=0.0,
                evidence="Baseline request returned no response",
                technique="generic",
            )

        # Status code difference
        if exploit_resp.status_code != baseline_resp.status_code:
            return PocResult(
                finding_id=finding_id,
                validated=True,
                confidence=0.5,
                evidence=(
                    f"Status code changed: baseline {baseline_resp.status_code} → exploit {exploit_resp.status_code}"
                ),
                request_dump=self._dump_request(url, param, payload, method),
                response_status=exploit_resp.status_code,
                response_snippet=self._snippet(exploit_resp.text),
                technique="generic_status",
            )

        # Content length difference
        baseline_len = len(baseline_resp.text)
        exploit_len = len(exploit_resp.text)
        if baseline_len > 0:
            diff_ratio = abs(exploit_len - baseline_len) / baseline_len
            if diff_ratio > 0.3:
                return PocResult(
                    finding_id=finding_id,
                    validated=True,
                    confidence=0.4,
                    evidence=(
                        f"Content size changed: baseline {baseline_len} bytes "
                        f"→ exploit {exploit_len} bytes ({diff_ratio:.0%} diff)"
                    ),
                    request_dump=self._dump_request(url, param, payload, method),
                    response_status=exploit_resp.status_code,
                    response_snippet=self._snippet(exploit_resp.text),
                    technique="generic_size",
                )

        # Payload reflected in response
        if payload in exploit_resp.text and (payload not in baseline_resp.text):
            return PocResult(
                finding_id=finding_id,
                validated=True,
                confidence=0.5,
                evidence="Payload reflected in exploit response but not in baseline",
                request_dump=self._dump_request(url, param, payload, method),
                response_status=exploit_resp.status_code,
                response_snippet=self._snippet(exploit_resp.text),
                technique="generic_reflection",
            )

        return PocResult(
            finding_id=finding_id,
            validated=False,
            confidence=0.0,
            evidence="No significant difference between baseline and exploit responses",
            request_dump=self._dump_request(url, param, payload, method),
            response_status=exploit_resp.status_code,
            technique="generic",
        )


# ---------------------------------------------------------------------------
# MCP tool wrapper
# ---------------------------------------------------------------------------


async def python_poc_validate(
    findings: str = "[]",
    url: str = "",
    timeout: float = 15.0,
    headers: str = "{}",
) -> str:
    """Validate existing security findings by re-testing with targeted exploit payloads.

    Args:
        findings: JSON array of finding dicts (each must have url, parameter, payload, cwe_id).
        url: Optional override URL (applied to all findings missing a url).
        timeout: HTTP request timeout in seconds.
        headers: JSON string of extra HTTP headers.

    Returns:
        JSON string with validation results.
    """
    start = time.monotonic()

    try:
        finding_list: list[dict[str, Any]] = json.loads(findings)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid findings JSON: {exc}"})

    if not isinstance(finding_list, list):
        return json.dumps({"error": "findings must be a JSON array"})

    try:
        extra_headers: dict[str, str] = (
            headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
        )
    except json.JSONDecodeError:
        extra_headers = {}

    # Apply url override to findings that lack one
    if url:
        for f in finding_list:
            if not f.get("url"):
                f["url"] = url

    target = url or (finding_list[0].get("url", "") if finding_list else "")

    validator = PocValidator(timeout=timeout, headers=extra_headers)
    result = await validator.validate_findings(finding_list, target=target)

    return json.dumps(
        wrap_result("poc_validate", target, result.to_dict(), start_time=start),
        indent=2,
    )
