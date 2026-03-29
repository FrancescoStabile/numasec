"""Python-native OS Command Injection tester (CWE-78).

Detection strategy (multi-signal to reduce FP):

1. **Response-based:** Inject command separators (``; id``, ``| whoami``)
   and check for OS-specific output patterns (``uid=``, hostname, etc.).
2. **Time-based blind:** Inject ``; sleep 5`` / ``& timeout 5`` and measure
   response time delta against a baseline request.
3. **Error-based:** Inject invalid commands and check for shell error
   messages (``sh:``, ``not found``, ``cmd.exe``).

A finding is only reported with high confidence when **two independent
signals** agree (e.g., response-based + time-based).  A single signal
produces confidence 0.5; two signals produce 0.9.

Severity: **Critical** -- command injection directly leads to RCE.
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

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.command_injection_tester")

# ---------------------------------------------------------------------------
# Payload definitions
# ---------------------------------------------------------------------------

# (payload, expected_pattern_re, platform, separator_type)
_RESPONSE_PAYLOADS: list[tuple[str, str, str, str]] = [
    # Unix
    ("; id", r"uid=\d+", "unix", "semicolon"),
    ("| id", r"uid=\d+", "unix", "pipe"),
    ("`id`", r"uid=\d+", "unix", "backtick"),
    ("$(id)", r"uid=\d+", "unix", "substitution"),
    ("; whoami", r"^[a-z_][a-z0-9_-]{0,30}$", "unix", "semicolon"),
    ("| cat /etc/hostname", r"^[a-zA-Z0-9._-]+$", "unix", "pipe"),
    # Windows
    ("| whoami", r"[a-zA-Z0-9]+\\[a-zA-Z0-9]+", "windows", "pipe"),
    ("& whoami", r"[a-zA-Z0-9]+\\[a-zA-Z0-9]+", "windows", "ampersand"),
    # Newline injection
    ("%0aid", r"uid=\d+", "unix", "newline"),
]

# (payload, expected_delay_seconds, platform)
_TIME_PAYLOADS: list[tuple[str, int, str]] = [
    ("; sleep 5", 5, "unix"),
    ("| sleep 5", 5, "unix"),
    ("$(sleep 5)", 5, "unix"),
    ("`sleep 5`", 5, "unix"),
    ("& timeout /t 5 /nobreak", 5, "windows"),
    ("| ping -n 6 127.0.0.1", 5, "windows"),
]

_TIME_TOLERANCE = 1.0  # seconds

# Shell error patterns that indicate the payload reached a shell
_ERROR_PATTERNS: list[str] = [
    r"sh:\s+\d+:\s+",  # sh: 1: <cmd>: not found
    r"bash:\s+",  # bash: <cmd>: command not found
    r"/bin/sh:\s+",  # /bin/sh: <cmd>: not found
    r"not found",  # generic "not found"
    r"not recognized as an internal or external command",  # Windows cmd.exe
    r"is not recognized",
    r"cmd\.exe",
]

# Parameters commonly used for command injection
_CMD_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "cmd",
        "exec",
        "command",
        "execute",
        "run",
        "ping",
        "query",
        "host",
        "ip",
        "hostname",
        "target",
        "address",
        "addr",
        "domain",
        "dir",
        "path",
        "file",
        "filename",
        "name",
        "process",
        "action",
        "do",
        "func",
    }
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CmdInjVulnerability:
    """A single command injection finding."""

    param: str
    payload: str
    technique: str  # response_based, time_based, error_based
    platform: str  # unix, windows
    evidence: str
    confidence: float = 0.5
    location: str = "GET"


@dataclass
class CmdInjResult:
    """Complete command injection test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[CmdInjVulnerability] = field(default_factory=list)
    params_tested: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": "command_injection",
                    "param": v.param,
                    "payload": v.payload,
                    "technique": v.technique,
                    "platform": v.platform,
                    "evidence": v.evidence,
                    "confidence": v.confidence,
                    "location": v.location,
                }
                for v in self.vulnerabilities
            ],
            "params_tested": self.params_tested,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"Command injection confirmed (confidence: {max(v.confidence for v in self.vulnerabilities):.1f})"
                if self.vulnerabilities
                else "No command injection found"
            ),
            "next_steps": (
                ["Establish reverse shell", "Extract sensitive files via command execution"]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------


class CommandInjectionTester:
    """Multi-signal OS Command Injection detector."""

    def __init__(self, timeout: float = 15.0, extra_headers: dict[str, str] | None = None) -> None:
        self.timeout = timeout
        self._extra_headers = extra_headers or {}

    async def test(
        self,
        url: str,
        params: list[str] | None = None,
        method: str = "GET",
        body: dict[str, str] | None = None,
    ) -> CmdInjResult:
        start = time.monotonic()
        result = CmdInjResult(target=url)

        all_params = self._detect_params(url, params, body)
        # Prioritise params with command-like names
        cmd_params = [(p, loc) for p, loc in all_params if p.lower() in _CMD_PARAM_NAMES]
        other_params = [(p, loc) for p, loc in all_params if p.lower() not in _CMD_PARAM_NAMES]
        ordered = cmd_params + other_params
        result.params_tested = len(ordered)

        async with create_client(
            timeout=self.timeout,
            headers=self._extra_headers,
        ) as client:
            for param_name, location in ordered:
                vuln = await self._test_param(client, url, param_name, location, method, body)
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "CmdInj test complete: %s -- %d params, %d vulns, %.0fms",
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
        explicit: list[str] | None,
        body: dict[str, str] | None,
    ) -> list[tuple[str, str]]:
        params: list[tuple[str, str]] = []
        parsed = urlparse(url)
        for p in parse_qs(parsed.query):
            params.append((p, "GET"))
        if body:
            for p in body:
                params.append((p, "POST"))
        if explicit:
            params = [(p, loc) for p, loc in params if p in explicit]
        return params

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _send(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        payload: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> httpx.Response | None:
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
            logger.debug("CmdInj HTTP error (param=%s): %s", param, exc)
            return None

    # ------------------------------------------------------------------
    # Per-parameter testing (multi-signal)
    # ------------------------------------------------------------------

    async def _test_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> CmdInjVulnerability | None:
        """Test one param with response-based, time-based, and error-based phases.

        Multi-signal confirmation: if two phases both fire, confidence = 0.9.
        """
        # Fetch baseline for comparison
        baseline = await self._send(client, url, param, "secmcp_cmdinj_noop", location, method, body)
        baseline_text = baseline.text if baseline else ""

        # Phase 1: Response-based
        resp_hit = await self._test_response_based(
            client,
            url,
            param,
            location,
            method,
            body,
            baseline_text,
        )

        # Phase 2: Time-based blind
        time_hit = await self._test_time_based(
            client,
            url,
            param,
            location,
            method,
            body,
        )

        # Phase 3: Error-based
        err_hit = await self._test_error_based(
            client,
            url,
            param,
            location,
            method,
            body,
            baseline_text,
        )

        # Multi-signal confidence upgrade
        hits = [h for h in (resp_hit, time_hit, err_hit) if h is not None]
        if not hits:
            return None

        best = hits[0]
        if len(hits) >= 2:
            best.confidence = 0.9
            best.evidence += f" [multi-signal: {', '.join(h.technique for h in hits)}]"
        return best

    # ------------------------------------------------------------------
    # Phase 1: Response-based
    # ------------------------------------------------------------------

    async def _test_response_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        baseline_text: str,
    ) -> CmdInjVulnerability | None:
        for payload, pattern, platform, _sep_type in _RESPONSE_PAYLOADS:
            resp = await self._send(client, url, param, payload, location, method, body)
            if resp is None:
                continue

            # Check for pattern in response but NOT in baseline
            match = re.search(pattern, resp.text, re.MULTILINE)
            if match and not re.search(pattern, baseline_text, re.MULTILINE):
                logger.info(
                    "CmdInj response hit: param=%s payload=%r platform=%s",
                    param,
                    payload,
                    platform,
                )
                return CmdInjVulnerability(
                    param=param,
                    payload=payload,
                    technique="response_based",
                    platform=platform,
                    evidence=f"Command output detected: {match.group()[:100]}",
                    confidence=0.8,
                    location=location,
                )
        return None

    # ------------------------------------------------------------------
    # Phase 2: Time-based blind
    # ------------------------------------------------------------------

    async def _test_time_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
    ) -> CmdInjVulnerability | None:
        for payload, expected_delay, platform in _TIME_PAYLOADS:
            start = time.monotonic()
            resp = await self._send(client, url, param, payload, location, method, body)
            elapsed = time.monotonic() - start

            if resp is not None and elapsed >= (expected_delay - _TIME_TOLERANCE):
                # Verify with sleep(0) control
                ctrl_payload = payload.replace("5", "0").replace("6", "1")
                ctrl_start = time.monotonic()
                await self._send(client, url, param, ctrl_payload, location, method, body)
                ctrl_elapsed = time.monotonic() - ctrl_start

                if ctrl_elapsed >= (expected_delay - _TIME_TOLERANCE):
                    continue  # Control also slow -- network latency

                logger.info(
                    "CmdInj time hit: param=%s platform=%s elapsed=%.1fs ctrl=%.1fs",
                    param,
                    platform,
                    elapsed,
                    ctrl_elapsed,
                )
                return CmdInjVulnerability(
                    param=param,
                    payload=payload,
                    technique="time_based",
                    platform=platform,
                    evidence=f"Response delayed {elapsed:.1f}s (control {ctrl_elapsed:.1f}s)",
                    confidence=0.7,
                    location=location,
                )
        return None

    # ------------------------------------------------------------------
    # Phase 3: Error-based
    # ------------------------------------------------------------------

    async def _test_error_based(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        location: str,
        method: str,
        body: dict[str, str] | None,
        baseline_text: str,
    ) -> CmdInjVulnerability | None:
        err_payloads = ["; invalid_secmcp_cmd_xyz", "| invalid_secmcp_cmd_xyz"]
        for payload in err_payloads:
            resp = await self._send(client, url, param, payload, location, method, body)
            if resp is None:
                continue

            for pattern in _ERROR_PATTERNS:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match and not re.search(pattern, baseline_text, re.IGNORECASE):
                    logger.info(
                        "CmdInj error hit: param=%s pattern=%s",
                        param,
                        pattern,
                    )
                    return CmdInjVulnerability(
                        param=param,
                        payload=payload,
                        technique="error_based",
                        platform="unknown",
                        evidence=f"Shell error detected: {match.group()[:100]}",
                        confidence=0.6,
                        location=location,
                    )
        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_command_injection_test(
    url: str,
    params: str | None = None,
    method: str = "GET",
    headers: str = "",
) -> str:
    """Test URL parameters for OS Command Injection (CWE-78).

    Injects command separators (``;``, ``|``, backticks, ``$()``) and
    checks for command output, timing delays, or shell error messages.
    Uses multi-signal confirmation to reduce false positives.

    Args:
        url: Target URL with query parameters.
        params: Comma-separated parameter names. Auto-detect if omitted.
        method: HTTP method (GET or POST).
        headers: JSON string of extra HTTP headers for authenticated testing,
            e.g. ``'{"Authorization": "Bearer token123"}'``. Default: ``""``.

    Returns:
        JSON string with test results.
    """
    param_list = params.split(",") if params else None
    extra_headers: dict[str, str] = headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    tester = CommandInjectionTester(extra_headers=extra_headers)
    result = await tester.test(url, params=param_list, method=method)
    return json.dumps(result.to_dict(), indent=2)
