"""Python-native HTTP request smuggling tester.

Detects HTTP request smuggling vulnerabilities using **safe** timing-based
detection.  Instead of actually smuggling requests (dangerous), we exploit
the fact that front-end / back-end header disagreements cause observable
timing differences:

1. **CL.TE** — front-end uses Content-Length, back-end uses Transfer-Encoding.
   Send oversized Content-Length with a valid chunked body; if the server waits
   for more data, it processes CL first.
2. **TE.CL** — front-end uses Transfer-Encoding, back-end uses Content-Length.
   Send valid chunks with short Content-Length; timing difference indicates
   processing order.
3. **TE.TE** — both sides use Transfer-Encoding but one can be tricked by
   obfuscated header variants (e.g. extra spaces, tab, duplicate headers).
4. **H2 smuggling** — HTTP/2 front-end downgrades to HTTP/1.1 on back-end,
   allowing Transfer-Encoding injection.

Raw sockets (``asyncio.open_connection``) are used for probes because
``httpx`` normalises headers and cannot send the malformed requests required
for smuggling detection.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.smuggling_tester")

# ---------------------------------------------------------------------------
# Timing thresholds
# ---------------------------------------------------------------------------

# If a probe response takes this many seconds longer than the baseline,
# we consider the server to be "waiting for more data" — a smuggling signal.
_TIMING_THRESHOLD_S: float = 5.0

# Default read timeout applied to each raw-socket probe.
_PROBE_TIMEOUT_S: float = 10.0

# Number of baseline requests to average for a stable reference.
_BASELINE_ROUNDS: int = 3

# ---------------------------------------------------------------------------
# TE obfuscation variants (Technique 3)
# ---------------------------------------------------------------------------

TE_OBFUSCATION_VARIANTS: list[tuple[str, str]] = [
    ("Transfer-Encoding: chunked", "standard"),
    ("Transfer-Encoding : chunked", "space_before_colon"),
    ("Transfer-Encoding: xchunked", "xchunked"),
    ("Transfer-Encoding: chunked\r\nTransfer-Encoding: cow", "duplicate_header"),
    ("Transfer-Encoding: chunked, cow", "comma_variant"),
    ("Transfer-Encoding:\tchunked", "tab_separator"),
    ("X-Transfer-Encoding: chunked", "x_prefix"),
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SmugglingVulnerability:
    """A single HTTP request smuggling finding."""

    smuggle_type: str  # "cl_te" | "te_cl" | "te_te" | "h2_smuggling"
    evidence: str
    severity: str = "critical"
    confidence: float = 0.7


@dataclass
class SmugglingResult:
    """Complete HTTP request smuggling test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[SmugglingVulnerability] = field(default_factory=list)
    techniques_tested: list[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": "http_request_smuggling",
                    "smuggle_type": v.smuggle_type,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "techniques_tested": self.techniques_tested,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"HTTP request smuggling detected ({len(self.vulnerabilities)} finding(s): "
                + ", ".join(v.smuggle_type for v in self.vulnerabilities)
                + ")"
                if self.vulnerabilities
                else "No HTTP request smuggling found"
            ),
            "next_steps": (
                [
                    "Verify smuggling with manual replay in Burp Suite Turbo Intruder",
                    "Test for cache poisoning via smuggled requests",
                    "Attempt request routing hijack to access internal endpoints",
                    "Check if smuggling can bypass authentication or WAF rules",
                ]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# Smuggling detection engine
# ---------------------------------------------------------------------------


class SmugglingTester:
    """Safe timing-based HTTP request smuggling detector.

    Parameters
    ----------
    timeout:
        Per-probe read timeout in seconds.
    extra_headers:
        Additional headers for authenticated testing.
    """

    def __init__(
        self,
        timeout: float = _PROBE_TIMEOUT_S,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._extra_headers = extra_headers or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def test(self, url: str) -> SmugglingResult:
        """Run HTTP request smuggling tests against *url*.

        Returns a ``SmugglingResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = SmugglingResult(target=url)

        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        if not host:
            result.duration_ms = (time.monotonic() - start) * 1000
            return result

        # Baseline: measure normal response time
        baseline_s = await self._measure_baseline(url)

        # Technique 1: CL.TE
        result.techniques_tested.append("cl_te")
        vuln = await self._time_based_clte(host, port, path, use_tls, baseline_s)
        if vuln:
            result.vulnerabilities.append(vuln)
            result.vulnerable = True

        # Technique 2: TE.CL
        result.techniques_tested.append("te_cl")
        vuln = await self._time_based_tecl(host, port, path, use_tls, baseline_s)
        if vuln:
            result.vulnerabilities.append(vuln)
            result.vulnerable = True

        # Technique 3: TE.TE (obfuscation)
        result.techniques_tested.append("te_te")
        vulns = await self._test_te_obfuscation(host, port, path, use_tls, baseline_s)
        for v in vulns:
            result.vulnerabilities.append(v)
            result.vulnerable = True

        # Technique 4: H2 smuggling probe
        result.techniques_tested.append("h2_smuggling")
        vuln = await self._test_h2_smuggling(url, host, port, path, use_tls, baseline_s)
        if vuln:
            result.vulnerabilities.append(vuln)
            result.vulnerable = True

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Smuggling test complete: %s — %d techniques, %d vulns, %.0fms",
            url,
            len(result.techniques_tested),
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Baseline measurement
    # ------------------------------------------------------------------

    async def _measure_baseline(self, url: str) -> float:
        """Measure average response time for a normal GET request.

        Uses ``create_client`` (httpx) for a clean baseline that avoids
        any raw-socket overhead.
        """
        times: list[float] = []
        try:
            async with create_client(
                timeout=self.timeout,
                headers=self._extra_headers or None,
            ) as client:
                for _ in range(_BASELINE_ROUNDS):
                    t0 = time.monotonic()
                    with contextlib.suppress(Exception):
                        await client.get(url)
                    times.append(time.monotonic() - t0)
        except Exception:  # noqa: BLE001
            logger.debug("Baseline measurement failed for %s", url)
            return 1.0

        return sum(times) / len(times) if times else 1.0

    # ------------------------------------------------------------------
    # Raw socket transport
    # ------------------------------------------------------------------

    async def _send_raw_request(
        self,
        host: str,
        port: int,
        raw_request: bytes,
        timeout: float | None = None,
        use_tls: bool = False,
    ) -> tuple[bytes, float]:
        """Send a raw HTTP request and return ``(response_bytes, elapsed_seconds)``.

        Uses ``asyncio.open_connection`` to bypass ``httpx`` header
        normalisation — essential for sending the conflicting header
        combinations required for smuggling detection.
        """
        timeout = timeout or self.timeout
        ssl_ctx: ssl.SSLContext | None = None
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        writer: asyncio.StreamWriter | None = None
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=timeout,
            )
            writer = w
            start = time.monotonic()
            w.write(raw_request)
            await w.drain()
            try:
                response = await asyncio.wait_for(r.read(4096), timeout=timeout)
            except TimeoutError:
                response = b""
            elapsed = time.monotonic() - start
            return response, elapsed
        except (OSError, TimeoutError) as exc:
            logger.debug("Raw request to %s:%d failed: %s", host, port, exc)
            return b"", timeout
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------
    # Technique 1: CL.TE — time-based
    # ------------------------------------------------------------------

    async def _time_based_clte(
        self,
        host: str,
        port: int,
        path: str,
        use_tls: bool,
        baseline_s: float,
    ) -> SmugglingVulnerability | None:
        """Detect CL.TE by sending oversized Content-Length with chunked body.

        If the server reads Content-Length, it will wait for more data
        (since CL is larger than the actual body) → observable timeout.
        If it reads Transfer-Encoding, the chunked terminator ends the
        request immediately → fast response.
        """
        extra_hdrs = self._format_extra_headers()

        # Body: valid chunked terminator "0\\r\\n\\r\\n" is 5 bytes, but
        # we claim Content-Length: 50 so a CL-first server waits for 45 more.
        body = b"0\r\n\r\n"
        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 50\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"{extra_hdrs}"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + body

        response, elapsed = await self._send_raw_request(host, port, raw, use_tls=use_tls)

        delay = elapsed - baseline_s
        if delay >= _TIMING_THRESHOLD_S:
            return SmugglingVulnerability(
                smuggle_type="cl_te",
                evidence=(
                    f"CL.TE timing anomaly: probe took {elapsed:.1f}s vs "
                    f"baseline {baseline_s:.1f}s (delta {delay:.1f}s). "
                    f"Server appears to read Content-Length first and waits "
                    f"for the remaining bytes, ignoring Transfer-Encoding chunked "
                    f"terminator. This indicates CL.TE request smuggling."
                ),
                severity="critical",
                confidence=0.6,
            )

        # Check for differential response (e.g. 400 Bad Request from parser confusion)
        if response and self._indicates_parser_confusion(response):
            return SmugglingVulnerability(
                smuggle_type="cl_te",
                evidence=(
                    f"CL.TE response anomaly: server returned an error response "
                    f"when receiving conflicting Content-Length and Transfer-Encoding "
                    f"headers. Response snippet: {response[:200]!r}"
                ),
                severity="critical",
                confidence=0.8,
            )

        return None

    # ------------------------------------------------------------------
    # Technique 2: TE.CL — time-based
    # ------------------------------------------------------------------

    async def _time_based_tecl(
        self,
        host: str,
        port: int,
        path: str,
        use_tls: bool,
        baseline_s: float,
    ) -> SmugglingVulnerability | None:
        """Detect TE.CL by sending valid chunks with short Content-Length.

        The request contains a valid chunked body ("1\\r\\nX\\r\\n0\\r\\n\\r\\n")
        but Content-Length: 3.  A TE-first server reads all chunks normally.
        A CL-first server reads only 3 bytes ("1\\r\\n") and leaves the rest in
        the buffer.  We set Content-Length to a value larger than the first
        line so a CL-first server would block waiting for data.
        """
        extra_hdrs = self._format_extra_headers()

        # Chunked body: chunk of size 1 ("X"), then terminator
        chunked_body = b"1\r\nX\r\n0\r\n\r\n"
        # CL deliberately larger than body to cause CL-first server to wait
        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 50\r\n"
            f"{extra_hdrs}"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + chunked_body

        response, elapsed = await self._send_raw_request(host, port, raw, use_tls=use_tls)

        delay = elapsed - baseline_s
        if delay >= _TIMING_THRESHOLD_S:
            return SmugglingVulnerability(
                smuggle_type="te_cl",
                evidence=(
                    f"TE.CL timing anomaly: probe took {elapsed:.1f}s vs "
                    f"baseline {baseline_s:.1f}s (delta {delay:.1f}s). "
                    f"Server appears to read Content-Length first and waits "
                    f"for additional bytes, ignoring Transfer-Encoding chunks. "
                    f"This indicates TE.CL request smuggling."
                ),
                severity="critical",
                confidence=0.6,
            )

        if response and self._indicates_parser_confusion(response):
            return SmugglingVulnerability(
                smuggle_type="te_cl",
                evidence=(
                    f"TE.CL response anomaly: server returned an error response "
                    f"when receiving conflicting Transfer-Encoding and Content-Length "
                    f"headers. Response snippet: {response[:200]!r}"
                ),
                severity="critical",
                confidence=0.8,
            )

        return None

    # ------------------------------------------------------------------
    # Technique 3: TE.TE — obfuscation variants
    # ------------------------------------------------------------------

    async def _test_te_obfuscation(
        self,
        host: str,
        port: int,
        path: str,
        use_tls: bool,
        baseline_s: float,
    ) -> list[SmugglingVulnerability]:
        """Test Transfer-Encoding obfuscation variants.

        If a front-end recognises one variant but the back-end does not
        (or vice versa), the servers disagree on body framing → smuggling.
        We detect this by comparing timing/response across variants.
        """
        vulns: list[SmugglingVulnerability] = []
        extra_hdrs = self._format_extra_headers()

        # First, send a request with standard TE header as reference
        ref_body = b"0\r\n\r\n"
        ref_raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 50\r\n"
            f"{extra_hdrs}"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + ref_body

        ref_response, ref_elapsed = await self._send_raw_request(
            host,
            port,
            ref_raw,
            use_tls=use_tls,
        )

        # Now test each obfuscation variant
        for te_header, variant_name in TE_OBFUSCATION_VARIANTS:
            if variant_name == "standard":
                continue  # skip — already used as reference

            body = b"0\r\n\r\n"
            raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{te_header}\r\n"
                f"Content-Length: 50\r\n"
                f"{extra_hdrs}"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode() + body

            response, elapsed = await self._send_raw_request(
                host,
                port,
                raw,
                use_tls=use_tls,
            )

            # Compare with reference: significant timing difference?
            timing_diff = abs(elapsed - ref_elapsed)
            if timing_diff >= _TIMING_THRESHOLD_S:
                vulns.append(
                    SmugglingVulnerability(
                        smuggle_type="te_te",
                        evidence=(
                            f"TE.TE obfuscation variant '{variant_name}' caused a "
                            f"timing anomaly: {elapsed:.1f}s vs reference {ref_elapsed:.1f}s "
                            f"(delta {timing_diff:.1f}s). Header used: '{te_header}'. "
                            f"The server handles this TE variant differently from the "
                            f"standard 'Transfer-Encoding: chunked', indicating the "
                            f"front-end and back-end disagree on body framing."
                        ),
                        severity="critical",
                        confidence=0.6,
                    )
                )
                continue

            # Different response status/pattern from reference?
            ref_status = self._extract_status_code(ref_response)
            var_status = self._extract_status_code(response)
            if ref_status and var_status and ref_status != var_status:
                vulns.append(
                    SmugglingVulnerability(
                        smuggle_type="te_te",
                        evidence=(
                            f"TE.TE obfuscation variant '{variant_name}' produced a "
                            f"different HTTP status ({var_status}) than the standard "
                            f"TE header ({ref_status}). Header: '{te_header}'. "
                            f"Servers handle this variant differently."
                        ),
                        severity="critical",
                        confidence=0.8,
                    )
                )

        return vulns

    # ------------------------------------------------------------------
    # Technique 4: H2 smuggling (downgrade probe)
    # ------------------------------------------------------------------

    async def _test_h2_smuggling(
        self,
        url: str,
        host: str,
        port: int,
        path: str,
        use_tls: bool,
        baseline_s: float,
    ) -> SmugglingVulnerability | None:
        """Probe for HTTP/2 → HTTP/1.1 downgrade smuggling.

        Many reverse proxies accept HTTP/2 from clients but speak HTTP/1.1
        to backends.  If the proxy blindly forwards a Transfer-Encoding
        header that it should have stripped (H2 does not use TE), the
        backend may interpret the body differently.

        We use httpx with ``http2=True`` (if h2 is installed) to send a
        request with Transfer-Encoding in the headers.  If the server
        responds differently from the baseline, that suggests the TE
        header "leaked" through the H2→H1 downgrade.
        """
        try:
            import h2 as _h2  # noqa: F401

            h2_available = True
        except ImportError:
            h2_available = False

        if not h2_available or not use_tls:
            return None

        try:
            import httpx as _httpx

            async with _httpx.AsyncClient(
                http2=True,
                verify=False,
                timeout=self.timeout,
            ) as client:
                t0 = time.monotonic()
                resp = await client.post(
                    url,
                    content=b"0\r\n\r\n",
                    headers={
                        "Transfer-Encoding": "chunked",
                        **self._extra_headers,
                    },
                )
                elapsed = time.monotonic() - t0

            delay = elapsed - baseline_s
            if delay >= _TIMING_THRESHOLD_S:
                return SmugglingVulnerability(
                    smuggle_type="h2_smuggling",
                    evidence=(
                        f"H2 downgrade smuggling: HTTP/2 request with "
                        f"Transfer-Encoding header took {elapsed:.1f}s vs "
                        f"baseline {baseline_s:.1f}s (delta {delay:.1f}s). "
                        f"The TE header may have leaked through the H2→H1 "
                        f"downgrade, causing the backend to wait for chunked data."
                    ),
                    severity="critical",
                    confidence=0.6,
                )

            # Check for unexpected error status (TE shouldn't be in H2)
            if resp.status_code in (400, 500, 501, 502):
                return SmugglingVulnerability(
                    smuggle_type="h2_smuggling",
                    evidence=(
                        f"H2 downgrade anomaly: server returned HTTP {resp.status_code} "
                        f"when receiving Transfer-Encoding header via HTTP/2. "
                        f"This may indicate the header leaked through H2→H1 downgrade."
                    ),
                    severity="high",
                    confidence=0.6,
                )

        except Exception as exc:  # noqa: BLE001
            logger.debug("H2 smuggling probe error: %s", exc)

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _format_extra_headers(self) -> str:
        """Format extra headers as raw HTTP header lines."""
        if not self._extra_headers:
            return ""
        lines = [f"{k}: {v}\r\n" for k, v in self._extra_headers.items()]
        return "".join(lines)

    @staticmethod
    def _indicates_parser_confusion(response: bytes) -> bool:
        """Check if a raw response indicates HTTP parser confusion.

        Returns ``True`` if the response contains error indicators that
        suggest the server could not parse the conflicting headers.
        """
        if not response:
            return False

        confusion_indicators = [
            b"invalid request",
            b"parse error",
            b"malformed",
            b"transfer-encoding",
            b"content-length",
            b"smuggl",
        ]
        # A 400 status by itself is interesting but not conclusive.
        # We need an error-like status AND a body indicator.
        status_line = response.split(b"\r\n", 1)[0] if b"\r\n" in response else response[:50]
        is_error_status = any(code in status_line for code in [b"400", b"501", b"502"])

        if not is_error_status:
            return False

        # Check indicators in the body only (after the status line)
        body = response.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in response else response
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in confusion_indicators)

    @staticmethod
    def _extract_status_code(response: bytes) -> int | None:
        """Extract HTTP status code from a raw response."""
        if not response:
            return None
        try:
            status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            parts = status_line.split(" ", 2)
            if len(parts) >= 2:
                return int(parts[1])
        except (ValueError, IndexError):
            pass
        return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_smuggling_test(url: str, headers: str | None = None) -> str:
    """Test URL for HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE).

    Uses safe timing-based detection to identify whether front-end and
    back-end servers disagree on how to parse Content-Length vs
    Transfer-Encoding headers.

    Args:
        url: Target URL to test.
        headers: Optional JSON string of HTTP headers for authenticated
            testing, e.g. ``'{"Authorization": "Bearer token123"}'``.

    Returns:
        JSON string with ``SmugglingResult`` data.
    """
    import contextlib

    parsed_headers: dict[str, str] | None = None
    if headers:
        with contextlib.suppress(json.JSONDecodeError):
            parsed_headers = headers if isinstance(headers, dict) else json.loads(headers)

    tester = SmugglingTester(extra_headers=parsed_headers)
    result = await tester.test(url)
    return json.dumps(result.to_dict(), indent=2)
