"""Python-native race condition (TOCTOU) tester.

Detects race condition vulnerabilities by sending concurrent identical requests
and analysing the responses for indicators of unsafe concurrent state access:

1. **Limit bypass** — all concurrent requests succeed when rate/quota limits
   should have rejected some (e.g. coupon redemption, vote stuffing).
2. **State change** — response bodies diverge among identical concurrent
   requests, indicating unsynchronised reads/writes (TOCTOU).
3. **Duplicate action** — the server processes the same idempotent action
   multiple times (e.g. double-charge, double-transfer).

The tester floods the target endpoint with *N* identical requests using
``asyncio.gather`` and then runs heuristic checks on the collected responses.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import httpx

from numasec.core.http import create_client
from numasec.scanners._envelope import wrap_result

logger = logging.getLogger("numasec.scanners.race_tester")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RaceVulnerability:
    """A single race condition finding."""

    race_type: str  # "limit_bypass" | "state_change" | "duplicate_action" | "toctou"
    endpoint: str
    evidence: str
    severity: str = "high"
    confidence: float = 0.6


@dataclass
class RaceResult:
    """Complete race condition test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[RaceVulnerability] = field(default_factory=list)
    requests_sent: int = 0
    concurrent_batch_size: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "race_type": v.race_type,
                    "endpoint": v.endpoint,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "requests_sent": self.requests_sent,
            "concurrent_batch_size": self.concurrent_batch_size,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"Race condition detected ({', '.join(v.race_type for v in self.vulnerabilities)})"
                if self.vulnerabilities
                else "No race condition detected"
            ),
            "next_steps": (
                [
                    "Confirm with manual replay and observe side effects (balance, inventory, etc.)",
                    "Test with increasing concurrency to widen the race window",
                    "Check for missing database-level locks or atomic operations",
                ]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# Race condition detection engine
# ---------------------------------------------------------------------------

# Minimum number of successful responses required before we flag a potential
# limit-bypass.  Keeps false-positives low on endpoints that legitimately
# accept many concurrent requests.
_MIN_SUCCESS_FOR_LIMIT_BYPASS = 10

# When fewer than this fraction of unique response bodies appear among all
# responses we flag a state-change race.  E.g. 0.5 means "less than half of
# the responses are unique".
_STATE_CHANGE_UNIQUENESS_THRESHOLD = 0.5


class RaceTester:
    """Concurrent-request race condition detector.

    Parameters
    ----------
    concurrency:
        Number of identical requests to send in one burst.
    timeout:
        Per-request HTTP timeout in seconds.
    extra_headers:
        Additional HTTP headers to include in every request.
    """

    def __init__(
        self,
        concurrency: int = 20,
        timeout: float = 15.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.extra_headers = extra_headers or {}

    async def test(
        self,
        url: str,
        method: str = "POST",
        body: dict[str, Any] | None = None,
        repeat: int = 20,
    ) -> RaceResult:
        """Run race condition tests against *url*.

        Sends *repeat* identical requests concurrently and analyses the
        responses for race-condition indicators. Compares against a
        sequential baseline to reduce false positives from dynamic content.

        Args:
            url: Target endpoint URL.
            method: HTTP method (``GET`` or ``POST``).
            body: Optional JSON body for POST requests.
            repeat: Number of concurrent requests per burst.

        Returns:
            ``RaceResult`` containing any discovered vulnerabilities.
        """
        start = time.monotonic()
        result = RaceResult(target=url, concurrent_batch_size=repeat)

        async with create_client(
            timeout=self.timeout,
            headers=self.extra_headers if self.extra_headers else None,
        ) as client:
            # Baseline: 2 sequential requests to measure natural response variation
            baseline_hashes: set[str] = set()
            for _ in range(2):
                try:
                    if method.upper() == "POST":
                        resp = await client.post(url, json=body or {})
                    else:
                        resp = await client.get(url)
                    baseline_hashes.add(hashlib.md5(resp.content).hexdigest())  # noqa: S324
                except httpx.HTTPError:
                    pass

            responses = await self._flood_endpoint(client, url, method, body, repeat)

        result.requests_sent = len(responses)
        vulns = self._analyze_responses(responses, url, baseline_hashes)
        if vulns:
            result.vulnerable = True
            result.vulnerabilities.extend(vulns)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Race test complete: %s - %d vulns, %d/%d responses, %.0fms",
            url,
            len(result.vulnerabilities),
            len(responses),
            repeat,
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _flood_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: dict[str, Any] | None,
        count: int,
    ) -> list[httpx.Response]:
        """Send *count* identical requests as fast as possible."""

        async def _single_request() -> httpx.Response:
            if method.upper() == "POST":
                return await client.post(url, json=body or {})
            return await client.get(url)

        tasks = [_single_request() for _ in range(count)]
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in raw if isinstance(r, httpx.Response)]

    def _analyze_responses(
        self,
        responses: list[httpx.Response],
        url: str,
        baseline_hashes: set[str] | None = None,
    ) -> list[RaceVulnerability]:
        """Inspect concurrent responses for race-condition indicators.

        Uses baseline_hashes (from sequential requests) to filter out
        natural response variation and reduce false positives.
        """
        if not responses:
            return []

        vulns: list[RaceVulnerability] = []

        status_counts = Counter(r.status_code for r in responses)
        success_count = sum(1 for r in responses if 200 <= r.status_code < 300)
        total = len(responses)

        # --- Technique 1: Limit bypass -----------------------------------
        if success_count == total and total >= _MIN_SUCCESS_FOR_LIMIT_BYPASS:
            vulns.append(
                RaceVulnerability(
                    race_type="limit_bypass",
                    endpoint=url,
                    confidence=0.5,
                    evidence=(
                        f"All {success_count}/{total} concurrent requests succeeded (HTTP 2xx). "
                        "If this endpoint should enforce limits, a race condition may allow "
                        "bypassing them."
                    ),
                )
            )

        # --- Technique 2: Duplicate action detection ---------------------
        rejection_codes = {409, 429, 403, 423}
        rejected = sum(status_counts.get(code, 0) for code in rejection_codes)
        if success_count > 1 and rejected > 0:
            vulns.append(
                RaceVulnerability(
                    race_type="duplicate_action",
                    endpoint=url,
                    confidence=0.8,
                    severity="high",
                    evidence=(
                        f"{success_count} requests succeeded and {rejected} were rejected "
                        f"(status {dict((c, status_counts[c]) for c in rejection_codes if c in status_counts)}). "
                        "Multiple successes alongside rejections indicate a race window."
                    ),
                )
            )

        # --- Technique 3: Response inconsistency (state_change) ----------
        body_hashes = [hashlib.md5(r.content).hexdigest() for r in responses]  # noqa: S324
        unique_bodies = set(body_hashes)

        # Subtract baseline variation to avoid FP from dynamic content
        if baseline_hashes:
            novel_bodies = unique_bodies - baseline_hashes
        else:
            novel_bodies = unique_bodies

        novel_count = len(novel_bodies)
        if novel_count > 1 and novel_count < total * _STATE_CHANGE_UNIQUENESS_THRESHOLD:
            vulns.append(
                RaceVulnerability(
                    race_type="state_change",
                    endpoint=url,
                    confidence=0.7,
                    evidence=(
                        f"{len(unique_bodies)} unique response bodies among {total} concurrent "
                        f"requests ({novel_count} novel vs baseline). "
                        "Inconsistent state suggests a TOCTOU race condition."
                    ),
                )
            )

        return vulns


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_race_test(
    url: str,
    method: str = "POST",
    body: str = "",
    concurrency: int = 20,
    headers: str | None = None,
) -> str:
    """Test URL for race condition vulnerabilities by flooding concurrent requests.

    Sends *concurrency* identical requests simultaneously and analyses responses
    for limit-bypass, state-change, and duplicate-action indicators.

    Args:
        url: Target endpoint URL.
        method: HTTP method (``GET`` or ``POST``).
        body: Optional JSON-encoded request body.
        concurrency: Number of simultaneous requests (default 20).
        headers: Optional JSON-encoded dict of extra HTTP headers.

    Returns:
        JSON string with ``RaceResult`` data wrapped in a standard envelope.
    """
    import contextlib

    parsed_body: dict[str, Any] | None = None
    if body:
        with contextlib.suppress(json.JSONDecodeError):
            parsed_body = json.loads(body)

    parsed_headers: dict[str, str] | None = None
    if headers:
        with contextlib.suppress(json.JSONDecodeError):
            parsed_headers = headers if isinstance(headers, dict) else json.loads(headers)

    start = time.monotonic()
    tester = RaceTester(
        concurrency=concurrency,
        extra_headers=parsed_headers,
    )
    result = await tester.test(url, method=method, body=parsed_body, repeat=concurrency)
    envelope = wrap_result("race_test", url, result.to_dict(), start_time=start)
    return json.dumps(envelope, indent=2)
