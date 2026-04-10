"""Mass Assignment vulnerability tester (OWASP API6:2023).

Tests whether an API endpoint accepts undeclared/privileged fields in the
request body, allowing attackers to modify properties that should be read-only
(e.g., role, admin, balance, credit, status, verified).

Two detection strategies:

1. **Response diff** — inject extra fields and compare the response body.
   If the injected field value appears in the response, the server accepted it.

2. **Persistence check** — for PUT/PATCH endpoints, send extra fields then
   fetch the resource (GET) and verify whether the injected field was stored.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.mass_assignment_tester")

# ---------------------------------------------------------------------------
# Extra fields to inject — grouped by category for clarity
# ---------------------------------------------------------------------------

_PRIVILEGE_FIELDS: list[tuple[str, Any]] = [
    # Role / privilege escalation
    ("role", "admin"),
    ("role", "superuser"),
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("is_staff", True),
    ("isStaff", True),
    ("permissions", ["read", "write", "admin"]),
    ("privilege", "admin"),
    ("access_level", "admin"),
    ("user_type", "admin"),
    # Financial manipulation
    ("balance", 99999),
    ("credit", 99999),
    ("available_credit", 99999),
    ("wallet_balance", 99999),
    ("points", 99999),
    ("discount", 100),
    ("price", 0),
    ("amount", 0),
    ("total", 0),
    # Status / verification bypass
    ("status", "active"),
    ("verified", True),
    ("email_verified", True),
    ("active", True),
    ("enabled", True),
    ("locked", False),
    ("banned", False),
    # Internal / sensitive fields
    ("internal", True),
    ("hidden", False),
    ("soft_deleted", False),
    ("deleted", False),
    ("created_at", "1970-01-01"),
    ("updated_at", "1970-01-01"),
    ("owner_id", 1),
    ("user_id", 1),
]

_RESPONSE_ACCEPTED_INDICATORS = [
    "admin",
    "superuser",
    "99999",
    "true",
    "verified",
    "active",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class MassAssignmentVulnerability:
    """A single mass assignment finding."""

    field_name: str
    injected_value: Any
    evidence: str
    severity: str = "high"
    confidence: float = 0.7


@dataclass
class MassAssignmentResult:
    """Complete mass assignment test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[MassAssignmentVulnerability] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "field": v.field_name,
                    "injected_value": v.injected_value,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"{len(self.vulnerabilities)} mass assignment "
                f"{'vulnerability' if len(self.vulnerabilities) == 1 else 'vulnerabilities'} found"
                if self.vulnerabilities
                else "No mass assignment vulnerabilities found"
            ),
            "next_steps": (
                [
                    "Verify privilege escalation by re-fetching the resource",
                    "Test other endpoints with the same technique",
                ]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# Mass assignment detection engine
# ---------------------------------------------------------------------------


class MassAssignmentTester:
    """Detects mass assignment vulnerabilities in REST API endpoints.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    extra_headers:
        Extra headers to include in requests (e.g. Authorization).
    get_url:
        Optional URL to fetch the resource after a PUT/PATCH to check persistence.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
        get_url: str | None = None,
    ) -> None:
        self.timeout = timeout
        self._extra_headers: dict[str, str] = extra_headers or {}
        self._get_url = get_url

    async def test(
        self,
        url: str,
        method: str = "POST",
        body: dict[str, Any] | None = None,
    ) -> MassAssignmentResult:
        """Run mass assignment tests.

        Args:
            url: Target endpoint.
            method: HTTP method (POST, PUT, PATCH).
            body: Known valid request body. Extra fields will be injected alongside.

        Returns:
            ``MassAssignmentResult`` with discovered vulnerabilities.
        """
        start = time.monotonic()
        result = MassAssignmentResult(target=url)
        base_body = body or {}

        async with create_client(timeout=self.timeout, headers=self._extra_headers) as client:
            # Obtain baseline response with the original body
            baseline_resp_text = ""
            baseline_status = 0
            try:
                baseline_resp = await client.request(method.upper(), url, json=base_body)
                baseline_resp_text = baseline_resp.text
                baseline_status = baseline_resp.status_code
            except httpx.HTTPError as exc:
                logger.debug("Mass assignment baseline error: %s", exc)

            for field_name, injected_value in _PRIVILEGE_FIELDS:
                # Skip fields already in the body (don't overwrite known fields)
                if field_name in base_body:
                    continue

                test_body = {**base_body, field_name: injected_value}
                try:
                    resp = await client.request(method.upper(), url, json=test_body)
                except httpx.HTTPError as exc:
                    logger.debug("Mass assignment probe error (field=%s): %s", field_name, exc)
                    continue

                vuln = self._evaluate(
                    resp,
                    baseline_resp_text,
                    baseline_status,
                    field_name,
                    injected_value,
                )
                if vuln:
                    result.vulnerabilities.append(vuln)
                    result.vulnerable = True

                    # Persistence check: if PUT/PATCH, fetch the resource and verify
                    if method.upper() in ("PUT", "PATCH") and self._get_url:
                        await self._check_persistence(client, field_name, injected_value, result)
                    continue

            # Batch injection: send all privilege fields at once to catch frameworks
            # that silently accept and store fields without reflecting them immediately
            all_extra = {f: v for f, v in _PRIVILEGE_FIELDS if f not in base_body}
            if all_extra and not result.vulnerable:
                batch_body = {**base_body, **all_extra}
                try:
                    batch_resp = await client.request(method.upper(), url, json=batch_body)
                    # A 2xx response to a body with many privilege fields is suspicious
                    if batch_resp.status_code < 300 and baseline_status < 300:
                        result.vulnerabilities.append(
                            MassAssignmentVulnerability(
                                field_name="multiple (batch)",
                                injected_value=list(all_extra.keys()),
                                evidence=(
                                    f"Server accepted a request body containing "
                                    f"{len(all_extra)} extra fields including 'role', 'admin', 'balance' "
                                    f"with HTTP {batch_resp.status_code}. "
                                    f"Verify if fields were persisted via GET."
                                ),
                                confidence=0.4,
                                severity="medium",
                            )
                        )
                        result.vulnerable = True
                except httpx.HTTPError:
                    pass

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Mass assignment test complete: %s — %d vulns, %.0fms",
            url,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    def _evaluate(
        self,
        resp: httpx.Response,
        baseline_text: str,
        baseline_status: int,
        field_name: str,
        injected_value: Any,
    ) -> MassAssignmentVulnerability | None:
        """Evaluate a response for signs of mass assignment acceptance."""
        resp_text = resp.text
        resp_lower = resp_text.lower()
        injected_str = str(injected_value).lower()

        # Tier 1: Injected value reflected back in response
        if injected_str in resp_lower and injected_str not in baseline_text.lower():
            return MassAssignmentVulnerability(
                field_name=field_name,
                injected_value=injected_value,
                evidence=(
                    f"Injected value '{injected_value}' for field '{field_name}' "
                    f"was reflected in the response body. Server accepted the extra field."
                ),
                confidence=0.8,
            )

        # Tier 2: Status code changed to success (403→200 or similar)
        if baseline_status >= 400 and resp.status_code < 300:
            return MassAssignmentVulnerability(
                field_name=field_name,
                injected_value=injected_value,
                evidence=(
                    f"Response status changed from {baseline_status} to {resp.status_code} "
                    f"after injecting field '{field_name}={injected_value}'. "
                    f"Possible privilege bypass via mass assignment."
                ),
                confidence=0.7,
            )

        # Tier 3: Significant response diff with success indicator
        body_diff = abs(len(resp_text) - len(baseline_text))
        if body_diff > 100:
            for indicator in _RESPONSE_ACCEPTED_INDICATORS:
                if indicator in resp_lower and indicator not in baseline_text.lower():
                    return MassAssignmentVulnerability(
                        field_name=field_name,
                        injected_value=injected_value,
                        evidence=(
                            f"Response changed significantly (+{body_diff} chars) and "
                            f"contains new indicator '{indicator}' after injecting "
                            f"'{field_name}={injected_value}'. Possible mass assignment."
                        ),
                        confidence=0.5,
                        severity="medium",
                    )

        return None

    async def _check_persistence(
        self,
        client: httpx.AsyncClient,
        field_name: str,
        injected_value: Any,
        result: MassAssignmentResult,
    ) -> None:
        """Fetch the resource via GET and check if the injected field was persisted."""
        if not self._get_url:
            return
        try:
            get_resp = await client.get(self._get_url)
            resp_lower = get_resp.text.lower()
            injected_str = str(injected_value).lower()
            if injected_str in resp_lower:
                result.vulnerabilities.append(
                    MassAssignmentVulnerability(
                        field_name=field_name,
                        injected_value=injected_value,
                        evidence=(
                            f"Field '{field_name}={injected_value}' was PERSISTED: "
                            f"GET {self._get_url} returned the injected value. "
                            f"Server stored the mass-assigned field server-side."
                        ),
                        confidence=0.95,
                        severity="critical",
                    )
                )
                result.vulnerable = True
        except httpx.HTTPError as exc:
            logger.debug("Mass assignment persistence check error: %s", exc)


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_mass_assignment_test(
    url: str,
    method: str = "POST",
    body: str = "",
    headers: str = "",
    get_url: str = "",
) -> str:
    """Test an API endpoint for mass assignment vulnerabilities (OWASP API6:2023).

    Injects extra privileged fields (role, admin, balance, verified, etc.) into
    the request body and checks if the server accepts or reflects them.

    Args:
        url: Target endpoint to test (POST, PUT, or PATCH).
        method: HTTP method — POST, PUT, or PATCH. Default: POST.
        body: Known valid request body as JSON string (e.g. ``'{"name": "test"}'``).
            Extra fields will be appended to this body.
        headers: JSON string of HTTP headers for authenticated testing.
        get_url: Optional URL to fetch the resource after PUT/PATCH to check
            if injected fields were persisted server-side.

    Returns:
        JSON string with ``MassAssignmentResult`` data.
    """
    extra_headers: dict[str, str] = (
        headers if isinstance(headers, dict) else (json.loads(headers) if headers else {})
    )
    body_dict: dict[str, Any] | None = json.loads(body) if body else None
    tester = MassAssignmentTester(
        extra_headers=extra_headers,
        get_url=get_url or None,
    )
    result = await tester.test(url, method=method, body=body_dict)
    return json.dumps(result.to_dict(), indent=2)
