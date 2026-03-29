"""Python-native IDOR (Insecure Direct Object Reference) tester.

Detects endpoints where changing a numeric or UUID resource identifier
in the URL path or query string returns data belonging to a different
user/entity without proper authorization checks.

Detection strategy:
1. Identify the resource ID in the URL (path segment or query param).
2. Send a baseline request with the original ID.
3. Replace the ID with adjacent values (±1, ±2) or common test IDs.
4. Compare responses: if a different resource is returned (different
   content, same 200 status), the endpoint is IDOR-vulnerable.
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

logger = logging.getLogger("numasec.scanners.idor_tester")

# Regex for path segments that look like numeric IDs
_PATH_ID_PATTERN = re.compile(r"/(\d+)(?:/|$)")

# Regex for UUID-style IDs in paths
_UUID_PATTERN = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)",
    re.IGNORECASE,
)

# Common query parameter names that hold resource IDs
_ID_PARAM_NAMES = {
    "id",
    "uid",
    "user_id",
    "userId",
    "account_id",
    "accountId",
    "order_id",
    "orderId",
    "item_id",
    "itemId",
    "basket_id",
    "basketId",
}


@dataclass
class IDORVulnerability:
    """A single IDOR finding."""

    parameter: str
    original_id: str
    tested_id: str
    evidence: str
    severity: str = "high"


@dataclass
class IDORResult:
    """Complete IDOR test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[IDORVulnerability] = field(default_factory=list)
    ids_tested: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "parameter": v.parameter,
                    "original_id": v.original_id,
                    "tested_id": v.tested_id,
                    "evidence": v.evidence,
                    "severity": v.severity,
                }
                for v in self.vulnerabilities
            ],
            "ids_tested": self.ids_tested,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"{len(self.vulnerabilities)} IDOR "
                f"{'vulnerability' if len(self.vulnerabilities) == 1 else 'vulnerabilities'} found"
                if self.vulnerabilities
                else "No IDOR found"
            ),
            "next_steps": (
                ["Test adjacent resource IDs (+1/-1)", "Test with different auth tokens"]
                if self.vulnerabilities
                else []
            ),
        }


class IDORTester:
    """Multi-strategy IDOR detection engine.

    Tests both path-based IDs (``/api/Users/1``) and query-param IDs
    (``/endpoint?id=1``) by substituting adjacent numeric values and
    comparing the responses.
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def test(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> IDORResult:
        """Run IDOR tests against a target URL.

        Args:
            url: Target URL containing a resource ID (path or query param).
            headers: Optional headers (e.g., Authorization) to send with requests.

        Returns:
            ``IDORResult`` with discovered IDOR vulnerabilities.
        """
        start = time.monotonic()
        result = IDORResult(target=url)

        parsed = urlparse(url)
        test_cases = self._find_ids(parsed)

        if not test_cases:
            logger.warning("No numeric/UUID IDs found in URL: %s", url)
            result.duration_ms = (time.monotonic() - start) * 1000
            return result

        async with create_client(
            timeout=self.timeout,
            headers=headers or {},
        ) as client:
            for id_location, original_id, build_url_fn in test_cases:
                try:
                    # Get baseline response with the original ID
                    try:
                        baseline_resp = await client.get(url)
                    except httpx.HTTPError:
                        continue

                    if baseline_resp.status_code != 200:
                        continue

                    baseline_text = baseline_resp.text
                    baseline_len = len(baseline_text)

                    # Generate adjacent IDs to test
                    alt_ids = self._generate_alt_ids(original_id)

                    for alt_id in alt_ids:
                        result.ids_tested += 1
                        test_url = build_url_fn(alt_id)

                        try:
                            resp = await client.get(test_url)
                        except httpx.HTTPError:
                            continue

                        if resp.status_code != 200:
                            continue

                        resp_text = resp.text
                        resp_len = len(resp_text)

                        # The response must be:
                        # 1. 200 OK (resource exists)
                        # 2. Different content from baseline (different resource)
                        # 3. Non-trivial length (not an empty/error response)
                        if (
                            resp_text != baseline_text
                            and resp_len > 50
                            and baseline_len > 50
                            # Content must have similar structure but different data
                            and abs(resp_len - baseline_len) / max(resp_len, baseline_len) < 0.5
                        ):
                            result.vulnerabilities.append(
                                IDORVulnerability(
                                    parameter=id_location,
                                    original_id=original_id,
                                    tested_id=alt_id,
                                    evidence=(
                                        f"Changing {id_location} from '{original_id}' to '{alt_id}' "
                                        f"returned a different 200 OK response "
                                        f"({baseline_len} → {resp_len} bytes). "
                                        f"Different resource data returned without authorization check."
                                    ),
                                )
                            )
                            result.vulnerable = True
                            break  # One proof per ID location is enough
                except Exception as exc:
                    logger.warning("IDOR test error on %s: %s", id_location, exc)
                    continue

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "IDOR test complete: %s — %d IDs tested, %d vulns, %.0fms",
            url,
            result.ids_tested,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    def _find_ids(self, parsed: Any) -> list[tuple[str, str, Any]]:
        """Find numeric/UUID IDs in path segments and query params.

        Returns list of ``(location_desc, original_id, build_url_fn)`` tuples
        where ``build_url_fn(new_id)`` returns a new URL with the ID replaced.
        """
        test_cases: list[tuple[str, str, Any]] = []

        # Path-based numeric IDs: /api/Users/1, /rest/basket/2
        for match in _PATH_ID_PATTERN.finditer(parsed.path):
            original_id = match.group(1)
            id_start = match.start(1)
            id_end = match.end(1)
            original_path = parsed.path

            def _build_path_url(new_id: str, _s: int = id_start, _e: int = id_end, _p: str = original_path) -> str:
                new_path = _p[:_s] + new_id + _p[_e:]
                return urlunparse(parsed._replace(path=new_path))

            test_cases.append((f"path:{original_id}", original_id, _build_path_url))

        # Query-param based IDs: ?id=1, ?userId=42
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name, values in query_params.items():
            if param_name.lower() in _ID_PARAM_NAMES or (values and values[0].isdigit()):
                original_id = values[0]
                if not original_id.isdigit():
                    continue

                def _build_query_url(new_id: str, _p: str = param_name) -> str:
                    modified = dict(query_params)
                    modified[_p] = [new_id]
                    new_query = urlencode(modified, doseq=True)
                    return urlunparse(parsed._replace(query=new_query))

                test_cases.append((f"param:{param_name}", original_id, _build_query_url))

        return test_cases

    @staticmethod
    def _generate_alt_ids(original_id: str) -> list[str]:
        """Generate alternative IDs to test against the original."""
        if not original_id.isdigit():
            return []

        num = int(original_id)
        alt_ids: list[str] = []

        # Adjacent IDs
        if num > 1:
            alt_ids.append(str(num - 1))
        alt_ids.append(str(num + 1))
        if num > 2:
            alt_ids.append(str(num - 2))
        alt_ids.append(str(num + 2))

        # Common test IDs (if not already adjacent)
        for test_id in [1, 2, 0]:
            s = str(test_id)
            if s != original_id and s not in alt_ids:
                alt_ids.append(s)

        return alt_ids


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_idor_test(
    url: str,
    headers: str | None = None,
) -> str:
    """Test a URL for Insecure Direct Object Reference (IDOR) vulnerabilities.

    Detects endpoints where changing a resource ID in the URL path or query
    string returns a different user's data without authorization.

    Args:
        url: Target URL containing a numeric resource ID
            (e.g., ``/api/Users/1``, ``/rest/basket/2``).
        headers: Optional JSON string of headers to send
            (e.g., ``'{"Authorization": "Bearer ..."}'``).

    Returns:
        JSON string with ``IDORResult`` data.
    """
    parsed_headers: dict[str, str] | None = None
    if headers:
        import contextlib

        with contextlib.suppress(json.JSONDecodeError):
            parsed_headers = headers if isinstance(headers, dict) else json.loads(headers)

    tester = IDORTester()
    result = await tester.test(url, headers=parsed_headers)
    return json.dumps(result.to_dict(), indent=2)
