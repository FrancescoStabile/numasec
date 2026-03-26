"""Benchmark tests against OWASP Juice Shop.

Requires:
- Juice Shop running at http://localhost:3000
- ANTHROPIC_API_KEY set
- SECMCP_ALLOW_INTERNAL=1

Run with: pytest tests/benchmarks/test_juice_shop.py -v -m benchmark
"""

from __future__ import annotations

import json
import os
import time

import pytest

from security_mcp.models.finding import Finding
from tests.benchmarks.ground_truth import JUICE_SHOP_GROUND_TRUTH
from tests.benchmarks.scorer import calculate_scores


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

_JUICE_SHOP_URL = os.getenv("JUICE_SHOP_URL", "http://localhost:3000")
_HAS_API_KEY = bool(os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY"))
_ALLOW_INTERNAL = os.getenv("SECMCP_ALLOW_INTERNAL") in ("1", "true", "True")


def _juice_shop_reachable() -> bool:
    """Check if Juice Shop is running."""
    try:
        import httpx
        resp = httpx.get(_JUICE_SHOP_URL, timeout=5.0, follow_redirects=True)
        return resp.status_code == 200
    except Exception:
        return False


_SKIP_REASON = ""
if not _HAS_API_KEY:
    _SKIP_REASON = "No API key (set ANTHROPIC_API_KEY or OPENAI_API_KEY)"
elif not _ALLOW_INTERNAL:
    _SKIP_REASON = "SECMCP_ALLOW_INTERNAL not set (required for localhost)"

# Lazy-check Juice Shop reachability only if other conditions pass
_skip_benchmark = bool(_SKIP_REASON)
if not _skip_benchmark and not _juice_shop_reachable():
    _SKIP_REASON = f"Juice Shop not reachable at {_JUICE_SHOP_URL}"
    _skip_benchmark = True

skip_if_no_env = pytest.mark.skipif(_skip_benchmark, reason=_SKIP_REASON or "missing environment")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def juice_shop_url():
    return _JUICE_SHOP_URL


@pytest.fixture
def ground_truth():
    return JUICE_SHOP_GROUND_TRUTH


# ---------------------------------------------------------------------------
# MCP mode benchmark
# ---------------------------------------------------------------------------

@pytest.mark.benchmark
@pytest.mark.slow
@skip_if_no_env
class TestJuiceShopMCP:
    """MCP tool-level benchmark against Juice Shop."""

    async def test_tech_fingerprint(self, juice_shop_url):
        """tech_fingerprint should detect Express/Node."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        result = await registry.call("tech_fingerprint", url=juice_shop_url)
        result_data = json.loads(result) if isinstance(result, str) else result

        assert isinstance(result_data, dict)
        techs = result_data.get("technologies", [])
        print(f"\n  Technologies: {techs}")

    async def test_port_scan(self, juice_shop_url):
        """port_scan should find port 3000 open."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        host = juice_shop_url.replace("http://", "").split(":")[0]
        result = await registry.call("port_scan", target=host, ports="3000")
        result_data = json.loads(result) if isinstance(result, str) else result

        ports = result_data.get("open_ports", result_data.get("ports", []))
        assert any(p.get("port", p) == 3000 or p == 3000 for p in ports), (
            f"Port 3000 not found in: {ports}"
        )

    async def test_dir_fuzz(self, juice_shop_url):
        """dir_fuzz should find common Juice Shop endpoints."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        result = await registry.call("dir_fuzz", url=juice_shop_url, wordlist="common")
        result_data = json.loads(result) if isinstance(result, str) else result

        found = result_data.get("found", result_data.get("results", []))
        print(f"\n  Dir fuzz: {len(found)} paths found")
        assert len(found) >= 1

    async def test_sqli_on_login(self, juice_shop_url):
        """sqli_test should detect SQLi on the Juice Shop login."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        result = await registry.call(
            "sqli_test",
            url=f"{juice_shop_url}/rest/user/login",
            params=["email", "password"],
            method="POST",
        )
        result_data = json.loads(result) if isinstance(result, str) else result

        is_vulnerable = result_data.get("vulnerable", result_data.get("is_vulnerable", False))
        print(f"\n  SQLi on login: vulnerable={is_vulnerable}")
        print(f"  Details: {json.dumps(result_data, indent=2)[:500]}")

    async def test_xss_test(self, juice_shop_url):
        """xss_test should check for reflected XSS."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        result = await registry.call(
            "xss_test",
            url=f"{juice_shop_url}/#/search",
            params=["q"],
        )
        result_data = json.loads(result) if isinstance(result, str) else result
        print(f"\n  XSS test result: {json.dumps(result_data, indent=2)[:500]}")

    async def test_vuln_scan(self, juice_shop_url):
        """vuln_scan should detect security header issues."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        result = await registry.call("vuln_scan", url=juice_shop_url)
        result_data = json.loads(result) if isinstance(result, str) else result

        findings = result_data.get("findings", result_data.get("vulnerabilities", []))
        print(f"\n  Vuln scan: {len(findings)} findings")
        assert len(findings) >= 1, "Expected at least 1 finding (missing headers)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _classify_finding_type(finding: Finding) -> str:
    """Classify a Finding into a ground-truth type string."""
    title = finding.title.lower()
    cwe = finding.cwe_id.lower()

    if "sql" in title or "sqli" in title or "cwe-89" in cwe:
        return "sqli"
    if "xss" in title or "cross-site scripting" in title or "cwe-79" in cwe:
        return "xss"
    if "idor" in title or "insecure direct" in title:
        return "idor"
    if "auth" in title or "login" in title or "bypass" in title:
        return "auth_bypass"
    if "sensitive" in title or "exposure" in title or "disclosure" in title:
        return "sensitive_data_exposure"
    if "header" in title or "security header" in title:
        return "missing_headers"
    if "csrf" in title:
        return "csrf"
    if "injection" in title or "command" in title:
        return "command_injection"
    return "other"
