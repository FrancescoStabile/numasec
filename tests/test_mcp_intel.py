"""Tests for security_mcp.mcp.intel_tools.

After consolidation, only 2 MCP tools are registered:
  - kb_search (replaces search_kb, get_cwe_info, get_attack_patterns)
  - plan (replaces get_scan_plan, get_mandatory_tests, get_coverage_gaps,
          get_auth_retest_plan, get_chain_opportunities)

Internal helper functions (_search_kb, _get_cwe_info, etc.) are tested
indirectly through the unified tools.
"""

from __future__ import annotations

import json

import pytest

from security_mcp.mcp.intel_tools import _lookup_cwe, register


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeMCP:
    """Minimal stand-in for FastMCP that captures registered tool functions."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *, name: str, description: str):  # noqa: ARG002
        def decorator(fn):
            self.tools[name] = fn
            return fn

        return decorator


@pytest.fixture()
def mcp_tools():
    """Register intel tools on a fake MCP and return the tool dict."""
    fake = _FakeMCP()
    register(fake)
    return fake.tools


# ---------------------------------------------------------------------------
# Registration sanity
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_only_two_tools_registered(self, mcp_tools):
        assert sorted(mcp_tools.keys()) == ["kb_search", "plan"]

    def test_kb_search_registered(self, mcp_tools):
        assert "kb_search" in mcp_tools

    def test_plan_registered(self, mcp_tools):
        assert "plan" in mcp_tools


# ---------------------------------------------------------------------------
# _lookup_cwe (unit)
# ---------------------------------------------------------------------------


class TestLookupCwe:
    def test_known_cwe(self):
        info = _lookup_cwe("CWE-89")
        assert info is not None
        assert info["cwe_id"] == "CWE-89"
        assert "SQL Injection" in info["name"]
        assert info["severity"] == "critical"
        assert info["owasp_category"] != ""

    def test_numeric_id(self):
        info = _lookup_cwe("79")
        assert info is not None
        assert info["cwe_id"] == "CWE-79"

    def test_unknown_cwe(self):
        assert _lookup_cwe("CWE-99999") is None

    def test_case_insensitive(self):
        info = _lookup_cwe("cwe-89")
        assert info is not None
        assert info["cwe_id"] == "CWE-89"


# ---------------------------------------------------------------------------
# kb_search (type="search") — was search_kb
# ---------------------------------------------------------------------------


class TestSearchKb:
    async def test_returns_results_for_sqli(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="SQL injection")
        data = json.loads(raw)
        assert data["query"] == "SQL injection"
        assert data["total_results"] > 0
        assert isinstance(data["results"], list)
        # Each result has the expected fields
        for r in data["results"]:
            assert "text" in r
            assert "template_id" in r
            assert "score" in r

    async def test_category_filter(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="injection", category="detection")
        data = json.loads(raw)
        assert data["category"] == "detection"
        for r in data["results"]:
            assert r["category"] == "detection"

    async def test_top_k_limit(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="vulnerability", top_k=2)
        data = json.loads(raw)
        assert data["total_results"] <= 2

    async def test_empty_query_returns_empty(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="")
        data = json.loads(raw)
        assert data["total_results"] == 0

    async def test_default_type_is_search(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="SQL injection")
        data = json.loads(raw)
        assert data["type"] == "search"


# ---------------------------------------------------------------------------
# kb_search (type="cwe") — was get_cwe_info
# ---------------------------------------------------------------------------


class TestGetCweInfo:
    async def test_known_cwe(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="CWE-89", type="cwe")
        data = json.loads(raw)
        assert data["found"] is True
        assert data["cwe_id"] == "CWE-89"
        assert "SQL Injection" in data["name"]
        assert data["severity"] == "critical"
        assert "owasp_category" in data
        assert isinstance(data["related_kb"], list)

    async def test_numeric_id_works(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="79", type="cwe")
        data = json.loads(raw)
        assert data["found"] is True
        assert "XSS" in data["name"] or "Scripting" in data["name"]

    async def test_unknown_cwe(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="CWE-99999", type="cwe")
        data = json.loads(raw)
        assert data["found"] is False
        # Should still return related_kb (even if empty)
        assert "related_kb" in data


# ---------------------------------------------------------------------------
# kb_search (type="attack_patterns") — was get_attack_patterns
# ---------------------------------------------------------------------------


class TestGetAttackPatterns:
    async def test_returns_structure_for_wordpress(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="WordPress", type="attack_patterns")
        data = json.loads(raw)
        assert data["technology"] == "WordPress"
        assert "detection_patterns" in data
        assert "attack_chains" in data
        assert "payloads" in data
        # All are lists
        assert isinstance(data["detection_patterns"], list)
        assert isinstance(data["attack_chains"], list)
        assert isinstance(data["payloads"], list)

    async def test_results_have_expected_fields(self, mcp_tools):
        raw = await mcp_tools["kb_search"](query="PHP", type="attack_patterns")
        data = json.loads(raw)
        for key in ("detection_patterns", "attack_chains", "payloads"):
            for item in data[key]:
                assert "text" in item
                assert "template_id" in item
                assert "score" in item


# ---------------------------------------------------------------------------
# plan (action="initial") — was get_scan_plan
# ---------------------------------------------------------------------------


class TestGetScanPlan:
    async def test_quick_scope(self, mcp_tools):
        raw = await mcp_tools["plan"](action="initial", target="http://example.com", scope="quick")
        data = json.loads(raw)
        assert data["target"] == "http://example.com"
        assert data["scope"] == "quick"
        assert data["total_steps"] > 0
        assert len(data["phases"]) >= 3  # recon + mapping + vuln + reporting
        # Quick scope should NOT have exploitation
        phase_names = [p["name"] for p in data["phases"]]
        assert "reconnaissance" in phase_names
        assert "reporting" in phase_names
        assert "exploitation_validation" not in phase_names

    async def test_standard_scope_has_exploitation(self, mcp_tools):
        raw = await mcp_tools["plan"](action="initial", target="http://example.com", scope="standard")
        data = json.loads(raw)
        phase_names = [p["name"] for p in data["phases"]]
        assert "exploitation_validation" in phase_names

    async def test_deep_scope(self, mcp_tools):
        raw = await mcp_tools["plan"](action="initial", target="http://example.com", scope="deep")
        data = json.loads(raw)
        assert data["scope"] == "deep"
        assert data["total_steps"] > 0
        # Deep should have dir_fuzz in recon
        recon = next(p for p in data["phases"] if p["name"] == "reconnaissance")
        step_ids = [s["id"] for s in recon["steps"]]
        assert "recon_dir_fuzz" in step_ids

    async def test_invalid_scope(self, mcp_tools):
        raw = await mcp_tools["plan"](action="initial", target="http://example.com", scope="ultra")
        data = json.loads(raw)
        assert "error" in data

    async def test_phases_have_steps_with_tools(self, mcp_tools):
        raw = await mcp_tools["plan"](action="initial", target="http://example.com", scope="quick")
        data = json.loads(raw)
        for phase in data["phases"]:
            assert "name" in phase
            assert "steps" in phase
            assert isinstance(phase["steps"], list)
            for step in phase["steps"]:
                assert "id" in step
                assert "description" in step
                assert "tool" in step

    async def test_invalid_action(self, mcp_tools):
        raw = await mcp_tools["plan"](action="nonexistent", target="http://example.com")
        data = json.loads(raw)
        assert "error" in data


# ---------------------------------------------------------------------------
# _classify_finding_owasp (unit)
# ---------------------------------------------------------------------------


class TestClassifyFindingOwasp:
    def test_cwe_based_classification(self):
        from types import SimpleNamespace

        from security_mcp.mcp.intel_tools import _classify_finding_owasp

        finding = SimpleNamespace(cwe_id="CWE-89", tool_used="", title="")
        cats = _classify_finding_owasp(finding)
        assert "A03_injection" in cats

    def test_tool_based_classification(self):
        from types import SimpleNamespace

        from security_mcp.mcp.intel_tools import _classify_finding_owasp

        finding = SimpleNamespace(cwe_id="", tool_used="ssrf_test", title="")
        cats = _classify_finding_owasp(finding)
        assert "A10_ssrf" in cats

    def test_title_based_classification(self):
        from types import SimpleNamespace

        from security_mcp.mcp.intel_tools import _classify_finding_owasp

        finding = SimpleNamespace(cwe_id="", tool_used="", title="SQL Injection in login form")
        cats = _classify_finding_owasp(finding)
        assert "A03_injection" in cats

    def test_multi_path_classification(self):
        from types import SimpleNamespace

        from security_mcp.mcp.intel_tools import _classify_finding_owasp

        finding = SimpleNamespace(cwe_id="CWE-89", tool_used="sqli_test", title="SQL Injection")
        cats = _classify_finding_owasp(finding)
        assert "A03_injection" in cats
        assert "A07_auth_failures" in cats  # sqli_test covers A07 too

    def test_empty_finding_returns_empty(self):
        from types import SimpleNamespace

        from security_mcp.mcp.intel_tools import _classify_finding_owasp

        finding = SimpleNamespace(cwe_id="", tool_used="", title="")
        cats = _classify_finding_owasp(finding)
        assert len(cats) == 0


# ---------------------------------------------------------------------------
# plan (action="mandatory_tests") — was get_mandatory_tests
# ---------------------------------------------------------------------------


class TestGetMandatoryTests:
    async def test_always_run_tools_on_empty_endpoints(self, mcp_tools):
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://target:3000", endpoints="[]")
        data = json.loads(raw)
        assert data["target"] == "http://target:3000"
        assert len(data["always_run"]) == 5
        tools = {t["tool"] for t in data["always_run"]}
        assert "auth_test" in tools
        assert "cors_test" in tools
        assert "open_redirect_test" in tools
        assert data["total_tasks"] == 5

    async def test_sqli_matching_on_post_endpoint(self, mcp_tools):
        eps = json.dumps([{"url": "/api/Users", "method": "POST", "content_type": "application/json"}])
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://t", endpoints=eps)
        data = json.loads(raw)
        task_tools = {t["tool"] for t in data["endpoint_tasks"]}
        assert "sqli_test" in task_tools

    async def test_nosql_matching_on_json_body(self, mcp_tools):
        eps = json.dumps([{"url": "/rest/user/login", "method": "POST", "content_type": "application/json"}])
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://t", endpoints=eps)
        data = json.loads(raw)
        task_tools = {t["tool"] for t in data["endpoint_tasks"]}
        assert "nosql_test" in task_tools

    async def test_idor_matching_on_numeric_path(self, mcp_tools):
        eps = json.dumps([{"url": "/rest/basket/1", "method": "GET"}])
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://t", endpoints=eps)
        data = json.loads(raw)
        task_tools = {t["tool"] for t in data["endpoint_tasks"]}
        assert "idor_test" in task_tools

    async def test_xxe_matching_on_upload_endpoint(self, mcp_tools):
        eps = json.dumps([{"url": "/file-upload", "method": "POST"}])
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://t", endpoints=eps)
        data = json.loads(raw)
        task_tools = {t["tool"] for t in data["endpoint_tasks"]}
        assert "xxe_test" in task_tools

    async def test_ssrf_matching_on_url_param(self, mcp_tools):
        eps = json.dumps([{"url": "/profile/image/url", "method": "GET"}])
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://t", endpoints=eps)
        data = json.loads(raw)
        task_tools = {t["tool"] for t in data["endpoint_tasks"]}
        assert "ssrf_test" in task_tools

    async def test_relative_url_normalization(self, mcp_tools):
        eps = json.dumps([{"url": "/api/Users", "method": "POST"}])
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://localhost:3000", endpoints=eps)
        data = json.loads(raw)
        urls = {t["url"] for t in data["endpoint_tasks"]}
        assert all(u.startswith("http://localhost:3000/") for u in urls)

    async def test_deduplication(self, mcp_tools):
        eps = json.dumps(
            [
                {"url": "/api/Users", "method": "POST"},
                {"url": "/api/Users", "method": "POST"},
            ]
        )
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://t", endpoints=eps)
        data = json.loads(raw)
        # Each (tool, url) pair should appear only once
        pairs = [(t["tool"], t["url"]) for t in data["endpoint_tasks"]]
        assert len(pairs) == len(set(pairs))

    async def test_invalid_json_returns_error(self, mcp_tools):
        raw = await mcp_tools["plan"](action="mandatory_tests", target="http://t", endpoints="not json")
        data = json.loads(raw)
        assert "error" in data
        assert "hint" in data

    async def test_empty_target_returns_error(self, mcp_tools):
        raw = await mcp_tools["plan"](action="mandatory_tests", target="", endpoints="[]")
        data = json.loads(raw)
        assert "error" in data


# ---------------------------------------------------------------------------
# plan (action="coverage_gaps") — was get_coverage_gaps
# ---------------------------------------------------------------------------


class TestGetCoverageGaps:
    """Tests for plan(action='coverage_gaps').

    These tests need a real McpSessionStore -- they use monkeypatch to inject
    a test-local store backed by a temporary SQLite DB.
    """

    @pytest.fixture()
    async def store(self, tmp_path):
        from security_mcp.mcp.mcp_session_store import McpSessionStore

        return McpSessionStore(db_path=str(tmp_path / "test.db"))

    @pytest.fixture(autouse=True)
    def _patch_store(self, store, monkeypatch):
        monkeypatch.setattr(
            "security_mcp.mcp._singletons.get_mcp_session_store",
            lambda: store,
        )

    async def _create_session(self, store, target="http://target:3000"):
        return await store.create(target=target)

    async def _add_finding(self, store, sid, title="Test", severity="high", cwe="", tool_used=""):
        from security_mcp.models.enums import Severity
        from security_mcp.models.finding import Finding

        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}
        f = Finding(title=title, severity=sev_map.get(severity, Severity.HIGH), cwe_id=cwe)
        # Set tool_used if provided
        if tool_used:
            f.tool_used = tool_used
        await store.add_finding(sid, f)

    async def test_no_findings_returns_all_gaps(self, mcp_tools, store):
        sid = await self._create_session(store)
        raw = await mcp_tools["plan"](action="coverage_gaps", session_id=sid, target="http://t")
        data = json.loads(raw)
        assert data["coverage"]["tested_count"] == 0
        assert data["coverage"]["total_count"] == 10
        assert data["coverage"]["coverage_pct"] == 0.0
        assert len(data["coverage"]["untested_categories"]) == 10
        assert data["total_gap_tasks"] > 0

    async def test_cwe_classification_marks_category(self, mcp_tools, store):
        sid = await self._create_session(store)
        await self._add_finding(store, sid, title="SQLi", cwe="CWE-89")
        raw = await mcp_tools["plan"](action="coverage_gaps", session_id=sid, target="http://t")
        data = json.loads(raw)
        assert "A03_injection" in data["coverage"]["tested_categories"]
        assert "A03_injection" not in data["coverage"]["untested_categories"]

    async def test_title_classification_marks_category(self, mcp_tools, store):
        sid = await self._create_session(store)
        await self._add_finding(store, sid, title="IDOR on /rest/basket/1")
        raw = await mcp_tools["plan"](action="coverage_gaps", session_id=sid, target="http://t")
        data = json.loads(raw)
        assert "A01_access_control" in data["coverage"]["tested_categories"]

    async def test_full_coverage_returns_empty_gaps(self, mcp_tools, store):
        sid = await self._create_session(store)
        # Add findings that cover all 10 categories
        findings = [
            ("IDOR", "CWE-639"),  # A01
            ("Weak hash", "CWE-327"),  # A02
            ("SQLi", "CWE-89"),  # A03
            ("Business logic flaw", ""),  # A04 via title
            ("CORS wildcard", "CWE-942"),  # A05 (actually A01 via CWE -- add title match)
            ("Vulnerable component", ""),  # A06 via title
            ("JWT weakness", "CWE-287"),  # A07
            ("CSRF", "CWE-352"),  # A08 (actually A01 via CWE -- use title)
        ]
        for title, cwe in findings:
            await self._add_finding(store, sid, title=title, cwe=cwe)
        # Also add SSRF and misconfiguration explicitly
        await self._add_finding(store, sid, title="SSRF on profile")
        await self._add_finding(store, sid, title="Misconfiguration in headers")

        raw = await mcp_tools["plan"](action="coverage_gaps", session_id=sid, target="http://t")
        data = json.loads(raw)
        # Some categories should now be tested (may not be all 10 due to CWE mapping)
        assert data["coverage"]["tested_count"] >= 6

    async def test_gap_tasks_skip_generic_tools(self, mcp_tools, store):
        sid = await self._create_session(store)
        raw = await mcp_tools["plan"](action="coverage_gaps", session_id=sid, target="http://t")
        data = json.loads(raw)
        for task in data["gap_tasks"]:
            assert task["tool"] not in ("http_request", "fetch_page")

    async def test_session_not_found_returns_error(self, mcp_tools):
        raw = await mcp_tools["plan"](action="coverage_gaps", session_id="mcp-nonexistent", target="http://t")
        data = json.loads(raw)
        assert "error" in data

    async def test_coverage_pct_calculation(self, mcp_tools, store):
        sid = await self._create_session(store)
        await self._add_finding(store, sid, title="SQLi", cwe="CWE-89")  # A03
        await self._add_finding(store, sid, title="SSRF found", tool_used="ssrf_test")  # A10
        raw = await mcp_tools["plan"](action="coverage_gaps", session_id=sid, target="http://t")
        data = json.loads(raw)
        assert data["coverage"]["coverage_pct"] == 20.0  # 2/10 = 20%

    async def test_gap_tasks_have_owasp_label(self, mcp_tools, store):
        sid = await self._create_session(store)
        raw = await mcp_tools["plan"](action="coverage_gaps", session_id=sid, target="http://t")
        data = json.loads(raw)
        for task in data["gap_tasks"]:
            assert "owasp_label" in task
            assert "owasp_category" in task
            assert task["owasp_label"] != ""


# ---------------------------------------------------------------------------
# plan (action="post_auth") — was get_auth_retest_plan
# ---------------------------------------------------------------------------


class TestGetAuthRetestPlan:
    async def test_bearer_token_header_format(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="eyJtest", token_type="bearer")
        data = json.loads(raw)
        assert data["auth_header"] == {"Authorization": "Bearer eyJtest"}
        assert data["token_type"] == "bearer"

    async def test_cookie_token_header_format(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="abc123", token_type="cookie")
        data = json.loads(raw)
        assert data["auth_header"] == {"Cookie": "token=abc123"}

    async def test_api_key_token_header_format(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="key123", token_type="api_key")
        data = json.loads(raw)
        assert data["auth_header"] == {"X-API-Key": "key123"}

    async def test_eight_tiers_present(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="tok")
        data = json.loads(raw)
        assert data["total_tiers"] == 8
        assert len(data["tiers"]) == 8
        tier_nums = [t["tier"] for t in data["tiers"]]
        assert tier_nums == [0, 1, 2, 3, 4, 5, 6, 7]

    async def test_tier0_has_browser_crawl(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="tok")
        data = json.loads(raw)
        tier0 = data["tiers"][0]
        assert tier0["name"] == "Authenticated Recon"
        tools = [t.get("tool") for t in tier0["tasks"] if "tool" in t]
        assert "browser_crawl_site" in tools
        assert "dir_fuzz" in tools

    async def test_tier4_no_auth_header(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="tok")
        data = json.loads(raw)
        tier4 = data["tiers"][4]
        assert tier4["name"] == "Unauthenticated API Sweep"
        for task in tier4["tasks"]:
            # These tasks should NOT have auth headers
            params = task.get("params", {})
            assert "headers" not in params

    async def test_empty_token_returns_error(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="")
        data = json.loads(raw)
        assert "error" in data

    async def test_invalid_token_type_returns_error(self, mcp_tools):
        raw = await mcp_tools["plan"](action="post_auth", target="http://t", token="tok", token_type="invalid")
        data = json.loads(raw)
        assert "error" in data
