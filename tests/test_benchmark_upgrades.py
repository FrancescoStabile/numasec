"""Tests for benchmark upgrade features: NoSQL FP fix, SQLi auth-bypass,
content_type normalization, IDOR tester, GraphQL tester, browser crawler,
open redirect bypass payloads, updated ground truth, and updated scorer.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest


def _transport(handler):
    return httpx.MockTransport(handler)


# ===========================================================================
# NoSQL FP fix: baseline-aware success indicators
# ===========================================================================


class TestNoSqlBaselineAware:
    """Verify that the nosql_test no longer flags success keywords
    that already exist in the baseline response."""

    async def test_success_keyword_in_baseline_not_flagged(self) -> None:
        """If 'success' already appears in baseline, it should NOT trigger a finding."""
        from security_mcp.scanners.nosql_tester import NoSqlTester

        tester = NoSqlTester(timeout=5.0)
        baseline = '{"status": "success", "data": []}'
        response = '{"status": "success", "data": [{"id": 1}]}'

        vuln = tester._evaluate_response(response, baseline, "email", '{"$ne": ""}', "POST JSON")
        # "success" is in both → should NOT trigger tier 2
        # Length diff might trigger tier 3 if above threshold; verify no tier 2 match
        if vuln is not None:
            assert "Success indicator" not in vuln.evidence, (
                "Should not flag success indicator that exists in baseline"
            )

    async def test_new_success_keyword_flagged(self) -> None:
        """Success indicator that is NEW vs baseline should be flagged."""
        from security_mcp.scanners.nosql_tester import NoSqlTester

        tester = NoSqlTester(timeout=5.0)
        baseline = '{"error": "Invalid credentials"}'
        # "welcome" and "logged in" are in _NOSQL_SUCCESS_INDICATORS
        response = '{"message": "Welcome! You are now logged in as admin"}'

        vuln = tester._evaluate_response(response, baseline, "email", '{"$ne": ""}', "POST JSON")
        assert vuln is not None
        assert "welcome" in vuln.evidence.lower() or "logged in" in vuln.evidence.lower()

    async def test_mongo_error_always_flagged(self) -> None:
        """MongoDB error keywords should be flagged regardless of baseline."""
        from security_mcp.scanners.nosql_tester import NoSqlTester

        tester = NoSqlTester(timeout=5.0)
        baseline = '{"status": "ok"}'
        response = 'MongoError: CastError: Cast to number failed'

        vuln = tester._evaluate_response(response, baseline, "q", '{"$ne": ""}', "GET")
        assert vuln is not None
        assert vuln.severity == "high"


# ===========================================================================
# SQLi content_type normalization
# ===========================================================================


class TestSqliContentTypeNormalization:
    async def test_application_json_normalized_to_json(self) -> None:
        """content_type='application/json' should be normalized to 'json'."""
        from security_mcp.scanners.sqli_tester import python_sqli_test

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = request.content.decode()
                if "'" in body or "OR" in body:
                    return httpx.Response(200, text="You have an error in your SQL syntax near ''")
            return httpx.Response(200, text="OK")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            output = await python_sqli_test(
                url="http://target/rest/user/login",
                method="POST",
                body='{"email": "test@test.com", "password": "test"}',
                content_type="application/json",  # <-- should work now
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(output)
        assert data["params_tested"] == 2
        assert data["vulnerable"] is True

    async def test_form_urlencoded_normalized_to_form(self) -> None:
        """content_type='application/x-www-form-urlencoded' → 'form'."""
        from security_mcp.scanners.sqli_tester import python_sqli_test

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="OK")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            output = await python_sqli_test(
                url="http://target/login",
                method="POST",
                body="user=admin&pass=secret",
                content_type="application/x-www-form-urlencoded",
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(output)
        assert data["params_tested"] == 2  # user + pass


# ===========================================================================
# SQLi auth-bypass detection (Phase 0)
# ===========================================================================


class TestSqliAuthBypass:
    async def test_auth_bypass_detected_via_status_upgrade(self) -> None:
        """401 baseline → 200 with injected payload = auth_bypass."""
        from security_mcp.scanners.sqli_tester import PythonSQLiTester

        call_count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            if request.method == "POST":
                body = request.content.decode()
                if "OR 1=1" in body or "admin'--" in body:
                    return httpx.Response(
                        200,
                        text='{"authentication": {"token": "eyJhbG..", "umail": "admin"}}',
                    )
            return httpx.Response(401, text="Invalid email or password.")

        tester = PythonSQLiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._test_auth_bypass(
                client,
                "http://target/rest/user/login",
                "email",
                "POST",
                "POST",
                {"email": "test@test.com", "password": "test"},
                "json",
            )

        assert vuln is not None
        assert vuln.technique == "auth_bypass"
        assert "status" in vuln.evidence.lower() or "token" in vuln.evidence.lower()

    async def test_auth_bypass_not_triggered_for_non_auth_params(self) -> None:
        """Non-auth parameters (like 'q') should NOT run Phase 0."""
        from security_mcp.scanners.sqli_tester import AUTH_PARAM_NAMES

        assert "q" not in AUTH_PARAM_NAMES
        assert "email" in AUTH_PARAM_NAMES
        assert "username" in AUTH_PARAM_NAMES

    async def test_no_false_positive_on_same_status(self) -> None:
        """If both baseline and injected return 200 with same content, no auth_bypass."""
        from security_mcp.scanners.sqli_tester import PythonSQLiTester

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Invalid email or password.")

        tester = PythonSQLiTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            vuln = await tester._test_auth_bypass(
                client,
                "http://target/rest/user/login",
                "email",
                "POST",
                "POST",
                {"email": "test@test.com", "password": "test"},
                "json",
            )

        assert vuln is None


# ===========================================================================
# IDOR Tester
# ===========================================================================


class TestIdorResult:
    def test_to_dict_empty(self) -> None:
        from security_mcp.scanners.idor_tester import IDORResult

        r = IDORResult(target="http://example.com/api/Users/1")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["vulnerabilities"] == []
        assert d["ids_tested"] == 0

    def test_to_dict_with_vuln(self) -> None:
        from security_mcp.scanners.idor_tester import IDORResult, IDORVulnerability

        r = IDORResult(
            target="http://example.com/api/Users/1",
            vulnerable=True,
            ids_tested=4,
            vulnerabilities=[
                IDORVulnerability(
                    parameter="path:1",
                    original_id="1",
                    tested_id="2",
                    evidence="Different response",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["ids_tested"] == 4
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["severity"] == "high"


class TestIdorIdDetection:
    def test_finds_numeric_path_id(self) -> None:
        from security_mcp.scanners.idor_tester import IDORTester

        tester = IDORTester()
        parsed = urlparse("http://target/api/Users/42/profile")
        test_cases = tester._find_ids(parsed)
        assert len(test_cases) >= 1
        locations = [tc[0] for tc in test_cases]
        assert any("42" in loc for loc in locations)

    def test_finds_query_param_id(self) -> None:
        from security_mcp.scanners.idor_tester import IDORTester

        tester = IDORTester()
        parsed = urlparse("http://target/page?id=7&name=test")
        test_cases = tester._find_ids(parsed)
        assert len(test_cases) >= 1
        locations = [tc[0] for tc in test_cases]
        assert any("id" in loc for loc in locations)

    def test_generates_adjacent_ids(self) -> None:
        from security_mcp.scanners.idor_tester import IDORTester

        alt = IDORTester._generate_alt_ids("5")
        assert "4" in alt
        assert "6" in alt
        assert "3" in alt
        assert "7" in alt

    def test_generates_common_test_ids(self) -> None:
        from security_mcp.scanners.idor_tester import IDORTester

        alt = IDORTester._generate_alt_ids("99")
        assert "1" in alt
        assert "0" in alt


class TestIdorDetection:
    async def test_idor_detected(self) -> None:
        """Different content for different IDs → IDOR vulnerability."""
        from security_mcp.scanners.idor_tester import IDORTester

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if "/1" in path:
                return httpx.Response(
                    200,
                    text='{"id": 1, "name": "Alice Johnson", "email": "alice@test.com", "role": "user"}',
                )
            if "/2" in path:
                return httpx.Response(
                    200,
                    text='{"id": 2, "name": "Robert Smith", "email": "bob@test.com", "role": "admin"}',
                )
            return httpx.Response(404, text="Not found")

        tester = IDORTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            result = await tester.test("http://target/api/Users/1")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is True
        assert len(result.vulnerabilities) >= 1

    async def test_no_idor_when_404(self) -> None:
        """404 for adjacent IDs → no IDOR."""
        from security_mcp.scanners.idor_tester import IDORTester

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if "/1" in path:
                return httpx.Response(200, text='{"id": 1, "name": "Alice", "email": "alice@test.com"}')
            return httpx.Response(404, text="Not found")

        tester = IDORTester(timeout=5.0)
        original_init = httpx.AsyncClient.__init__

        def patched_init(self_client, **kwargs):
            kwargs["transport"] = _transport(handler)
            original_init(self_client, **kwargs)

        httpx.AsyncClient.__init__ = patched_init
        try:
            result = await tester.test("http://target/api/Users/1")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.vulnerable is False


class TestIdorToolWrapper:
    async def test_python_idor_test_returns_json(self) -> None:
        from security_mcp.scanners.idor_tester import IDORResult, IDORTester, python_idor_test
        import unittest.mock as mock

        with mock.patch.object(IDORTester, "test") as mock_test:
            mock_test.return_value = IDORResult(target="http://target/api/Users/1")
            result = await python_idor_test("http://target/api/Users/1")

        data = json.loads(result)
        assert "target" in data
        assert "vulnerable" in data
        assert "ids_tested" in data

    async def test_python_idor_test_with_headers(self) -> None:
        from security_mcp.scanners.idor_tester import IDORResult, IDORTester, python_idor_test
        import unittest.mock as mock

        with mock.patch.object(IDORTester, "test") as mock_test:
            mock_test.return_value = IDORResult(target="http://target/api/Users/1")
            result = await python_idor_test(
                "http://target/api/Users/1",
                headers='{"Authorization": "Bearer token123"}',
            )

        data = json.loads(result)
        assert data["target"] == "http://target/api/Users/1"
        # Verify the tester was called with parsed headers
        _, kwargs = mock_test.call_args
        assert kwargs["headers"] == {"Authorization": "Bearer token123"}


# ===========================================================================
# GraphQL Tester
# ===========================================================================


class TestGraphQLResult:
    def test_to_dict_empty(self) -> None:
        from security_mcp.scanners.graphql_tester import GraphQLResult

        r = GraphQLResult(target="http://example.com")
        d = r.to_dict()
        assert d["vulnerable"] is False
        assert d["endpoint_found"] is False
        assert d["vulnerabilities"] == []

    def test_to_dict_with_vuln(self) -> None:
        from security_mcp.scanners.graphql_tester import GraphQLResult, GraphQLVulnerability

        r = GraphQLResult(
            target="http://example.com",
            endpoint_found=True,
            endpoint="http://example.com/graphql",
            vulnerable=True,
            schema_types=15,
            vulnerabilities=[
                GraphQLVulnerability(
                    vuln_type="introspection_enabled",
                    severity="medium",
                    evidence="15 types exposed",
                    endpoint="http://example.com/graphql",
                )
            ],
        )
        d = r.to_dict()
        assert d["vulnerable"] is True
        assert d["endpoint_found"] is True
        assert d["schema_types"] == 15
        assert d["vulnerabilities"][0]["type"] == "introspection_enabled"


class TestGraphQLEndpointDiscovery:
    async def test_discovers_graphql_endpoint(self) -> None:
        from security_mcp.scanners.graphql_tester import GraphQLTester

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/graphql" and request.method == "POST":
                return httpx.Response(200, text='{"data": {"__typename": "Query"}}')
            return httpx.Response(404, text="Not found")

        tester = GraphQLTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            endpoint = await tester._discover_endpoint(client, "http://target.local/")

        assert endpoint is not None
        assert "/graphql" in endpoint

    async def test_no_endpoint_found(self) -> None:
        from security_mcp.scanners.graphql_tester import GraphQLTester

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Not found")

        tester = GraphQLTester(timeout=5.0)
        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            endpoint = await tester._discover_endpoint(client, "http://target.local/")

        assert endpoint is None


class TestGraphQLIntrospection:
    async def test_introspection_detected(self) -> None:
        from security_mcp.scanners.graphql_tester import GraphQLResult, GraphQLTester

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=json.dumps({
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "Query", "kind": "OBJECT", "fields": [{"name": "user"}]},
                            {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}]},
                            {"name": "__Schema", "kind": "OBJECT", "fields": []},
                        ],
                        "queryType": {"name": "Query"},
                        "mutationType": None,
                    }
                }
            }))

        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://target.local/graphql")

        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            await tester._test_introspection(client, "http://target.local/graphql", result)

        assert result.vulnerable is True
        assert result.schema_types == 3
        introspection_vulns = [v for v in result.vulnerabilities if v.vuln_type == "introspection_enabled"]
        assert len(introspection_vulns) == 1


class TestGraphQLBatchQueries:
    async def test_batch_queries_detected(self) -> None:
        from security_mcp.scanners.graphql_tester import GraphQLResult, GraphQLTester

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode())
            if isinstance(body, list):
                return httpx.Response(200, text=json.dumps([
                    {"data": {"__typename": "Query"}},
                    {"data": {"__typename": "Query"}},
                    {"data": {"__typename": "Query"}},
                ]))
            return httpx.Response(200, text='{"data": {"__typename": "Query"}}')

        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://target.local/graphql")

        async with httpx.AsyncClient(transport=_transport(handler)) as client:
            await tester._test_batch_queries(client, "http://target.local/graphql", result)

        assert result.vulnerable is True
        batch_vulns = [v for v in result.vulnerabilities if v.vuln_type == "batch_queries_enabled"]
        assert len(batch_vulns) == 1


class TestGraphQLToolWrapper:
    async def test_python_graphql_test_returns_json(self) -> None:
        from security_mcp.scanners.graphql_tester import GraphQLResult, GraphQLTester, python_graphql_test
        import unittest.mock as mock

        with mock.patch.object(GraphQLTester, "test") as mock_test:
            mock_test.return_value = GraphQLResult(target="http://example.com")
            result = await python_graphql_test("http://example.com")

        data = json.loads(result)
        assert "target" in data
        assert "vulnerable" in data
        assert "endpoint_found" in data


# ===========================================================================
# Browser Crawler
# ===========================================================================


class TestBrowserCrawlResult:
    def test_to_dict(self) -> None:
        from security_mcp.scanners.browser_crawler import BrowserCrawlResult

        r = BrowserCrawlResult(
            target="http://example.com",
            urls=["http://example.com/a", "http://example.com/b", "http://example.com/a"],
            api_endpoints=["/api/users", "/api/users"],
            technologies=["Angular"],
        )
        d = r.to_dict()
        assert len(d["urls"]) == 2  # deduped
        assert len(d["api_endpoints"]) == 1  # deduped
        assert d["technologies"] == ["Angular"]


class TestBrowserCrawlerPlaywrightFallback:
    async def test_graceful_fallback_without_playwright(self) -> None:
        """If Playwright is not installed, browser crawl should return empty result."""
        import unittest.mock as mock

        with mock.patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
            # Import the module fresh after patching
            from security_mcp.scanners.browser_crawler import BrowserCrawler

            crawler = BrowserCrawler(timeout=5.0)
            result = await crawler.crawl("http://example.com")

        assert result.target == "http://example.com"
        assert result.urls == []


# ===========================================================================
# Open Redirect bypass payloads
# ===========================================================================


class TestOpenRedirectBypassPayloads:
    def test_bypass_payloads_exist(self) -> None:
        """Verify that allowlist bypass payloads were added."""
        from security_mcp.scanners.open_redirect_tester import _REDIRECT_PAYLOADS

        # Check for bypass-style payloads
        payloads_str = " ".join(_REDIRECT_PAYLOADS)
        assert "target@evil.example.com" in payloads_str
        assert "target.evil.example.com" in payloads_str
        assert "evil.example.com#target" in payloads_str

    def test_to_param_in_redirect_params(self) -> None:
        """Verify 'to' param is in the redirect param list."""
        from security_mcp.scanners.open_redirect_tester import _REDIRECT_PARAMS

        assert "to" in _REDIRECT_PARAMS
        assert "dest" in _REDIRECT_PARAMS
        assert "destination" in _REDIRECT_PARAMS
        assert "continue" in _REDIRECT_PARAMS
        assert "forward" in _REDIRECT_PARAMS

    def test_payload_count_at_least_11(self) -> None:
        """We should have at least 11 redirect payloads (4 original + 8 bypass)."""
        from security_mcp.scanners.open_redirect_tester import _REDIRECT_PAYLOADS

        assert len(_REDIRECT_PAYLOADS) >= 11


# ===========================================================================
# Updated Ground Truth
# ===========================================================================


class TestGroundTruth:
    def test_juice_shop_has_26_vulns(self) -> None:
        from tests.benchmarks.ground_truth import JUICE_SHOP_GROUND_TRUTH

        assert len(JUICE_SHOP_GROUND_TRUTH["vulns"]) == 26

    def test_juice_shop_covers_all_categories(self) -> None:
        from tests.benchmarks.ground_truth import JUICE_SHOP_GROUND_TRUTH

        types = {v["type"] for v in JUICE_SHOP_GROUND_TRUTH["vulns"]}
        assert "sqli" in types
        assert "sqli_auth_bypass" in types
        assert "xss_dom" in types
        assert "xss_stored" in types
        assert "idor" in types
        assert "jwt_weak" in types
        assert "nosql_injection" in types
        assert "xxe" in types
        assert "csrf" in types
        assert "ssrf" in types
        assert "open_redirect" in types
        assert "path_traversal" in types
        assert "default_credentials" in types

    def test_dvwa_ground_truth_unchanged(self) -> None:
        from tests.benchmarks.ground_truth import DVWA_GROUND_TRUTH

        assert len(DVWA_GROUND_TRUTH["vulns"]) == 7

    def test_type_aliases_exist(self) -> None:
        from tests.benchmarks.ground_truth import _TYPE_ALIASES

        assert "sqli" in _TYPE_ALIASES
        assert "idor" in _TYPE_ALIASES
        assert "jwt_weak" in _TYPE_ALIASES
        assert len(_TYPE_ALIASES) >= 20


# ===========================================================================
# Updated Scorer
# ===========================================================================


class TestScorer:
    def test_basic_scoring(self) -> None:
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "sqli"}, {"type": "xss_dom"}]
        gt = [{"type": "sqli", "severity": "high"}, {"type": "xss_dom", "severity": "medium"}]
        scores = calculate_scores(findings, gt)
        assert scores["precision"] == 1.0
        assert scores["recall"] == 1.0
        assert scores["f1"] == 1.0
        assert scores["true_positives"] == 2

    def test_alias_matching(self) -> None:
        from tests.benchmarks.ground_truth import _TYPE_ALIASES
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "sql_injection"}]
        gt = [{"type": "sqli", "severity": "high"}]
        scores = calculate_scores(findings, gt, aliases=_TYPE_ALIASES)
        assert scores["recall"] == 1.0
        assert scores["true_positives"] == 1

    def test_partial_match(self) -> None:
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "sqli"}, {"type": "xss"}]
        gt = [
            {"type": "sqli", "severity": "critical"},
            {"type": "idor", "severity": "high"},
            {"type": "csrf", "severity": "medium"},
        ]
        scores = calculate_scores(findings, gt)
        assert scores["true_positives"] == 1  # only sqli matches
        assert scores["precision"] == 0.5  # 1/2
        assert abs(scores["recall"] - 1 / 3) < 0.01

    def test_empty_findings(self) -> None:
        from tests.benchmarks.scorer import calculate_scores

        scores = calculate_scores([], [{"type": "sqli", "severity": "high"}])
        assert scores["recall"] == 0.0
        assert scores["precision"] == 0.0

    def test_unmatched_gt_and_findings_reported(self) -> None:
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "sqli"}, {"type": "xxe"}]
        gt = [{"type": "sqli", "severity": "high"}, {"type": "csrf", "severity": "medium"}]
        scores = calculate_scores(findings, gt)
        assert scores["true_positives"] == 1
        assert len(scores["unmatched_gt"]) == 1
        assert scores["unmatched_gt"][0]["type"] == "csrf"
        assert len(scores["unmatched_findings"]) == 1
        assert scores["unmatched_findings"][0]["type"] == "xxe"

    def test_location_matching(self) -> None:
        from tests.benchmarks.scorer import calculate_scores

        findings = [
            {"type": "idor", "location": "/api/Users/"},
            {"type": "idor", "location": "/api/Cards/"},
        ]
        gt = [
            {"type": "idor", "severity": "high", "location": "/api/Users/"},
            {"type": "idor", "severity": "high", "location": "/api/Cards/"},
        ]
        scores = calculate_scores(findings, gt)
        assert scores["true_positives"] == 2
        assert scores["recall"] == 1.0

    def test_weighted_recall(self) -> None:
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "sqli"}]  # matches only critical
        gt = [
            {"type": "sqli", "severity": "critical"},  # weight 3.0
            {"type": "xss", "severity": "low"},  # weight 0.5
        ]
        scores = calculate_scores(findings, gt)
        # weighted_recall = 3.0 / (3.0 + 0.5) = 0.857
        assert abs(scores["weighted_recall"] - 3.0 / 3.5) < 0.01


# ===========================================================================
# Tool Registration (new tools)
# ===========================================================================


class TestNewToolRegistration:
    def test_access_control_test_registered(self) -> None:
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "access_control_test" in registry._tools

    def test_injection_test_registered(self) -> None:
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "injection_test" in registry._tools

    def test_crawl_registered(self) -> None:
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "crawl" in registry._tools

    def test_total_tool_count_at_least_14(self) -> None:
        """Consolidated registry has ~14-16 tools (plus conditional sqlmap/nuclei)."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert len(registry._tools) >= 14

    def test_composite_tool_schemas_have_required_url(self) -> None:
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        schemas = registry.get_schemas()
        for tool_name in ("access_control_test", "injection_test", "crawl"):
            schema = next(s for s in schemas if s["function"]["name"] == tool_name)
            assert "url" in schema["function"]["parameters"]["properties"]
            assert "url" in schema["function"]["parameters"]["required"]


# ===========================================================================
# MCP intel_tools plan(action="initial") testing guidance
# ===========================================================================


class TestScanPlanGuidance:
    async def test_plan_initial_includes_testing_guidance(self) -> None:
        """plan(action='initial') should return testing_guidance with checklists."""
        import unittest.mock as mock

        from security_mcp.mcp.intel_tools import register

        # Create a minimal mock MCP server to capture the registered tool
        tools: dict = {}

        class MockMCP:
            def tool(self, name: str, description: str = ""):
                def decorator(func):
                    tools[name] = func
                    return func
                return decorator

        mcp = MockMCP()
        register(mcp)

        assert "plan" in tools

        # Mock the planner at its actual module (lazy import inside the tool function)
        with mock.patch("security_mcp.core.planner.DeterministicPlanner") as MockPlanner:
            mock_plan = mock.MagicMock()
            mock_plan.phases = []
            MockPlanner.return_value.create_plan.return_value = mock_plan

            with mock.patch("security_mcp.models.target.TargetProfile"):
                result_json = await tools["plan"](action="initial", target="http://target.com", scope="quick")

        result = json.loads(result_json)
        assert "testing_guidance" in result
        guidance = result["testing_guidance"]
        assert "recon_checklist" in guidance
        assert "mapping_checklist" in guidance
        assert "vulnerability_checklist" in guidance
        assert "exploitation_checklist" in guidance
        assert "tips" in guidance

        # Verify key guidance items
        vuln_checklist = " ".join(guidance["vulnerability_checklist"])
        assert "sqli_test" in vuln_checklist
        assert "xss_test" in vuln_checklist
        assert "idor_test" in vuln_checklist

        mapping_checklist = " ".join(guidance["mapping_checklist"])
        assert "graphql" in mapping_checklist.lower()

        all_guidance = " ".join(
            item
            for checklist in guidance.values()
            if isinstance(checklist, list)
            for item in checklist
        )
        assert "graphql_test" in all_guidance or "graphql" in all_guidance.lower()
