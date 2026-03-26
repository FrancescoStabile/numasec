"""Tests for extended GraphQL checks (checks 5-8) in security_mcp.scanners.graphql_tester."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from security_mcp.scanners.graphql_tester import (
    GraphQLResult,
    GraphQLTester,
    GraphQLVulnerability,
)


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# Check 5: Mutation authorization bypass
# ---------------------------------------------------------------------------


class TestMutationAuthorizationBypass:
    @pytest.mark.asyncio
    async def test_mutation_no_auth_detected(self):
        """Unauthenticated mutation that returns data is flagged as missing auth."""
        tester = GraphQLTester(timeout=5.0)

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            query = body.get("query", "")
            if "createUser" in query:
                return httpx.Response(
                    200,
                    json={"data": {"createUser": {"id": "123"}}},
                )
            return httpx.Response(200, json={"data": None, "errors": [{"message": "not found"}]})

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await tester._check_mutation_auth(
                "http://example.com/graphql",
                {"Content-Type": "application/json"},
                client,
            )

        assert len(findings) >= 1
        assert any(v.vuln_type == "mutation_no_auth" for v in findings)
        assert any(v.severity == "high" for v in findings)


# ---------------------------------------------------------------------------
# Check 6: Field-level authorization
# ---------------------------------------------------------------------------


class TestFieldLevelAuthorization:
    @pytest.mark.asyncio
    async def test_sensitive_field_exposed(self):
        """Sensitive fields (password, token) accessible on types are flagged."""
        tester = GraphQLTester(timeout=5.0)

        # Fake types from introspection
        types = [
            {
                "name": "User",
                "kind": "OBJECT",
                "fields": [
                    {"name": "id"},
                    {"name": "email"},
                    {"name": "password"},
                    {"name": "token"},
                ],
            }
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            query = body.get("query", "")
            if "password" in query or "token" in query:
                return httpx.Response(
                    200,
                    json={"data": {"user": {"id": "1", "password": "hashed_pw", "token": "secret_tok"}}},
                )
            return httpx.Response(200, json={"errors": [{"message": "unknown field"}]})

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await tester._check_field_auth(
                "http://example.com/graphql",
                {"Content-Type": "application/json"},
                types,
                client,
            )

        assert len(findings) >= 1
        assert any(v.vuln_type == "sensitive_field_exposed" for v in findings)
        assert any(v.severity == "high" for v in findings)


# ---------------------------------------------------------------------------
# Check 7: Alias resource exhaustion
# ---------------------------------------------------------------------------


class TestAliasResourceExhaustion:
    @pytest.mark.asyncio
    async def test_no_alias_limit_detected(self):
        """Server accepting 100 aliases without rejection is flagged."""
        tester = GraphQLTester(timeout=5.0)

        def handler(request: httpx.Request) -> httpx.Response:
            # Accept and respond to alias query
            return httpx.Response(
                200,
                json={"data": {f"a{i}": "Query" for i in range(100)}},
            )

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await tester._check_alias_dos(
                "http://example.com/graphql",
                {"Content-Type": "application/json"},
                client,
            )

        assert len(findings) == 1
        assert findings[0].vuln_type == "no_alias_limit"

    @pytest.mark.asyncio
    async def test_alias_rejected_no_finding(self):
        """Server that rejects alias query with 400 produces no finding."""
        tester = GraphQLTester(timeout=5.0)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="Query too complex")

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await tester._check_alias_dos(
                "http://example.com/graphql",
                {"Content-Type": "application/json"},
                client,
            )

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Check 8: Persisted query bypass
# ---------------------------------------------------------------------------


class TestPersistedQueryBypass:
    @pytest.mark.asyncio
    async def test_persisted_query_bypass_detected(self):
        """APQ bypass: server executes full query alongside invalid hash."""
        tester = GraphQLTester(timeout=5.0)
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            body = json.loads(request.content)

            # First call: probe for APQ support
            if call_count == 1:
                return httpx.Response(
                    200,
                    json={"errors": [{"message": "PersistedQueryNotFound"}]},
                )
            # Second call: bypass attempt -- server executes the full query
            return httpx.Response(
                200,
                json={"data": {"__typename": "Query"}},
            )

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await tester._check_persisted_query_bypass(
                "http://example.com/graphql",
                {"Content-Type": "application/json"},
                client,
            )

        assert len(findings) == 1
        assert findings[0].vuln_type == "persisted_query_bypass"
        assert findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_apq_support_no_finding(self):
        """Server without APQ support produces no finding."""
        tester = GraphQLTester(timeout=5.0)

        def handler(request: httpx.Request) -> httpx.Response:
            # No PersistedQueryNotFound error -- APQ not supported
            return httpx.Response(
                200,
                json={"errors": [{"message": "Unknown extension"}]},
            )

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await tester._check_persisted_query_bypass(
                "http://example.com/graphql",
                {"Content-Type": "application/json"},
                client,
            )

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Check 1: Introspection detection
# ---------------------------------------------------------------------------


class TestIntrospectionDetection:
    @pytest.mark.asyncio
    async def test_introspection_enabled(self):
        """Introspection query returning schema types is flagged."""
        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://example.com/graphql")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "__schema": {
                            "types": [
                                {"name": "__Schema", "kind": "OBJECT", "fields": []},
                                {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}]},
                                {"name": "Query", "kind": "OBJECT", "fields": [{"name": "users"}]},
                            ],
                            "queryType": {"name": "Query"},
                            "mutationType": None,
                        }
                    }
                },
            )

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            user_types = await tester._test_introspection(client, "http://example.com/graphql", result)

        assert result.vulnerable is True
        assert any(v.vuln_type == "introspection_enabled" for v in result.vulnerabilities)
        # __Schema is an internal type and should be filtered out
        assert all(not t.get("name", "").startswith("__") for t in user_types)


# ---------------------------------------------------------------------------
# Check 3: Query depth detection
# ---------------------------------------------------------------------------


class TestQueryDepthDetection:
    @pytest.mark.asyncio
    async def test_no_depth_limit_detected(self):
        """Deep nested query accepted without depth error is flagged."""
        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://example.com/graphql")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"__typename": "Query"}})

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await tester._test_depth_limit(client, "http://example.com/graphql", result)

        assert any(v.vuln_type == "no_depth_limit" for v in result.vulnerabilities)

    @pytest.mark.asyncio
    async def test_depth_limit_enforced(self):
        """Server that rejects deep queries with depth error produces no finding."""
        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://example.com/graphql")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"errors": [{"message": "Query depth exceeds maximum allowed depth of 5"}]},
            )

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await tester._test_depth_limit(client, "http://example.com/graphql", result)

        assert not any(v.vuln_type == "no_depth_limit" for v in result.vulnerabilities)


# ---------------------------------------------------------------------------
# Check 4: Batch query detection
# ---------------------------------------------------------------------------


class TestBatchQueryDetection:
    @pytest.mark.asyncio
    async def test_batch_queries_enabled(self):
        """Server accepting batch queries (array of operations) is flagged."""
        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://example.com/graphql")

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if isinstance(body, list):
                return httpx.Response(
                    200,
                    json=[{"data": {"__typename": "Query"}} for _ in body],
                )
            return httpx.Response(200, json={"data": {"__typename": "Query"}})

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await tester._test_batch_queries(client, "http://example.com/graphql", result)

        assert any(v.vuln_type == "batch_queries_enabled" for v in result.vulnerabilities)

    @pytest.mark.asyncio
    async def test_batch_rejected_no_finding(self):
        """Server that rejects batch queries produces no finding."""
        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://example.com/graphql")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="Batch queries not supported")

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await tester._test_batch_queries(client, "http://example.com/graphql", result)

        assert not any(v.vuln_type == "batch_queries_enabled" for v in result.vulnerabilities)


# ---------------------------------------------------------------------------
# Check 2: Field suggestion enumeration
# ---------------------------------------------------------------------------


class TestFieldSuggestionEnumeration:
    @pytest.mark.asyncio
    async def test_field_suggestion_leak(self):
        """Error messages with 'did you mean' leak field names."""
        tester = GraphQLTester(timeout=5.0)
        result = GraphQLResult(target="http://example.com/graphql")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "errors": [
                        {"message": "Cannot query field 'user'. Did you mean 'users' or 'userProfile'?"}
                    ]
                },
            )

        transport = _transport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await tester._test_field_suggestions(client, "http://example.com/graphql", result)

        assert any(v.vuln_type == "field_suggestion_leak" for v in result.vulnerabilities)
