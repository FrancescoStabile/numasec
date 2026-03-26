"""Tests for security_mcp.scanners.openapi_parser — OpenAPI/Swagger spec parsing."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import yaml

from security_mcp.scanners.openapi_parser import (
    OpenAPIEndpoint,
    OpenAPIParameter,
    OpenAPIParser,
    OpenAPISpec,
)


# ---------------------------------------------------------------------------
# Sample specs
# ---------------------------------------------------------------------------


_OPENAPI_30_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Pet Store", "version": "1.0.0"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/pets": {
            "get": {
                "summary": "List all pets",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer"},
                    }
                ],
                "security": [{"bearerAuth": []}],
                "tags": ["pets"],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "summary": "Create a pet",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "tag": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "security": [{"bearerAuth": []}],
                "tags": ["pets"],
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/pets/{petId}": {
            "parameters": [
                {"name": "petId", "in": "path", "required": True, "schema": {"type": "string"}}
            ],
            "get": {
                "summary": "Get pet by ID",
                "tags": ["pets"],
                "responses": {"200": {"description": "OK"}},
            },
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    },
    "security": [{"bearerAuth": []}],
}


_SWAGGER_20_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "0.9"},
    "host": "api.legacy.com",
    "basePath": "/v2",
    "schemes": ["https"],
    "paths": {
        "/users": {
            "get": {
                "summary": "List users",
                "parameters": [
                    {"name": "page", "in": "query", "type": "integer"},
                    {"name": "X-Request-ID", "in": "header", "type": "string"},
                ],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "summary": "Create user",
                "consumes": ["application/json"],
                "parameters": [
                    {
                        "name": "body",
                        "in": "body",
                        "required": True,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "username": {"type": "string"},
                                "email": {"type": "string"},
                            },
                        },
                    }
                ],
                "responses": {"201": {"description": "Created"}},
            },
        },
    },
    "securityDefinitions": {
        "api_key": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
    },
}


_OPENAPI_31_SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "Webhook API", "version": "2.0.0"},
    "paths": {
        "/events": {
            "get": {
                "summary": "List events",
                "responses": {"200": {"description": "OK"}},
            }
        },
    },
    "webhooks": {
        "newEvent": {
            "post": {
                "summary": "New event webhook",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "properties": {"event_id": {"type": "string"}}}
                        }
                    }
                },
            }
        }
    },
    "components": {
        "securitySchemes": {
            "basicAuth": {"type": "http", "scheme": "basic"}
        }
    },
}


# ---------------------------------------------------------------------------
# Parsing tests
# ---------------------------------------------------------------------------


class TestParseOpenapi30:
    def test_parse_openapi_30_spec(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_30_SPEC, base_url="https://api.example.com/v1")

        assert spec.title == "Pet Store"
        assert spec.version == "1.0.0"
        assert spec.spec_version == "3.0"
        assert spec.total_endpoints == 3  # GET /pets, POST /pets, GET /pets/{petId}
        assert spec.base_url == "https://api.example.com/v1"

        # Security schemes extracted
        assert "bearerAuth" in spec.security_schemes
        assert spec.security_schemes["bearerAuth"]["scheme"] == "bearer"

        # Endpoint details
        methods = [(ep.method, ep.path) for ep in spec.endpoints]
        assert ("GET", "/pets") in methods
        assert ("POST", "/pets") in methods
        assert ("GET", "/pets/{petId}") in methods

    def test_auth_required_inferred(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_30_SPEC)

        get_pets = next(ep for ep in spec.endpoints if ep.path == "/pets" and ep.method == "GET")
        assert get_pets.auth_required is True
        assert "bearer" in get_pets.auth_schemes


class TestParseOpenapi20Swagger:
    def test_parse_swagger_20(self):
        parser = OpenAPIParser()
        spec = parser.parse(_SWAGGER_20_SPEC)

        assert spec.title == "Legacy API"
        assert spec.spec_version == "2.0"
        assert spec.base_url == "https://api.legacy.com/v2"
        assert spec.total_endpoints == 2

        # POST /users has body parameter
        post_users = next(ep for ep in spec.endpoints if ep.path == "/users" and ep.method == "POST")
        assert post_users.request_body_type == "application/json"
        assert post_users.request_body_required is True


class TestParseOpenapi31:
    def test_parse_openapi_31_detected(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_31_SPEC)

        assert spec.spec_version == "3.1"
        assert spec.title == "Webhook API"
        assert spec.total_endpoints >= 1


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------


class TestExtractParameters:
    def test_query_and_path_params(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_30_SPEC)

        get_pets = next(ep for ep in spec.endpoints if ep.path == "/pets" and ep.method == "GET")
        param_names = [p.name for p in get_pets.parameters]
        assert "limit" in param_names

        get_pet_by_id = next(ep for ep in spec.endpoints if ep.path == "/pets/{petId}")
        param_names = [p.name for p in get_pet_by_id.parameters]
        assert "petId" in param_names
        pet_id_param = next(p for p in get_pet_by_id.parameters if p.name == "petId")
        assert pet_id_param.location == "path"
        assert pet_id_param.required is True

    def test_header_params_swagger20(self):
        parser = OpenAPIParser()
        spec = parser.parse(_SWAGGER_20_SPEC)

        get_users = next(ep for ep in spec.endpoints if ep.path == "/users" and ep.method == "GET")
        header_params = [p for p in get_users.parameters if p.location == "header"]
        assert len(header_params) == 1
        assert header_params[0].name == "X-Request-ID"


class TestExtractRequestBodySchema:
    def test_openapi3_request_body(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_30_SPEC)

        post_pets = next(ep for ep in spec.endpoints if ep.path == "/pets" and ep.method == "POST")
        assert post_pets.request_body_type == "application/json"
        assert post_pets.request_body_required is True
        assert "properties" in post_pets.request_body_schema
        assert "name" in post_pets.request_body_schema["properties"]


# ---------------------------------------------------------------------------
# Security schemes
# ---------------------------------------------------------------------------


class TestExtractSecuritySchemes:
    def test_bearer_scheme(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_30_SPEC)
        assert "bearerAuth" in spec.security_schemes
        assert spec.security_schemes["bearerAuth"]["type"] == "http"
        assert spec.security_schemes["bearerAuth"]["scheme"] == "bearer"

    def test_api_key_scheme(self):
        parser = OpenAPIParser()
        spec = parser.parse(_SWAGGER_20_SPEC)
        assert "api_key" in spec.security_schemes
        assert spec.security_schemes["api_key"]["type"] == "apiKey"

    def test_basic_scheme(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_31_SPEC)
        assert "basicAuth" in spec.security_schemes
        assert spec.security_schemes["basicAuth"]["scheme"] == "basic"


# ---------------------------------------------------------------------------
# Fetch and parse
# ---------------------------------------------------------------------------


class TestFetchAndParseJson:
    @pytest.mark.asyncio
    async def test_fetch_json_spec(self):
        """fetch_and_parse correctly fetches and parses a JSON spec."""
        parser = OpenAPIParser()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_OPENAPI_30_SPEC)

        transport = httpx.MockTransport(handler)

        async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
            data = await parser._try_fetch(client, "https://api.example.com/openapi.json")

        assert data is not None
        spec = parser.parse(data)
        assert spec.title == "Pet Store"
        assert spec.total_endpoints == 3


class TestFetchAndParseYaml:
    @pytest.mark.asyncio
    async def test_fetch_yaml_spec(self):
        """fetch_and_parse correctly handles YAML response."""
        parser = OpenAPIParser()
        yaml_content = yaml.dump(_OPENAPI_30_SPEC)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=yaml_content, headers={"Content-Type": "text/yaml"})

        transport = httpx.MockTransport(handler)

        async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
            data = await parser._try_fetch(client, "https://api.example.com/openapi.yaml")

        assert data is not None
        spec = parser.parse(data)
        assert spec.title == "Pet Store"


class TestFetchFallbackPaths:
    @pytest.mark.asyncio
    async def test_html_triggers_fallback(self):
        """When main URL returns HTML, fallback paths are tried."""
        parser = OpenAPIParser()

        request_urls = []

        def handler(request: httpx.Request) -> httpx.Response:
            request_urls.append(str(request.url))
            path = request.url.path

            if path == "/swagger.json":
                return httpx.Response(200, json=_OPENAPI_30_SPEC)
            # Default: return HTML (triggers fallback)
            return httpx.Response(200, text="<!DOCTYPE html><html><body>Swagger UI</body></html>")

        transport = httpx.MockTransport(handler)

        async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
            data = await parser._fetch_spec(client, "https://api.example.com/docs")

        assert data is not None
        # The first request was HTML, so fallbacks were tried
        assert any("/swagger.json" in u for u in request_urls)


# ---------------------------------------------------------------------------
# to_crawl_format
# ---------------------------------------------------------------------------


class TestToCrawlFormat:
    def test_crawl_format_output(self):
        parser = OpenAPIParser()
        spec = parser.parse(_OPENAPI_30_SPEC, base_url="https://api.example.com")

        crawl = parser.to_crawl_format(spec, target_base="https://api.example.com")

        assert crawl["crawler"] == "openapi"
        assert crawl["openapi_source"] is True
        assert crawl["spec_title"] == "Pet Store"
        assert len(crawl["urls"]) > 0
        assert len(crawl["api_endpoints"]) == 3
        assert crawl["total_endpoints"] == 3

        # Each endpoint entry has required keys
        for ep in crawl["api_endpoints"]:
            assert "url" in ep
            assert "method" in ep
            assert "parameters" in ep
            assert "auth_required" in ep


# ---------------------------------------------------------------------------
# Invalid spec handling
# ---------------------------------------------------------------------------


class TestInvalidSpecHandling:
    def test_malformed_string(self):
        """Non-dict input returns empty OpenAPISpec."""
        parser = OpenAPIParser()
        spec = parser.parse("not a dict")  # type: ignore
        assert spec.total_endpoints == 0
        assert spec.endpoints == []

    def test_missing_version_key(self):
        """Dict without 'swagger' or 'openapi' returns empty spec."""
        parser = OpenAPIParser()
        spec = parser.parse({"info": {"title": "Bad Spec"}})
        assert spec.total_endpoints == 0

    def test_empty_dict(self):
        parser = OpenAPIParser()
        spec = parser.parse({})
        assert spec.total_endpoints == 0

    @pytest.mark.asyncio
    async def test_try_fetch_bad_json(self):
        """Non-JSON non-YAML response returns None."""
        parser = OpenAPIParser()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="this is not json or yaml: {{{[[[")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            data = await parser._try_fetch(client, "https://example.com/spec")

        assert data is None

    @pytest.mark.asyncio
    async def test_try_fetch_404(self):
        """HTTP 404 returns None."""
        parser = OpenAPIParser()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            data = await parser._try_fetch(client, "https://example.com/openapi.json")

        assert data is None
