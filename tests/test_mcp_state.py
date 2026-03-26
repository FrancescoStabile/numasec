"""Tests for security_mcp.mcp.state_tools — MCP v2.0 state management and reporting.

v2.0 API:
  - create_session(target) → session_id (required before save_finding)
  - save_finding(session_id, title, severity, ...) — session_id is now required
  - get_findings(session_id, ...) — session_id is required
  - generate_report(session_id, format) — session_id is required
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_mcp.mcp import state_tools


class _FakeMCP:
    """Minimal stub that captures tool registrations."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *, name: str, description: str = ""):
        def decorator(fn):
            self.tools[name] = fn
            return fn
        return decorator


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_state_tools.db"


@pytest.fixture
async def store(tmp_db: Path):
    """Fresh McpSessionStore backed by a temp SQLite DB."""
    from security_mcp.mcp.mcp_session_store import McpSessionStore
    return McpSessionStore(db_path=str(tmp_db))


@pytest.fixture(autouse=True)
def patch_mcp_store(store, monkeypatch):
    """Patch get_mcp_session_store to return the test-local McpSessionStore."""
    monkeypatch.setattr(
        "security_mcp.mcp._singletons.get_mcp_session_store",
        lambda: store,
    )
    yield


@pytest.fixture
def mcp():
    """FakeMCP with state tools registered."""
    fake = _FakeMCP()
    state_tools.register(fake)
    return fake


# ── create_session ───────────────────────────────────────────────────────


class TestCreateSession:
    async def test_returns_session_id(self, mcp):
        result = json.loads(await mcp.tools["create_session"](target="https://example.com"))
        assert result["session_id"].startswith("mcp-")
        assert result["target"] == "https://example.com"
        assert result["status"] == "active"

    async def test_includes_instructions(self, mcp):
        result = json.loads(await mcp.tools["create_session"](target="https://example.com"))
        assert "message" in result
        assert result["session_id"] in result["message"]

    async def test_unique_ids_per_call(self, mcp):
        r1 = json.loads(await mcp.tools["create_session"](target="https://a.com"))
        r2 = json.loads(await mcp.tools["create_session"](target="https://b.com"))
        assert r1["session_id"] != r2["session_id"]


# ── save_finding ─────────────────────────────────────────────────────────


class TestSaveFinding:
    async def _create_session(self, mcp, target: str = "http://target") -> str:
        return json.loads(await mcp.tools["create_session"](target=target))["session_id"]

    async def test_creates_finding(self, mcp):
        sid = await self._create_session(mcp)
        result = json.loads(
            await mcp.tools["save_finding"](
                session_id=sid,
                title="SQL Injection in /api/users",
                severity="critical",
                url="http://target/api/users",
                cwe="CWE-89",
                evidence="Error-based SQLi response",
                parameter="id",
            )
        )
        assert result["severity"] == "critical"
        assert result["total_findings"] == 1
        assert result["finding_id"].startswith("SSEC-")
        assert result["session_id"] == sid
        # Enrichment should populate CVSS, OWASP, ATT&CK from CWE-89
        enriched = result["enriched"]
        assert enriched["cwe_id"] == "CWE-89"
        assert enriched["cvss_score"] is not None
        assert enriched["cvss_score"] > 0
        assert enriched["cvss_vector"].startswith("CVSS:3.1/")
        assert "Injection" in enriched["owasp_category"]

    async def test_enrichment_infers_cwe_from_title(self, mcp):
        """When no CWE is provided, enrichment infers it from the title."""
        sid = await self._create_session(mcp)
        result = json.loads(
            await mcp.tools["save_finding"](
                session_id=sid,
                title="SQL Injection in login form",
                severity="high",
                url="http://target/login",
            )
        )
        enriched = result["enriched"]
        # Should infer CWE-89 from "SQL Injection" in title
        assert enriched["cwe_id"] != ""
        assert enriched["owasp_category"] != ""

    async def test_enrichment_severity_fallback(self, mcp):
        """When CWE is unknown, enrichment falls back to severity-based CVSS."""
        sid = await self._create_session(mcp)
        result = json.loads(
            await mcp.tools["save_finding"](
                session_id=sid,
                title="Custom vulnerability with no CWE match",
                severity="medium",
            )
        )
        enriched = result["enriched"]
        assert enriched["cvss_score"] is not None

    async def test_auto_generates_finding_id(self, mcp):
        sid = await self._create_session(mcp)
        result = json.loads(
            await mcp.tools["save_finding"](
                session_id=sid,
                title="XSS in search",
                severity="high",
            )
        )
        assert result["finding_id"].startswith("SSEC-")

    async def test_default_severity_maps_unknown_to_info(self, mcp, store):
        sid = await self._create_session(mcp)
        result = json.loads(
            await mcp.tools["save_finding"](
                session_id=sid,
                title="Server version disclosed",
                severity="unknown_value",
            )
        )
        findings = await store.get_findings(sid)
        assert findings[0].severity.value == "info"

    async def test_accumulates_multiple_findings(self, mcp):
        sid = await self._create_session(mcp)
        await mcp.tools["save_finding"](
            session_id=sid, title="Finding 1", severity="low",
        )
        r2 = json.loads(
            await mcp.tools["save_finding"](
                session_id=sid, title="Finding 2", severity="medium",
            )
        )
        assert r2["total_findings"] == 2

    async def test_unknown_session_returns_error(self, mcp):
        result = json.loads(
            await mcp.tools["save_finding"](
                session_id="mcp-does-not-exist",
                title="Test",
                severity="low",
            )
        )
        assert "error" in result


# ── get_findings ─────────────────────────────────────────────────────────


class TestGetFindings:
    async def _populate_session(self, mcp, target: str = "http://t") -> str:
        sid = json.loads(await mcp.tools["create_session"](target=target))["session_id"]
        await mcp.tools["save_finding"](
            session_id=sid, title="Finding A", severity="critical", url=f"{target}/a",
        )
        await mcp.tools["save_finding"](
            session_id=sid, title="Finding B", severity="low", url=f"{target}/b",
        )
        return sid

    async def test_returns_all_findings(self, mcp):
        sid = await self._populate_session(mcp)
        result = json.loads(await mcp.tools["get_findings"](session_id=sid))
        assert result["summary"]["total"] == 2
        assert result["summary"]["filtered"] == 2
        assert len(result["findings"]) == 2

    async def test_severity_filter(self, mcp):
        sid = await self._populate_session(mcp)
        result = json.loads(
            await mcp.tools["get_findings"](session_id=sid, severity_filter="critical")
        )
        assert result["summary"]["total"] == 2
        assert result["summary"]["filtered"] == 1
        assert result["findings"][0]["severity"] == "critical"

    async def test_unknown_session_returns_error(self, mcp):
        result = json.loads(await mcp.tools["get_findings"](session_id="mcp-unknown"))
        assert "error" in result

    async def test_empty_session_returns_empty_findings(self, mcp):
        sid = json.loads(await mcp.tools["create_session"](target="http://empty"))["session_id"]
        result = json.loads(await mcp.tools["get_findings"](session_id=sid))
        assert result["summary"]["total"] == 0
        assert result["findings"] == []


# ── generate_report ──────────────────────────────────────────────────────


class TestGenerateReport:
    async def _populate_session(self, mcp) -> str:
        sid = json.loads(await mcp.tools["create_session"](target="http://target"))["session_id"]
        await mcp.tools["save_finding"](
            session_id=sid,
            title="SQL Injection in login",
            severity="critical",
            url="http://target/login",
            cwe="CWE-89",
            evidence="union select",
        )
        await mcp.tools["save_finding"](
            session_id=sid,
            title="Missing X-Frame-Options",
            severity="low",
            url="http://target/",
        )
        return sid

    async def test_sarif_format(self, mcp):
        sid = await self._populate_session(mcp)
        result = json.loads(await mcp.tools["generate_report"](session_id=sid, format="sarif"))
        assert result["format"] == "sarif"
        assert result["findings_count"] == 2
        content = result["content"]
        assert "runs" in content
        assert len(content["runs"][0]["results"]) == 2

    async def test_markdown_format(self, mcp):
        sid = await self._populate_session(mcp)
        result = json.loads(await mcp.tools["generate_report"](session_id=sid, format="markdown"))
        assert result["format"] == "markdown"
        assert result["findings_count"] == 2
        assert "security-mcp Security Assessment Report" in result["content"]
        assert "SQL Injection in login" in result["content"]

    async def test_json_format(self, mcp):
        sid = await self._populate_session(mcp)
        result = json.loads(await mcp.tools["generate_report"](session_id=sid, format="json"))
        assert result["format"] == "json"
        assert result["findings_count"] == 2
        assert result["session_id"] == sid
        titles = {f["title"] for f in result["findings"]}
        assert "SQL Injection in login" in titles
        assert "Missing X-Frame-Options" in titles

    async def test_unknown_session_returns_error(self, mcp):
        result = json.loads(await mcp.tools["generate_report"](session_id="mcp-unknown", format="sarif"))
        assert "error" in result
