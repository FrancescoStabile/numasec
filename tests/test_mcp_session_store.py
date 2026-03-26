"""Tests for McpSessionStore — MCP v2.0 CRUD session store."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_mcp.mcp.mcp_session_store import McpSessionStore, _McpSession
from security_mcp.models.enums import Severity
from security_mcp.models.finding import Finding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_mcp_store.db"


@pytest.fixture
async def store(tmp_db: Path) -> McpSessionStore:
    """Fresh McpSessionStore backed by a temp SQLite DB."""
    return McpSessionStore(db_path=str(tmp_db))


def _make_finding(title: str = "SQL Injection", url: str = "https://example.com/login") -> Finding:
    return Finding(
        title=title,
        severity=Severity.HIGH,
        url=url,
        cwe_id="CWE-89",
        evidence="' OR 1=1--",
        description=title,
    )


# ---------------------------------------------------------------------------
# _McpSession dataclass
# ---------------------------------------------------------------------------


class TestMcpSession:
    def test_defaults(self) -> None:
        s = _McpSession(session_id="mcp-abc123", target="https://example.com")
        assert s.scope == "manual"
        assert s.status == "active"
        assert s.total_cost_usd == 0.0
        assert s.findings == []
        assert s.events == []
        assert s.plan is None
        assert s.profile is None
        assert s._saved_event_count == 0

    def test_custom_fields(self) -> None:
        s = _McpSession(session_id="mcp-xyz", target="https://test.com", scope="standard", status="completed")
        assert s.scope == "standard"
        assert s.status == "completed"

    def test_findings_are_independent_per_instance(self) -> None:
        s1 = _McpSession(session_id="s1", target="a")
        s2 = _McpSession(session_id="s2", target="b")
        s1.findings.append("x")
        assert len(s2.findings) == 0


# ---------------------------------------------------------------------------
# McpSessionStore.create()
# ---------------------------------------------------------------------------


class TestCreate:
    async def test_returns_mcp_prefixed_id(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        assert sid.startswith("mcp-")
        assert len(sid) == 12  # "mcp-" + 8 hex chars

    async def test_session_in_active_cache(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        assert sid in store._active

    async def test_persists_to_sqlite(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        # Evict from memory and load from SQLite
        del store._active[sid]
        session = await store.get_session(sid)
        assert session is not None
        assert session["target"] == "https://example.com"

    async def test_each_call_returns_unique_id(self, store: McpSessionStore) -> None:
        ids = {await store.create(target="https://example.com") for _ in range(5)}
        assert len(ids) == 5


# ---------------------------------------------------------------------------
# McpSessionStore.add_finding()
# ---------------------------------------------------------------------------


class TestAddFinding:
    async def test_returns_finding_id(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        f = _make_finding()
        result = await store.add_finding(sid, f)
        assert result == f.id

    async def test_finding_in_memory(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        f = _make_finding()
        await store.add_finding(sid, f)
        assert len(store._active[sid].findings) == 1

    async def test_multiple_findings(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        for i in range(3):
            await store.add_finding(sid, _make_finding(title=f"Finding {i}"))
        assert len(store._active[sid].findings) == 3

    async def test_unknown_session_raises(self, store: McpSessionStore) -> None:
        with pytest.raises(KeyError):
            await store.add_finding("mcp-unknown", _make_finding())


# ---------------------------------------------------------------------------
# McpSessionStore.get_findings()
# ---------------------------------------------------------------------------


class TestGetFindings:
    async def test_empty_for_new_session(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        findings = await store.get_findings(sid)
        assert findings == []

    async def test_returns_from_memory(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        f = _make_finding()
        await store.add_finding(sid, f)
        findings = await store.get_findings(sid)
        assert len(findings) == 1
        assert findings[0].id == f.id

    async def test_falls_back_to_sqlite(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        f = _make_finding()
        await store.add_finding(sid, f)
        # Evict from memory cache
        del store._active[sid]
        findings = await store.get_findings(sid)
        assert len(findings) == 1
        assert findings[0].title == f.title

    async def test_unknown_session_raises(self, store: McpSessionStore) -> None:
        with pytest.raises(KeyError):
            await store.get_findings("mcp-does-not-exist")


# ---------------------------------------------------------------------------
# McpSessionStore.get_session()
# ---------------------------------------------------------------------------


class TestGetSession:
    async def test_returns_metadata_from_memory(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        meta = await store.get_session(sid)
        assert meta is not None
        assert meta["session_id"] == sid
        assert meta["target"] == "https://example.com"
        assert meta["status"] == "active"
        assert meta["finding_count"] == 0

    async def test_finding_count_reflects_additions(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        await store.add_finding(sid, _make_finding())
        await store.add_finding(sid, _make_finding(title="XSS"))
        meta = await store.get_session(sid)
        assert meta is not None
        assert meta["finding_count"] == 2

    async def test_returns_from_sqlite(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        del store._active[sid]
        meta = await store.get_session(sid)
        assert meta is not None
        assert meta["session_id"] == sid

    async def test_unknown_returns_none(self, store: McpSessionStore) -> None:
        meta = await store.get_session("mcp-unknown")
        assert meta is None


# ---------------------------------------------------------------------------
# McpSessionStore.complete()
# ---------------------------------------------------------------------------


class TestComplete:
    async def test_sets_status_completed(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        await store.complete(sid)
        meta = await store.get_session(sid)
        assert meta is not None
        assert meta["status"] == "completed"

    async def test_evicts_from_memory(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        await store.complete(sid)
        assert sid not in store._active

    async def test_persists_findings_on_complete(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        f = _make_finding()
        await store.add_finding(sid, f)
        await store.complete(sid)
        # After complete, session is evicted from memory — load from SQLite
        findings = await store.get_findings(sid)
        assert len(findings) == 1
        assert findings[0].title == f.title

    async def test_unknown_session_raises(self, store: McpSessionStore) -> None:
        with pytest.raises(KeyError):
            await store.complete("mcp-unknown")


# ---------------------------------------------------------------------------
# McpSessionStore.list_sessions()
# ---------------------------------------------------------------------------


class TestListSessions:
    async def test_returns_list(self, store: McpSessionStore) -> None:
        await store.create(target="https://a.com")
        await store.create(target="https://b.com")
        sessions = await store.list_sessions()
        assert len(sessions) >= 2

    async def test_limit_respected(self, store: McpSessionStore) -> None:
        for i in range(5):
            await store.create(target=f"https://target{i}.com")
        sessions = await store.list_sessions(limit=3)
        assert len(sessions) <= 3


# ---------------------------------------------------------------------------
# McpSessionStore._ensure_session()
# ---------------------------------------------------------------------------


class TestEnsureSession:
    async def test_returns_from_memory(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        session = await store._ensure_session(sid)
        assert session.session_id == sid

    async def test_loads_from_sqlite_on_cache_miss(self, store: McpSessionStore) -> None:
        sid = await store.create(target="https://example.com")
        del store._active[sid]
        session = await store._ensure_session(sid)
        assert session.session_id == sid
        assert session.target == "https://example.com"
        # Re-cached
        assert sid in store._active

    async def test_raises_for_unknown(self, store: McpSessionStore) -> None:
        with pytest.raises(KeyError):
            await store._ensure_session("mcp-does-not-exist")


# ---------------------------------------------------------------------------
# Integration: full assessment lifecycle
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    async def test_create_add_complete_retrieve(self, store: McpSessionStore) -> None:
        # 1. Create session
        sid = await store.create(target="https://vulnerable.example.com")
        assert sid.startswith("mcp-")

        # 2. Add several findings
        f1 = _make_finding("SQL Injection", "https://vulnerable.example.com/login")
        f2 = _make_finding("XSS", "https://vulnerable.example.com/search")
        await store.add_finding(sid, f1)
        await store.add_finding(sid, f2)

        # 3. Check state mid-assessment
        meta = await store.get_session(sid)
        assert meta is not None
        assert meta["finding_count"] == 2
        assert meta["status"] == "active"

        # 4. Complete
        await store.complete(sid)
        assert sid not in store._active

        # 5. Retrieve from SQLite
        findings = await store.get_findings(sid)
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert titles == {"SQL Injection", "XSS"}

        meta_done = await store.get_session(sid)
        assert meta_done is not None
        assert meta_done["status"] == "completed"

    async def test_multiple_independent_sessions(self, store: McpSessionStore) -> None:
        sid1 = await store.create(target="https://target1.com")
        sid2 = await store.create(target="https://target2.com")

        await store.add_finding(sid1, _make_finding("F1-A"))
        await store.add_finding(sid1, _make_finding("F1-B"))
        await store.add_finding(sid2, _make_finding("F2-A"))

        assert len(await store.get_findings(sid1)) == 2
        assert len(await store.get_findings(sid2)) == 1
