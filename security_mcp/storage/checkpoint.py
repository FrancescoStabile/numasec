"""SQLite-based session persistence with checkpointing and resume."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path.home() / ".security_mcp"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "sessions.db"

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'quick',
    status TEXT NOT NULL DEFAULT 'running',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    total_cost_usd REAL DEFAULT 0.0,
    plan_json TEXT,
    profile_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cwe_id TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    url TEXT DEFAULT '',
    confidence REAL DEFAULT 0.5,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    event_type TEXT NOT NULL,
    data_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_cache (
    cache_key TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 3600
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_cache_tool ON tool_cache(tool_name);
"""


class CheckpointStore:
    """SQLite-based session persistence with checkpointing."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._initialized = False

    async def _ensure_db(self) -> aiosqlite.Connection:
        """Create DB and apply schema if needed.

        WAL mode is enabled for concurrent access:
        readers never block writers, writers never block readers.
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(self._db_path))
        # WAL: concurrent readers/writers without SQLITE_BUSY
        await db.execute("PRAGMA journal_mode=WAL")
        # NORMAL: fsync only at WAL checkpoint, not every commit (~3x faster)
        await db.execute("PRAGMA synchronous=NORMAL")
        # 64 MB page cache — scans write many small rows
        await db.execute("PRAGMA cache_size=-64000")
        # Retry for up to 5 s on a locked page instead of raising immediately
        await db.execute("PRAGMA busy_timeout=5000")
        if not self._initialized:
            await db.executescript(_SCHEMA)
            await db.commit()
            self._initialized = True
        return db

    async def save(self, state: Any) -> None:
        """Save or update session state to DB.

        Upserts the session row, all findings, and appends new events.
        """
        db = await self._ensure_db()
        try:
            now = datetime.now(UTC).isoformat()

            plan_json = None
            if state.plan is not None:
                if hasattr(state.plan, "model_dump"):
                    plan_json = json.dumps(state.plan.model_dump(), default=str)
                else:
                    plan_json = json.dumps(
                        {"target": getattr(state.plan, "target", ""), "scope": getattr(state.plan, "scope", "quick")},
                        default=str,
                    )

            profile_json = None
            if hasattr(state, "profile") and state.profile is not None and hasattr(state.profile, "model_dump"):
                profile_json = json.dumps(state.profile.model_dump(), default=str)

            await db.execute(
                """INSERT INTO sessions
                   (session_id, target, scope, status, created_at, updated_at,
                    total_cost_usd, plan_json, profile_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(session_id) DO UPDATE SET
                       status=excluded.status,
                       updated_at=excluded.updated_at,
                       total_cost_usd=excluded.total_cost_usd,
                       plan_json=excluded.plan_json,
                       profile_json=excluded.profile_json""",
                (
                    state.session_id,
                    state.target,
                    getattr(state, "scope", "quick"),
                    getattr(state, "status", "running"),
                    now,
                    now,
                    state.total_cost_usd,
                    plan_json,
                    profile_json,
                ),
            )

            for finding in state.findings:
                data_json = json.dumps(finding.model_dump(), default=str)
                await db.execute(
                    """INSERT INTO findings
                       (finding_id, session_id, title, severity, cwe_id,
                        evidence, url, confidence, data_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(finding_id) DO UPDATE SET
                           data_json=excluded.data_json""",
                    (
                        finding.id,
                        state.session_id,
                        finding.title,
                        finding.severity.value,
                        finding.cwe_id,
                        finding.evidence[:2000],
                        finding.url,
                        finding.confidence,
                        data_json,
                        now,
                    ),
                )

            events = getattr(state, "events", [])
            saved_count = getattr(state, "_saved_event_count", 0)
            for event in events[saved_count:]:
                evt_type = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
                await db.execute(
                    "INSERT INTO events (session_id, event_type, data_json, created_at) VALUES (?, ?, ?, ?)",
                    (
                        state.session_id,
                        evt_type,
                        json.dumps(event.data, default=str),
                        event.timestamp.isoformat(),
                    ),
                )
            state._saved_event_count = len(events)

            await db.commit()
            logger.info(
                "Checkpoint saved: session=%s, findings=%d, events=%d",
                state.session_id,
                len(state.findings),
                len(events),
            )
        finally:
            await db.close()

    async def load(self, session_id: str) -> dict[str, Any]:
        """Load session data from DB.

        Returns a dict with session metadata, findings, and events.
        """
        db = await self._ensure_db()
        try:
            async with db.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)) as cursor:
                row = await cursor.fetchone()
                if not row:
                    raise KeyError(f"Session not found: {session_id}")
                columns = [d[0] for d in cursor.description]
                session = dict(zip(columns, row, strict=False))

            findings: list[dict[str, Any]] = []
            async with db.execute(
                "SELECT data_json FROM findings WHERE session_id = ? ORDER BY created_at",
                (session_id,),
            ) as cursor:
                async for row in cursor:
                    findings.append(json.loads(row[0]))

            events: list[dict[str, Any]] = []
            async with db.execute(
                "SELECT event_type, data_json, created_at FROM events WHERE session_id = ? ORDER BY event_id",
                (session_id,),
            ) as cursor:
                async for row in cursor:
                    events.append({"event_type": row[0], "data": json.loads(row[1]), "created_at": row[2]})

            session["findings"] = findings
            session["events"] = events
            if session.get("plan_json"):
                session["plan"] = json.loads(session["plan_json"])
            if session.get("profile_json"):
                session["profile"] = json.loads(session["profile_json"])

            return session
        finally:
            await db.close()

    async def list_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent sessions with summary info."""
        db = await self._ensure_db()
        try:
            results: list[dict[str, Any]] = []
            async with db.execute(
                """SELECT s.session_id, s.target, s.scope, s.status,
                          s.created_at, s.updated_at, s.total_cost_usd,
                          (SELECT COUNT(*) FROM findings f
                           WHERE f.session_id = s.session_id) AS finding_count
                   FROM sessions s
                   ORDER BY s.updated_at DESC LIMIT ?""",
                (limit,),
            ) as cursor:
                async for row in cursor:
                    columns = [d[0] for d in cursor.description]
                    results.append(dict(zip(columns, row, strict=False)))
            return results
        finally:
            await db.close()

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session and all associated data."""
        db = await self._ensure_db()
        try:
            await db.execute("DELETE FROM events WHERE session_id = ?", (session_id,))
            await db.execute("DELETE FROM findings WHERE session_id = ?", (session_id,))
            cursor = await db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            await db.commit()
            return cursor.rowcount > 0
        finally:
            await db.close()

    # ------------------------------------------------------------------
    # Tool result caching
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_key(tool: str, target: str, params: dict[str, Any]) -> str:
        """Deterministic cache key from tool + target + params."""
        raw = f"{tool}:{target}:{json.dumps(params, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()

    async def cache_get(
        self, tool: str, target: str, params: dict[str, Any],
    ) -> str | None:
        """Return cached tool result if it exists and has not expired."""
        key = self._cache_key(tool, target, params)
        db = await self._ensure_db()
        try:
            async with db.execute(
                """SELECT result_json, created_at, ttl_seconds
                   FROM tool_cache WHERE cache_key = ?""",
                (key,),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                return None
            created = datetime.fromisoformat(row[1])
            age = (datetime.now(UTC) - created).total_seconds()
            if age > row[2]:
                await db.execute(
                    "DELETE FROM tool_cache WHERE cache_key = ?", (key,),
                )
                await db.commit()
                return None
            logger.debug("Cache hit: %s (age=%.0fs)", tool, age)
            return row[0]
        finally:
            await db.close()

    async def cache_set(
        self,
        tool: str,
        target: str,
        params: dict[str, Any],
        result: str,
        ttl: int = 3600,
    ) -> None:
        """Store a tool result in the cache."""
        key = self._cache_key(tool, target, params)
        now = datetime.now(UTC).isoformat()
        db = await self._ensure_db()
        try:
            await db.execute(
                """INSERT INTO tool_cache
                   (cache_key, tool_name, result_json, created_at, ttl_seconds)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(cache_key) DO UPDATE SET
                       result_json=excluded.result_json,
                       created_at=excluded.created_at,
                       ttl_seconds=excluded.ttl_seconds""",
                (key, tool, result, now, ttl),
            )
            await db.commit()
        finally:
            await db.close()

    async def cache_clear(self, tool: str | None = None) -> int:
        """Clear cached results. If *tool* is given, only that tool's cache."""
        db = await self._ensure_db()
        try:
            if tool:
                cursor = await db.execute(
                    "DELETE FROM tool_cache WHERE tool_name = ?", (tool,),
                )
            else:
                cursor = await db.execute("DELETE FROM tool_cache")
            await db.commit()
            return cursor.rowcount
        finally:
            await db.close()
