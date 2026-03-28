"""Simple CRUD session store for MCP v2.0.

McpSessionStore replaces the heavyweight SessionManager for the MCP server path.
It is a thin wrapper over CheckpointStore: create → add_finding × N → complete,
all persisted synchronously (no asyncio.Task, no asyncio.Event).

The host LLM drives the assessment; McpSessionStore only holds state between calls.
Zero background tasks = zero hangs.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("numasec.mcp.mcp_session_store")


@dataclass
class _McpSession:
    """Minimal session object compatible with CheckpointStore.save().

    Uses the same duck-typed interface as SessionState so CheckpointStore
    can persist both without knowing which type it receives.
    """

    session_id: str
    target: str
    scope: str = "manual"
    status: str = "active"
    total_cost_usd: float = 0.0
    findings: list[Any] = field(default_factory=list)
    events: list[Any] = field(default_factory=list)
    plan: None = None
    profile: None = None
    _saved_event_count: int = 0


class McpSessionStore:
    """CRUD session store for MCP assessments.

    Each MCP assessment has a simple lifecycle::

        session_id = await store.create(target="https://example.com")
        await store.add_finding(session_id, finding)   # repeat for each finding
        await store.complete(session_id)
        report = await store.get_findings(session_id)

    Backed by CheckpointStore (SQLite, 3-table schema).
    All methods are async for consistency with the rest of the codebase.
    """

    def __init__(self, db_path: str | None = None) -> None:
        from pathlib import Path

        from numasec.storage.checkpoint import CheckpointStore

        self._store = CheckpointStore(db_path=Path(db_path) if db_path else None)
        # In-memory cache: session_id → _McpSession (only active sessions)
        self._active: dict[str, _McpSession] = {}

    async def create(self, target: str) -> str:
        """Create a new MCP assessment session.

        Args:
            target: Target URL or hostname for this assessment.

        Returns:
            Unique session_id ("mcp-{8hex}").
        """
        session_id = f"mcp-{uuid.uuid4().hex[:8]}"
        session = _McpSession(session_id=session_id, target=target)
        self._active[session_id] = session
        await self._store.save(session)
        logger.info("MCP session created: %s (target=%s)", session_id, target)
        return session_id

    async def add_finding(self, session_id: str, finding: Any) -> str:
        """Add a finding to a session and persist immediately.

        Args:
            session_id: Session to add the finding to.
            finding:    Finding object (must have .id attribute).

        Returns:
            finding_id: The finding's unique ID.
        """
        session = await self._ensure_session(session_id)
        session.findings.append(finding)
        await self._store.save(session)
        logger.info("Finding added to %s: %s", session_id, finding.id)
        return finding.id

    async def build_chains(self, session_id: str) -> dict[str, list[str]]:
        """Auto-detect and assign attack chains based on URL/parameter overlap.

        Findings sharing the same target URL base path are grouped into chains.
        Findings with explicit ``related_finding_ids`` are merged into the same chain.

        Returns:
            Dict mapping chain_id → list of finding IDs in the chain.
        """
        findings = await self.get_findings(session_id)
        if not findings:
            return {}

        from urllib.parse import urlparse

        # Group findings by URL base (scheme + netloc + first path segment)
        url_groups: dict[str, list[Any]] = {}
        for f in findings:
            url = getattr(f, "url", "") or ""
            if not url:
                continue
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}"
            url_groups.setdefault(base, []).append(f)

        chains: dict[str, list[str]] = {}
        chain_counter = 0

        # Merge related_finding_ids into same chain
        id_to_chain: dict[str, str] = {}
        for f in findings:
            fid = getattr(f, "id", "")
            existing_chain = getattr(f, "chain_id", "")
            if existing_chain:
                id_to_chain[fid] = existing_chain

        # Build chains from URL groups (only multi-finding groups)
        for _base, group in url_groups.items():
            if len(group) < 2:
                continue
            chain_counter += 1
            cid = f"chain-{chain_counter}"

            # Check if any finding in this group already has a chain_id
            existing = {id_to_chain[g.id] for g in group if g.id in id_to_chain}
            if existing:
                cid = existing.pop()

            fids = []
            for f in group:
                f.chain_id = cid
                id_to_chain[f.id] = cid
                fids.append(f.id)
            chains[cid] = fids

        # Merge chains connected by related_finding_ids
        for f in findings:
            related = getattr(f, "related_finding_ids", []) or []
            if not related:
                continue
            fid = getattr(f, "id", "")
            my_chain = id_to_chain.get(fid)
            for rid in related:
                other_chain = id_to_chain.get(rid)
                if my_chain and other_chain and my_chain != other_chain:
                    # Merge other_chain into my_chain
                    for merge_f in findings:
                        if getattr(merge_f, "chain_id", "") == other_chain:
                            merge_f.chain_id = my_chain
                    if other_chain in chains:
                        chains.setdefault(my_chain, []).extend(chains.pop(other_chain))
                elif my_chain and not other_chain:
                    for merge_f in findings:
                        if getattr(merge_f, "id", "") == rid:
                            merge_f.chain_id = my_chain
                            chains.setdefault(my_chain, []).append(rid)
                            id_to_chain[rid] = my_chain

        # Persist updated chain_ids
        if chains:
            session = await self._ensure_session(session_id)
            await self._store.save(session)
            logger.info("Built %d attack chains in session %s", len(chains), session_id)

        return chains

    async def get_findings(self, session_id: str) -> list[Any]:
        """Return all findings for a session.

        Checks in-memory cache first; falls back to SQLite for completed sessions.

        Args:
            session_id: Session to retrieve findings from.

        Returns:
            List of Finding objects.

        Raises:
            KeyError: If the session is not found.
        """
        if session_id in self._active:
            return list(self._active[session_id].findings)

        # Load from SQLite (completed or cross-process session)
        data = await self._store.load(session_id)
        from numasec.models.finding import Finding

        findings = []
        for fd in data.get("findings", []):
            try:
                findings.append(Finding(**fd))
            except Exception:
                continue
        return findings

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Return session metadata dict, or None if not found.

        Args:
            session_id: Session to look up.

        Returns:
            Dict with session metadata, or None if not found.
        """
        if session_id in self._active:
            s = self._active[session_id]
            return {
                "session_id": s.session_id,
                "target": s.target,
                "scope": s.scope,
                "status": s.status,
                "total_cost_usd": s.total_cost_usd,
                "finding_count": len(s.findings),
            }
        try:
            data = await self._store.load(session_id)
            return {
                "session_id": data["session_id"],
                "target": data.get("target", ""),
                "scope": data.get("scope", "manual"),
                "status": data.get("status", "completed"),
                "total_cost_usd": data.get("total_cost_usd", 0.0),
                "finding_count": len(data.get("findings", [])),
            }
        except KeyError:
            return None

    async def add_event(self, session_id: str, event_type: str, data: dict[str, Any]) -> None:
        """Append an event to a session.

        Args:
            session_id: Session to add the event to.
            event_type: Event type string (e.g., "credential_relay").
            data:       Event payload dict.
        """
        from datetime import UTC, datetime
        from types import SimpleNamespace

        session = await self._ensure_session(session_id)
        event = SimpleNamespace(
            event_type=event_type,
            data=data,
            timestamp=datetime.now(UTC),
        )
        session.events.append(event)
        await self._store.save(session)
        logger.debug("Event added: type=%s session=%s", event_type, session_id)

    async def get_events(self, session_id: str, event_type: str = "") -> list[dict[str, Any]]:
        """Get events for a session, optionally filtered by type.

        Args:
            session_id: Session to query.
            event_type: Filter by event type. Empty string = all events.
        """
        session = await self._ensure_session(session_id)
        events = []
        for evt in session.events:
            etype = evt.event_type.value if hasattr(evt.event_type, "value") else str(evt.event_type)
            if event_type and etype != event_type:
                continue
            events.append({"event_type": etype, "data": evt.data})
        return events

    async def complete(self, session_id: str) -> None:
        """Mark a session as completed and persist the final state.

        Args:
            session_id: Session to complete.
        """
        session = await self._ensure_session(session_id)
        session.status = "completed"
        await self._store.save(session)
        self._active.pop(session_id, None)
        logger.info("MCP session completed: %s (%d findings)", session_id, len(session.findings))

    async def list_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent sessions with summary info.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            List of session summary dicts, newest first.
        """
        return await self._store.list_sessions(limit=limit)

    async def _ensure_session(self, session_id: str) -> _McpSession:
        """Return the in-memory session, loading from SQLite if needed.

        Args:
            session_id: Session to look up.

        Returns:
            _McpSession instance.

        Raises:
            KeyError: If the session is not found in memory or SQLite.
        """
        if session_id in self._active:
            return self._active[session_id]

        # Try to load from SQLite (session created in a previous process/restart)
        data = await self._store.load(session_id)  # raises KeyError if not found
        session = _McpSession(
            session_id=data["session_id"],
            target=data.get("target", ""),
            scope=data.get("scope", "manual"),
            status=data.get("status", "active"),
            total_cost_usd=data.get("total_cost_usd", 0.0),
        )
        # Hydrate findings from SQLite JSON
        from numasec.models.finding import Finding

        for fd in data.get("findings", []):
            try:
                session.findings.append(Finding(**fd))
            except Exception:
                continue
        self._active[session_id] = session
        return session
