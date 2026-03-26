"""Module-level lazy singletons for MCP server performance.

Avoids re-initializing KB and tool registry on every MCP tool call.
First access triggers initialization (~200ms); subsequent accesses
return the cached instance (~0ms).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from security_mcp.knowledge import KnowledgeRetriever
    from security_mcp.mcp.mcp_session_store import McpSessionStore
    from security_mcp.mcp.server import SessionRateLimiter
    from security_mcp.tools._base import ToolRegistry

logger = logging.getLogger(__name__)

_kb_retriever: KnowledgeRetriever | None = None
_tool_registry: ToolRegistry | None = None
_mcp_session_store: McpSessionStore | None = None
_rate_limiter: SessionRateLimiter | None = None


def get_kb() -> KnowledgeRetriever:
    """Return the singleton KnowledgeRetriever, creating on first call."""
    global _kb_retriever
    if _kb_retriever is None:
        from security_mcp.knowledge import KnowledgeChunker, KnowledgeLoader, KnowledgeRetriever

        loader = KnowledgeLoader()
        templates = loader.load_all()
        chunker = KnowledgeChunker()
        chunks = [c for tpl in templates.values() for c in chunker.chunk(tpl)]
        _kb_retriever = KnowledgeRetriever(chunks)
        logger.info(
            "KB singleton initialized: %d templates, %d chunks",
            len(templates),
            len(chunks),
        )
    return _kb_retriever


def get_tool_registry() -> ToolRegistry:
    """Return the singleton ToolRegistry, creating on first call."""
    global _tool_registry
    if _tool_registry is None:
        from security_mcp.tools import create_default_tool_registry

        _tool_registry = create_default_tool_registry()
        logger.info("Tool registry singleton initialized")
    return _tool_registry


def get_mcp_session_store() -> McpSessionStore:
    """Return the singleton McpSessionStore, creating on first call."""
    global _mcp_session_store
    if _mcp_session_store is None:
        from security_mcp.mcp.mcp_session_store import McpSessionStore

        _mcp_session_store = McpSessionStore()
        logger.info("McpSessionStore singleton initialized")
    return _mcp_session_store


def get_rate_limiter() -> SessionRateLimiter:
    """Return the singleton SessionRateLimiter, creating on first call."""
    global _rate_limiter
    if _rate_limiter is None:
        from security_mcp.mcp.server import SessionRateLimiter

        _rate_limiter = SessionRateLimiter()
        logger.info("SessionRateLimiter singleton initialized")
    return _rate_limiter


def reset_all() -> None:
    """Reset all singletons. Used in tests to ensure clean state."""
    global _kb_retriever, _tool_registry, _mcp_session_store, _rate_limiter
    _kb_retriever = None
    _tool_registry = None
    _mcp_session_store = None
    _rate_limiter = None
    logger.debug("All MCP singletons reset")
