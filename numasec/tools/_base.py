"""Tool registry for managing available tools."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)

# Default per-tool execution timeout (seconds)
_TOOL_TIMEOUT = 300


class ToolRegistry:
    """Registry for tool execution backends."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Awaitable[Any]]] = {}
        self._schemas: dict[str, dict] = {}
        self._scope: set[str] | None = None

    def register(self, name: str, func: Callable[..., Awaitable[Any]], schema: dict | None = None) -> None:
        """Register a tool function."""
        self._tools[name] = func
        if schema:
            self._schemas[name] = schema

    async def call(self, name: str, **kwargs: Any) -> Any:
        """Execute a registered tool with a timeout guard."""
        if self._scope is not None and name not in self._scope:
            raise PermissionError(f"Tool '{name}' not in current scope")
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not registered")
        try:
            return await asyncio.wait_for(self._tools[name](**kwargs), timeout=_TOOL_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error("Tool '%s' timed out after %ds", name, _TOOL_TIMEOUT)
            return {"error": f"Tool '{name}' timed out after {_TOOL_TIMEOUT}s", "timed_out": True}

    def get_schemas(self) -> list[dict]:
        """Get OpenAI-compatible tool schemas."""
        return [
            {"type": "function", "function": {"name": n, **s}}
            for n, s in self._schemas.items()
            if self._scope is None or n in self._scope
        ]

    def set_scope(self, tools: set[str]) -> None:
        """Restrict available tools to a subset."""
        self._scope = tools

    def clear_scope(self) -> None:
        """Remove tool restrictions."""
        self._scope = None

    @property
    def available_tools(self) -> list[str]:
        if self._scope:
            return [t for t in self._tools if t in self._scope]
        return list(self._tools.keys())
