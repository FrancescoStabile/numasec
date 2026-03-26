"""Tool registry for managing available tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any


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
        """Execute a registered tool."""
        if self._scope is not None and name not in self._scope:
            raise PermissionError(f"Tool '{name}' not in current scope")
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not registered")
        return await self._tools[name](**kwargs)

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
