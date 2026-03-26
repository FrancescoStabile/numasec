"""Composite OOB tool — setup and poll for blind vulnerability detection."""

from __future__ import annotations

import json
import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)


async def oob(
    action: Literal["setup", "poll"],
    server: str = "",
    correlation_id: str = "",
) -> dict[str, Any]:
    """Out-of-Band callback detection: setup a listener or poll for interactions.

    Args:
        action: OOB action — setup (create listener) or poll (check for callbacks).
        server: Interactsh server hostname (for setup; default: oast.live).
        correlation_id: Correlation ID from setup (required for poll).
    """
    from security_mcp.tools.oob_tool import python_oob_poll, python_oob_setup

    if action == "setup":
        result = await python_oob_setup(server=server or None)
        # python_oob_setup returns a JSON string — parse it to a dict
        return json.loads(result) if isinstance(result, str) else result
    elif action == "poll":
        result = await python_oob_poll(correlation_id=correlation_id or None)
        # python_oob_poll returns a JSON string — parse it to a dict
        return json.loads(result) if isinstance(result, str) else result
    else:
        return {"error": f"Unknown action: {action}. Use: setup or poll"}
