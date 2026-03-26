"""Sandboxed command execution tool."""

from __future__ import annotations

import logging
from typing import Any

from security_mcp.security.sandbox import ToolSandbox, ToolTimeout

logger = logging.getLogger("security_mcp.tools.command")

_sandbox = ToolSandbox()


async def run_command(
    command: list[str],
    allowed_targets: list[str] | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run a command in the sandbox.

    Returns a dict with stdout, stderr, return_code, and success flag.
    """
    if not command:
        return {"success": False, "error": "Empty command", "stdout": "", "stderr": "", "return_code": -1}

    logger.info("Executing: %s (timeout=%ds)", command[0], timeout)

    try:
        output = await _sandbox.run(
            command,
            allowed_targets=allowed_targets,
            timeout=timeout,
        )
    except ToolTimeout:
        logger.warning("Command timed out: %s", command[0])
        return {
            "success": False,
            "error": f"Timeout after {timeout}s",
            "stdout": "",
            "stderr": "",
            "return_code": -1,
        }

    stdout = output.stdout.decode("utf-8", errors="replace")
    stderr = output.stderr.decode("utf-8", errors="replace")
    success = output.rc == 0

    if not success:
        logger.warning("Command failed (rc=%d): %s", output.rc, command[0])

    return {
        "success": success,
        "stdout": stdout,
        "stderr": stderr,
        "return_code": output.rc,
    }
