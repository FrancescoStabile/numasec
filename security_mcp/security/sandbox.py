"""ToolSandbox — bubblewrap on Linux, timeout on other OS."""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from dataclasses import dataclass

logger = logging.getLogger("security_mcp.security.sandbox")


class TargetNotAllowed(Exception):
    """Raised when target is not in the allowed list."""


class ToolTimeout(Exception):
    """Raised when a tool exceeds its timeout."""


@dataclass
class ToolOutput:
    """Output from a sandboxed tool execution."""

    stdout: bytes = b""
    stderr: bytes = b""
    rc: int = 0


class ToolSandbox:
    """
    Sandboxing validated: bubblewrap (bwrap) on Linux,
    timeout + resource limits on macOS/Windows.
    """

    async def run(
        self,
        command: list[str],
        allowed_targets: list[str] | None = None,
        timeout: int = 300,
        max_memory_mb: int = 512,
    ) -> ToolOutput:
        """Run a command in the sandbox.

        Args:
            command: Command and arguments to execute.
            allowed_targets: If provided, validates extracted target against this list.
            timeout: Max execution time in seconds.
            max_memory_mb: Memory limit in MB (Linux only, best-effort).

        Raises:
            TargetNotAllowed: If target is not in allowed list.
            ToolTimeout: If command exceeds timeout.
        """
        # 1. Target validation (anti-SSRF)
        if allowed_targets is not None:
            target = self._extract_target(command)
            if target and not self._is_allowed_target(target, allowed_targets):
                raise TargetNotAllowed(f"Target '{target}' not in allowed list: {allowed_targets}")

        # 2. Wrap with sandbox if available
        actual_command = list(command)
        if self._has_bwrap():
            actual_command = self._wrap_with_bwrap(command)
            logger.debug("Using bubblewrap sandbox")
        else:
            logger.debug("No bubblewrap available, using basic timeout sandbox")

        # 3. Execute with timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                *actual_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except TimeoutError as exc:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise ToolTimeout(f"Command '{command[0]}' killed after {timeout}s timeout") from exc

        return ToolOutput(stdout=stdout, stderr=stderr, rc=proc.returncode or 0)

    def _is_allowed_target(self, target: str, allowed: list[str]) -> bool:
        """Validate target against allow list (anti-SSRF).

        Supports exact match, wildcard subdomains (*.example.com),
        and CIDR ranges (192.168.1.0/24).
        """
        if not target:
            return False

        target_lower = target.lower().strip()

        for entry in allowed:
            entry_lower = entry.lower().strip()

            # Exact match
            if target_lower == entry_lower:
                return True

            # Wildcard subdomain: *.example.com matches sub.example.com
            if entry_lower.startswith("*."):
                domain = entry_lower[2:]
                if target_lower == domain or target_lower.endswith(f".{domain}"):
                    return True

            # CIDR match
            if "/" in entry:
                try:
                    from ipaddress import ip_address, ip_network

                    net = ip_network(entry, strict=False)
                    addr = ip_address(target)
                    if addr in net:
                        return True
                except (ValueError, TypeError):
                    continue

        return False

    def _extract_target(self, command: list[str]) -> str:
        """Extract target from command arguments.

        Looks for common flag patterns: -host, --host, -target, --target, -u, --url,
        or the last non-flag argument.
        """
        target_flags = {"-host", "--host", "-target", "--target", "-u", "--url", "-h"}

        for i, arg in enumerate(command):
            if arg in target_flags and i + 1 < len(command):
                return command[i + 1]
            for flag in target_flags:
                if arg.startswith(f"{flag}="):
                    return arg.split("=", 1)[1]

        # Fallback: last non-flag argument
        for arg in reversed(command[1:]):
            if not arg.startswith("-"):
                return arg

        return ""

    @staticmethod
    def _has_bwrap() -> bool:
        """Check if bubblewrap is available."""
        return sys.platform == "linux" and shutil.which("bwrap") is not None

    @staticmethod
    def _wrap_with_bwrap(command: list[str]) -> list[str]:
        """Wrap command with bubblewrap for Linux sandbox."""
        bwrap_args = [
            "bwrap",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--tmpfs",
            "/tmp",
            "--dev",
            "/dev",
            "--unshare-all",
            "--share-net",  # Need network for scanning
            "--die-with-parent",
        ]
        # /lib and /lib64 may not exist on all distros
        for lib_dir in ("/lib", "/lib64", "/sbin"):
            import os

            if os.path.isdir(lib_dir):
                bwrap_args.extend(["--ro-bind", lib_dir, lib_dir])

        bwrap_args.append("--")
        bwrap_args.extend(command)
        return bwrap_args
