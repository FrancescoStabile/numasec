"""Python-native directory/path fuzzer.

Replaces ffuf with async httpx-based fuzzing and smart response filtering.
Uses a built-in wordlist of common web paths and supports extension bruting.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("security_mcp.scanners.dir_fuzzer")

# ---------------------------------------------------------------------------
# Built-in wordlist — top ~200 common web paths
# ---------------------------------------------------------------------------

COMMON_PATHS: list[str] = [
    # Admin / management
    "admin",
    "administrator",
    "login",
    "wp-admin",
    "wp-login.php",
    "console",
    "dashboard",
    "panel",
    "manage",
    "management",
    "cpanel",
    "webmail",
    "portal",
    "sysadmin",
    "controlpanel",
    # API endpoints
    "api",
    "api/v1",
    "api/v2",
    "api/v3",
    "api/docs",
    "api/swagger",
    "swagger.json",
    "swagger-ui",
    "openapi.json",
    "graphql",
    "graphiql",
    "api/graphql",
    # Configuration / sensitive files
    "config",
    "configuration",
    ".env",
    ".env.bak",
    ".env.local",
    ".git",
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "crossdomain.xml",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "package.json",
    "composer.json",
    "Gemfile",
    # Well-known / standard
    "robots.txt",
    "sitemap.xml",
    "humans.txt",
    "security.txt",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    "favicon.ico",
    # WordPress
    "wp-content",
    "wp-includes",
    "wp-json",
    "xmlrpc.php",
    "wp-config.php",
    "wp-cron.php",
    # Database / server admin
    "phpmyadmin",
    "phpinfo.php",
    "info.php",
    "adminer.php",
    "server-status",
    "server-info",
    "apc.php",
    # Backup / archives
    "backup",
    "backups",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "db",
    "database",
    "dump.sql",
    "data",
    # Debug / development
    "debug",
    "test",
    "testing",
    "dev",
    "development",
    "staging",
    "_debug",
    "_test",
    "sandbox",
    # Application directories
    "uploads",
    "images",
    "img",
    "static",
    "assets",
    "media",
    "files",
    "content",
    "resources",
    "public",
    "private",
    # Documentation
    "docs",
    "documentation",
    "readme",
    "changelog",
    "help",
    # Server directories
    "cgi-bin",
    "scripts",
    "includes",
    "modules",
    "vendor",
    "lib",
    "libs",
    "bin",
    "src",
    # Temp / cache / logs
    "tmp",
    "temp",
    "cache",
    "log",
    "logs",
    "error_log",
    "access.log",
    "error.log",
    "debug.log",
    # Health / monitoring
    "status",
    "health",
    "healthcheck",
    "ping",
    "version",
    "metrics",
    "prometheus",
    "actuator",
    "actuator/health",
    "actuator/info",
    "actuator/env",
    # Node.js / JS frameworks
    "node_modules",
    ".next",
    "_next",
    "__nuxt",
    # Error pages
    "error",
    "404",
    "500",
    "403",
    # Common application paths
    "search",
    "register",
    "signup",
    "signin",
    "logout",
    "profile",
    "account",
    "settings",
    "user",
    "users",
    "blog",
    "news",
    "about",
    "contact",
    "faq",
    # Hidden files / OS artifacts
    ".DS_Store",
    "Thumbs.db",
    ".svn",
    ".svn/entries",
    ".hg",
    ".bzr",
    "CVS",
    # CI/CD
    ".github",
    ".gitlab-ci.yml",
    ".circleci",
    "Jenkinsfile",
    ".travis.yml",
    # Other sensitive
    "secret",
    "secrets",
    "token",
    "tokens",
    "credentials",
    "keys",
    "id_rsa",
    "id_rsa.pub",
    ".ssh",
    "shadow",
    "passwd",
    # Common frameworks
    "rails/info",
    "elmah.axd",
    "trace.axd",
    "wp-admin/install.php",
    "install",
    "setup",
    # Catch-all extensions
    "index.html",
    "index.php",
    "index.asp",
    "index.jsp",
    "default.asp",
    "default.aspx",
]

# Status codes that indicate a discovered resource
INTERESTING_STATUS_CODES: set[int] = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FuzzResult:
    """Result of a directory fuzzing session."""

    target: str
    discovered: list[dict[str, Any]] = field(default_factory=list)
    total_checked: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "discovered": self.discovered,
            "total_checked": self.total_checked,
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Fuzzer engine
# ---------------------------------------------------------------------------


class PythonDirFuzzer:
    """Async directory fuzzer using httpx with smart 404 filtering.

    Features:
    - Baseline 404 detection to filter custom error pages
    - Concurrent requests with semaphore-based rate limiting
    - Extension bruting (e.g. ``.php``, ``.bak``, ``.old``)
    - Response size + status code filtering

    Parameters
    ----------
    concurrency:
        Maximum concurrent HTTP requests.
    timeout:
        Per-request timeout in seconds.
    """

    def __init__(self, concurrency: int = 50, timeout: float = 5.0) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)

    async def fuzz(
        self,
        url: str,
        wordlist: list[str] | None = None,
        extensions: list[str] | None = None,
    ) -> FuzzResult:
        """Fuzz a target URL for directories and files.

        Args:
            url: Base URL to fuzz (paths are appended to this).
            wordlist: Custom wordlist. ``None`` uses the built-in
                ``COMMON_PATHS`` list.
            extensions: File extensions to append (e.g. ``["php", "bak"]``).
                Each path is tested with and without each extension.

        Returns:
            ``FuzzResult`` with all discovered paths.
        """
        start = time.monotonic()
        result = FuzzResult(target=url)
        paths = wordlist or COMMON_PATHS

        # Expand paths with extensions
        expanded: list[str] = list(paths)
        for ext in extensions or []:
            ext = ext.lstrip(".")
            expanded.extend(f"{p}.{ext}" for p in paths if "." not in p)

        # Normalise base URL
        base = url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-mcp/1.0)"},
        ) as client:
            # Get baseline 404 fingerprint
            baseline = await self._get_baseline(client, base)

            # Fuzz all paths concurrently
            tasks = [self._check_path(client, base, path, baseline) for path in expanded]
            findings = await asyncio.gather(*tasks, return_exceptions=True)

            for finding in findings:
                if isinstance(finding, dict):
                    result.discovered.append(finding)

            result.total_checked = len(expanded)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Dir fuzz complete: %s — %d paths checked, %d discovered, %.0fms",
            url,
            result.total_checked,
            len(result.discovered),
            result.duration_ms,
        )
        return result

    async def _get_baseline(
        self,
        client: httpx.AsyncClient,
        base: str,
    ) -> dict[str, Any]:
        """Get baseline 404 response fingerprint for false-positive filtering.

        Sends a request to a path that is extremely unlikely to exist.
        Records the status code and response length for later comparison.
        """
        random_path = f"security_mcp-nonexistent-{time.time_ns()}"
        try:
            resp = await client.get(f"{base}/{random_path}")
            return {
                "status": resp.status_code,
                "length": len(resp.text),
            }
        except httpx.HTTPError:
            return {"status": 404, "length": 0}

    async def _check_path(
        self,
        client: httpx.AsyncClient,
        base: str,
        path: str,
        baseline: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Check a single path against the target.

        Returns a finding dict if the path exists, ``None`` otherwise.
        Filters out responses that match the baseline 404 fingerprint.
        """
        async with self._sem:
            try:
                resp = await client.get(f"{base}/{path}")

                # Filter: matches baseline 404 (custom error page)
                if resp.status_code == baseline["status"] and abs(len(resp.text) - baseline["length"]) < 50:
                    return None

                # Filter: not an interesting status code
                if resp.status_code not in INTERESTING_STATUS_CODES:
                    return None

                return {
                    "path": f"/{path}",
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "redirect": str(resp.headers.get("location", "")),
                }
            except httpx.HTTPError:
                return None


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_dir_fuzz(
    url: str,
    wordlist: str | None = None,
    extensions: str | None = None,
) -> str:
    """Run directory fuzzing against a URL.

    Args:
        url: Target base URL (e.g. ``http://example.com``).
        wordlist: Comma-separated custom paths. ``None`` uses built-in list.
        extensions: Comma-separated extensions (e.g. ``"php,bak,old"``).

    Returns:
        JSON string with discovered paths and metadata.
    """
    word_list = wordlist.split(",") if wordlist else None
    ext_list = extensions.split(",") if extensions else None

    fuzzer = PythonDirFuzzer()
    result = await fuzzer.fuzz(url, wordlist=word_list, extensions=ext_list)
    return json.dumps(result.to_dict(), indent=2)
