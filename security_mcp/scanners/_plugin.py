"""Scanner plugin and template interfaces.

Provides two extensibility mechanisms:

1. **YAML Scanner Templates** — lightweight scanner definitions that
   non-developers can write.  Loaded by ``load_yaml_scanners()`` and
   executed by ``YAMLScanner.scan()``.

2. **Scanner Plugin Protocol** — a Python interface for external plugins
   installed into ``~/.security_mcp/plugins/``.

YAML Template Format
--------------------

.. code-block:: yaml

   id: custom-header-check
   name: "Custom Security Header Check"
   severity: medium
   cwe: CWE-693

   request:
     method: GET
     path: /

   matchers:
     - type: header_absent
       headers: ["X-Custom-Security"]
     - type: header_value
       header: "Server"
       pattern: "Apache/2\\\\.2\\\\.\\\\d+"
       description: "Outdated Apache version"
     - type: body_regex
       pattern: "DEBUG\\\\s*=\\\\s*True"
       description: "Debug mode enabled"
"""

from __future__ import annotations

import importlib.util
import json
import logging
import re
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx
import yaml

logger = logging.getLogger("security_mcp.scanners._plugin")


# ---------------------------------------------------------------------------
# YAML Scanner Templates
# ---------------------------------------------------------------------------


class YAMLScanner:
    """Execute a scanner defined by a YAML template."""

    def __init__(self, template: dict[str, Any]) -> None:
        self.id: str = template["id"]
        self.name: str = template.get("name", self.id)
        self.severity: str = template.get("severity", "medium")
        self.cwe: str = template.get("cwe", "")
        self.request_method: str = template.get("request", {}).get("method", "GET")
        self.request_path: str = template.get("request", {}).get("path", "/")
        self.matchers: list[dict[str, Any]] = template.get("matchers", [])

    async def scan(self, base_url: str, timeout: float = 10.0) -> dict[str, Any]:
        """Run the template scanner against a target.

        Returns a dict with ``vulnerable``, ``findings``, ``template_id``.
        """
        url = base_url.rstrip("/") + self.request_path
        findings: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            try:
                if self.request_method.upper() == "GET":
                    resp = await client.get(url)
                else:
                    resp = await client.request(self.request_method.upper(), url)
            except httpx.HTTPError as exc:
                return {
                    "template_id": self.id,
                    "vulnerable": False,
                    "error": str(exc),
                    "findings": [],
                }

            for matcher in self.matchers:
                match_type = matcher.get("type", "")
                result = self._evaluate_matcher(matcher, match_type, resp)
                if result:
                    findings.append(result)

        return {
            "template_id": self.id,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "url": url,
            "status_code": resp.status_code,
        }

    def _evaluate_matcher(
        self,
        matcher: dict[str, Any],
        match_type: str,
        resp: httpx.Response,
    ) -> dict[str, Any] | None:
        """Evaluate a single matcher against the response."""
        if match_type == "header_absent":
            missing = [
                h for h in matcher.get("headers", [])
                if h.lower() not in {k.lower() for k in resp.headers}
            ]
            if missing:
                return {
                    "type": "header_absent",
                    "severity": self.severity,
                    "cwe": self.cwe,
                    "description": matcher.get("description", f"Missing headers: {', '.join(missing)}"),
                    "evidence": f"Headers absent: {', '.join(missing)}",
                }

        elif match_type == "header_value":
            header = matcher.get("header", "")
            pattern = matcher.get("pattern", "")
            value = resp.headers.get(header, "")
            if value and re.search(pattern, value):
                return {
                    "type": "header_value",
                    "severity": self.severity,
                    "cwe": self.cwe,
                    "description": matcher.get("description", f"Header {header} matches {pattern}"),
                    "evidence": f"{header}: {value}",
                }

        elif match_type == "body_regex":
            pattern = matcher.get("pattern", "")
            match = re.search(pattern, resp.text)
            if match:
                return {
                    "type": "body_regex",
                    "severity": self.severity,
                    "cwe": self.cwe,
                    "description": matcher.get("description", f"Body matches {pattern}"),
                    "evidence": match.group(0)[:200],
                }

        elif match_type == "status_code":
            expected = matcher.get("code", 200)
            if resp.status_code == expected:
                return {
                    "type": "status_code",
                    "severity": self.severity,
                    "cwe": self.cwe,
                    "description": matcher.get("description", f"Status code {expected}"),
                    "evidence": f"HTTP {resp.status_code}",
                }

        return None


def load_yaml_scanners(directory: str | Path) -> list[YAMLScanner]:
    """Load all YAML scanner templates from a directory.

    Args:
        directory: Path containing ``*.yaml`` or ``*.yml`` files.

    Returns:
        List of YAMLScanner instances ready to execute.
    """
    scanners: list[YAMLScanner] = []
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return scanners

    for path in sorted(dir_path.glob("*.yaml")) + sorted(dir_path.glob("*.yml")):
        try:
            with open(path, encoding="utf-8") as f:
                template = yaml.safe_load(f)
            if not isinstance(template, dict) or "id" not in template:
                logger.warning("Skipping invalid scanner template: %s (missing 'id')", path)
                continue
            if "matchers" not in template:
                logger.warning("Skipping scanner template %s (no matchers)", path)
                continue
            scanners.append(YAMLScanner(template))
            logger.debug("Loaded YAML scanner: %s from %s", template["id"], path)
        except Exception as exc:
            logger.warning("Failed to load scanner template %s: %s", path, exc)

    logger.info("Loaded %d YAML scanner templates from %s", len(scanners), directory)
    return scanners


# ---------------------------------------------------------------------------
# Python Plugin Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ScanPlugin(Protocol):
    """Interface for external scanner plugins.

    Plugins are Python modules placed in ``~/.security_mcp/plugins/``.
    Each module must define a ``register(registry)`` function that
    registers one or more tools with the ToolRegistry.

    Alternatively, a plugin can implement this protocol directly and
    be auto-discovered by the plugin loader.
    """

    name: str
    description: str
    cwe_ids: list[str]

    async def scan(self, url: str, **kwargs: Any) -> dict[str, Any]:
        """Run the scan against a target URL."""
        ...


def load_plugins(registry: Any, plugin_dir: str | Path | None = None) -> int:
    """Discover and load scanner plugins.

    Args:
        registry: ToolRegistry instance to register tools into.
        plugin_dir: Directory to scan for ``.py`` plugin files.
            Defaults to ``~/.security_mcp/plugins/``.

    Returns:
        Number of plugins successfully loaded.
    """
    if plugin_dir is None:
        plugin_dir = Path.home() / ".security_mcp" / "plugins"
    else:
        plugin_dir = Path(plugin_dir)

    if not plugin_dir.is_dir():
        return 0

    loaded = 0
    for plugin_file in sorted(plugin_dir.glob("*.py")):
        if plugin_file.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"security_mcp_plugin_{plugin_file.stem}", plugin_file,
            )
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "register"):
                module.register(registry)
                loaded += 1
                logger.info("Loaded plugin: %s from %s", plugin_file.stem, plugin_file)
            else:
                logger.warning("Plugin %s has no register() function, skipping", plugin_file)
        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", plugin_file, exc)

    logger.info("Loaded %d scanner plugins from %s", loaded, plugin_dir)
    return loaded
