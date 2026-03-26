"""YAML template loader for the knowledge base."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("security_mcp.knowledge.loader")

# Bundled templates ship alongside this module
_BUNDLED_DIR = Path(__file__).parent / "templates"


class KnowledgeLoader:
    """Loads and validates YAML knowledge templates.

    By default includes the bundled templates directory. Additional
    directories (user-defined, remote-fetched) can be passed via
    ``template_dirs``.
    """

    def __init__(
        self,
        template_dirs: list[Path] | None = None,
        *,
        include_bundled: bool = True,
    ) -> None:
        self._template_dirs: list[Path] = []
        if include_bundled and _BUNDLED_DIR.is_dir():
            self._template_dirs.append(_BUNDLED_DIR)
        if template_dirs:
            self._template_dirs.extend(template_dirs)
        self._templates: dict[str, dict[str, Any]] = {}

    def load_all(self) -> dict[str, dict[str, Any]]:
        """Load all YAML templates from configured directories."""
        for d in self._template_dirs:
            if d.is_dir():
                for f in d.rglob("*.yaml"):
                    self._load_template(f)
        return self._templates

    def _load_template(self, path: Path) -> None:
        """Load and validate a single YAML template."""
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and isinstance(data, dict) and "id" in data:
                self._templates[data["id"]] = data
                logger.debug("Loaded template: %s (%s)", data["id"], path.name)
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Skipping malformed template %s: %s", path, exc)

    def get_template(self, template_id: str) -> dict[str, Any] | None:
        return self._templates.get(template_id)
