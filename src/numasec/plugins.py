"""
NumaSec v3 - Plugin System

Extensible architecture for loading custom tools, extractors, and knowledge.

Plugin types:
  - tool: Adds new tool functions + schemas to ToolRegistry
  - extractor: Adds new extractors to the extraction pipeline
  - knowledge: Adds knowledge files for context injection

Discovery:
  - ~/.numasec/plugins/ directory
  - Each plugin is a Python package (directory with __init__.py)
  - Plugin metadata in plugin.json or __init__.py attributes

Plugin structure example:
  ~/.numasec/plugins/
    my_tool/
      __init__.py          # Must define PLUGIN_META dict
      plugin.json          # Optional: metadata override
      tool.py              # Tool implementation
      extractor.py         # Optional: custom extractor
      knowledge/           # Optional: knowledge files
        my_cheatsheet.md

PLUGIN_META format:
  {
      "name": "my_tool",
      "version": "1.0.0",
      "description": "A custom tool for ...",
      "author": "Your Name",
      "type": "tool",  # tool | extractor | knowledge
  }
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("numasec.plugins")

# Default plugin directory
PLUGIN_DIR = Path.home() / ".numasec" / "plugins"


# ═══════════════════════════════════════════════════════════════════════════
# Plugin Metadata
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class PluginMeta:
    """Plugin metadata."""
    name: str
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    plugin_type: str = "tool"  # tool | extractor | knowledge
    enabled: bool = True
    path: Path = field(default_factory=lambda: Path("."))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "type": self.plugin_type,
            "enabled": self.enabled,
            "path": str(self.path),
        }


@dataclass
class LoadedPlugin:
    """A loaded plugin with its components."""
    meta: PluginMeta
    module: Any = None
    tools: dict[str, Callable] = field(default_factory=dict)
    tool_schemas: dict[str, dict] = field(default_factory=dict)
    extractors: dict[str, Callable] = field(default_factory=dict)
    knowledge_files: list[Path] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Plugin Manager
# ═══════════════════════════════════════════════════════════════════════════


class PluginManager:
    """
    Discovers, loads, and manages NumaSec plugins.

    Usage:
        pm = PluginManager()
        pm.discover()
        pm.load_all()

        # Register tools
        for plugin in pm.loaded:
            for name, func in plugin.tools.items():
                tool_registry.register(name, func, plugin.tool_schemas.get(name, {}))
    """

    def __init__(self, plugin_dir: Path | str | None = None):
        self.plugin_dir = Path(plugin_dir) if plugin_dir else PLUGIN_DIR
        self.discovered: list[PluginMeta] = []
        self.loaded: list[LoadedPlugin] = []
        self._errors: list[tuple[str, str]] = []

    def ensure_plugin_dir(self) -> Path:
        """Create plugin directory if it doesn't exist."""
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        return self.plugin_dir

    def discover(self) -> list[PluginMeta]:
        """
        Discover plugins in the plugin directory.

        Looks for:
        1. Directories with __init__.py (Python packages)
        2. plugin.json for metadata
        3. PLUGIN_META dict in __init__.py

        Returns:
            List of discovered plugin metadata
        """
        self.discovered.clear()

        if not self.plugin_dir.exists():
            logger.debug(f"Plugin directory does not exist: {self.plugin_dir}")
            return self.discovered

        for item in sorted(self.plugin_dir.iterdir()):
            if not item.is_dir():
                continue

            init_file = item / "__init__.py"
            if not init_file.exists():
                continue

            try:
                meta = self._read_plugin_meta(item)
                if meta:
                    self.discovered.append(meta)
                    logger.info(f"Discovered plugin: {meta.name} v{meta.version} ({meta.plugin_type})")
            except Exception as e:
                logger.warning(f"Failed to read plugin metadata from {item.name}: {e}")
                self._errors.append((item.name, str(e)))

        return self.discovered

    def _read_plugin_meta(self, plugin_dir: Path) -> PluginMeta | None:
        """Read plugin metadata from plugin.json or __init__.py."""
        # Try plugin.json first
        json_file = plugin_dir / "plugin.json"
        if json_file.exists():
            try:
                data = json.loads(json_file.read_text())
                return PluginMeta(
                    name=data.get("name", plugin_dir.name),
                    version=data.get("version", "0.1.0"),
                    description=data.get("description", ""),
                    author=data.get("author", ""),
                    plugin_type=data.get("type", "tool"),
                    enabled=data.get("enabled", True),
                    path=plugin_dir,
                )
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid plugin.json in {plugin_dir.name}: {e}")

        # Fallback: Try loading __init__.py for PLUGIN_META
        init_file = plugin_dir / "__init__.py"
        try:
            spec = importlib.util.spec_from_file_location(
                f"numasec_plugin_{plugin_dir.name}", init_file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                plugin_meta = getattr(module, "PLUGIN_META", None)
                if plugin_meta and isinstance(plugin_meta, dict):
                    return PluginMeta(
                        name=plugin_meta.get("name", plugin_dir.name),
                        version=plugin_meta.get("version", "0.1.0"),
                        description=plugin_meta.get("description", ""),
                        author=plugin_meta.get("author", ""),
                        plugin_type=plugin_meta.get("type", "tool"),
                        enabled=plugin_meta.get("enabled", True),
                        path=plugin_dir,
                    )
        except Exception as e:
            logger.debug(f"Could not load __init__.py for {plugin_dir.name}: {e}")

        # Minimal metadata from directory name
        return PluginMeta(name=plugin_dir.name, path=plugin_dir)

    def load_all(self) -> list[LoadedPlugin]:
        """Load all discovered and enabled plugins."""
        if not self.discovered:
            self.discover()

        self.loaded.clear()

        for meta in self.discovered:
            if not meta.enabled:
                logger.info(f"Skipping disabled plugin: {meta.name}")
                continue

            try:
                plugin = self._load_plugin(meta)
                if plugin:
                    self.loaded.append(plugin)
                    logger.info(
                        f"Loaded plugin: {meta.name} "
                        f"(tools: {len(plugin.tools)}, "
                        f"extractors: {len(plugin.extractors)}, "
                        f"knowledge: {len(plugin.knowledge_files)})"
                    )
            except Exception as e:
                logger.error(f"Failed to load plugin {meta.name}: {e}", exc_info=True)
                self._errors.append((meta.name, str(e)))

        return self.loaded

    def _load_plugin(self, meta: PluginMeta) -> LoadedPlugin | None:
        """Load a single plugin."""
        plugin = LoadedPlugin(meta=meta)

        # Add plugin directory to sys.path temporarily
        plugin_path = str(meta.path)
        if plugin_path not in sys.path:
            sys.path.insert(0, plugin_path)

        try:
            # Load tool module
            if meta.plugin_type in ("tool", "all"):
                self._load_tool_module(meta, plugin)

            # Load extractor module
            if meta.plugin_type in ("extractor", "all"):
                self._load_extractor_module(meta, plugin)

            # Discover knowledge files
            if meta.plugin_type in ("knowledge", "all"):
                self._load_knowledge_files(meta, plugin)

            # Also load tools from __init__.py if exported
            self._load_from_init(meta, plugin)

        finally:
            if plugin_path in sys.path:
                sys.path.remove(plugin_path)

        return plugin

    def _load_tool_module(self, meta: PluginMeta, plugin: LoadedPlugin):
        """Load tool.py from plugin directory."""
        tool_file = meta.path / "tool.py"
        if not tool_file.exists():
            return

        try:
            spec = importlib.util.spec_from_file_location(
                f"numasec_plugin_{meta.name}_tool", tool_file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                plugin.module = module

                # Look for TOOLS dict: {name: function}
                tools = getattr(module, "TOOLS", {})
                if isinstance(tools, dict):
                    plugin.tools.update(tools)

                # Look for TOOL_SCHEMAS dict: {name: schema}
                schemas = getattr(module, "TOOL_SCHEMAS", {})
                if isinstance(schemas, dict):
                    plugin.tool_schemas.update(schemas)

        except Exception as e:
            logger.warning(f"Failed to load tool.py from {meta.name}: {e}")

    def _load_extractor_module(self, meta: PluginMeta, plugin: LoadedPlugin):
        """Load extractor.py from plugin directory."""
        extractor_file = meta.path / "extractor.py"
        if not extractor_file.exists():
            return

        try:
            spec = importlib.util.spec_from_file_location(
                f"numasec_plugin_{meta.name}_extractor", extractor_file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Look for EXTRACTORS dict: {tool_name: extractor_function}
                extractors = getattr(module, "EXTRACTORS", {})
                if isinstance(extractors, dict):
                    plugin.extractors.update(extractors)

        except Exception as e:
            logger.warning(f"Failed to load extractor.py from {meta.name}: {e}")

    def _load_knowledge_files(self, meta: PluginMeta, plugin: LoadedPlugin):
        """Discover knowledge markdown files."""
        knowledge_dir = meta.path / "knowledge"
        if knowledge_dir.exists():
            for md_file in sorted(knowledge_dir.glob("**/*.md")):
                plugin.knowledge_files.append(md_file)

    def _load_from_init(self, meta: PluginMeta, plugin: LoadedPlugin):
        """Load tools/extractors exported from __init__.py."""
        init_file = meta.path / "__init__.py"
        if not init_file.exists():
            return

        try:
            spec = importlib.util.spec_from_file_location(
                f"numasec_plugin_{meta.name}_init", init_file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Check for register function
                register_fn = getattr(module, "register", None)
                if callable(register_fn):
                    result = register_fn()
                    if isinstance(result, dict):
                        if "tools" in result:
                            plugin.tools.update(result["tools"])
                        if "schemas" in result:
                            plugin.tool_schemas.update(result["schemas"])
                        if "extractors" in result:
                            plugin.extractors.update(result["extractors"])

        except Exception as e:
            logger.debug(f"Could not load from __init__.py for {meta.name}: {e}")

    # ──────────────────────────────────────────────────────────
    # Registration helpers
    # ──────────────────────────────────────────────────────────

    def register_tools(self, tool_registry) -> int:
        """
        Register all plugin tools into the ToolRegistry.

        Args:
            tool_registry: The ToolRegistry instance

        Returns:
            Number of tools registered
        """
        count = 0
        for plugin in self.loaded:
            for name, func in plugin.tools.items():
                schema = plugin.tool_schemas.get(name, {})
                tool_registry.register(name, func, schema)
                logger.info(f"Registered plugin tool: {name} (from {plugin.meta.name})")
                count += 1
        return count

    def register_extractors(self, extractors_dict: dict) -> int:
        """
        Register all plugin extractors into the extractors dispatch dict.

        Args:
            extractors_dict: The EXTRACTORS dict from extractors.py

        Returns:
            Number of extractors registered
        """
        count = 0
        for plugin in self.loaded:
            for tool_name, extractor_fn in plugin.extractors.items():
                extractors_dict[tool_name] = extractor_fn
                logger.info(f"Registered plugin extractor: {tool_name} (from {plugin.meta.name})")
                count += 1
        return count

    def get_knowledge_files(self) -> list[Path]:
        """Get all knowledge files from all loaded plugins."""
        files = []
        for plugin in self.loaded:
            files.extend(plugin.knowledge_files)
        return files

    def get_errors(self) -> list[tuple[str, str]]:
        """Get list of (plugin_name, error_message) for failed plugins."""
        return self._errors.copy()

    def list_plugins(self) -> list[dict]:
        """List all discovered plugins with their status."""
        result = []
        loaded_names = {p.meta.name for p in self.loaded}

        for meta in self.discovered:
            status = "loaded" if meta.name in loaded_names else "disabled" if not meta.enabled else "error"
            result.append({
                **meta.to_dict(),
                "status": status,
            })

        return result


# ═══════════════════════════════════════════════════════════════════════════
# Plugin scaffold helper
# ═══════════════════════════════════════════════════════════════════════════


def scaffold_plugin(name: str, plugin_type: str = "tool", plugin_dir: Path | None = None) -> Path:
    """
    Create a new plugin scaffold.

    Args:
        name: Plugin name
        plugin_type: "tool", "extractor", or "knowledge"
        plugin_dir: Override plugin directory

    Returns:
        Path to created plugin directory
    """
    base = plugin_dir or PLUGIN_DIR
    base.mkdir(parents=True, exist_ok=True)
    pdir = base / name

    if pdir.exists():
        raise FileExistsError(f"Plugin directory already exists: {pdir}")

    pdir.mkdir()

    # plugin.json
    meta = {
        "name": name,
        "version": "0.1.0",
        "description": f"NumaSec plugin: {name}",
        "author": "",
        "type": plugin_type,
        "enabled": True,
    }
    (pdir / "plugin.json").write_text(json.dumps(meta, indent=2))

    # __init__.py
    (pdir / "__init__.py").write_text(f'''"""
NumaSec Plugin: {name}
"""

PLUGIN_META = {{
    "name": "{name}",
    "version": "0.1.0",
    "description": "NumaSec plugin: {name}",
    "type": "{plugin_type}",
}}
''')

    # Tool template
    if plugin_type in ("tool", "all"):
        (pdir / "tool.py").write_text(f'''"""
Tool implementation for {name} plugin.
"""


async def my_tool(param1: str, param2: str = "") -> str:
    """Your tool implementation."""
    # TODO: Implement your tool logic here
    return f"Result from {name}: {{param1}}"


# Register tools - dict of name -> function
TOOLS = {{
    "{name}": my_tool,
}}

# Tool schemas for LLM
TOOL_SCHEMAS = {{
    "{name}": {{
        "name": "{name}",
        "description": "Description of what {name} does",
        "input_schema": {{
            "type": "object",
            "properties": {{
                "param1": {{
                    "type": "string",
                    "description": "First parameter"
                }},
                "param2": {{
                    "type": "string",
                    "description": "Optional second parameter"
                }}
            }},
            "required": ["param1"]
        }}
    }}
}}
''')

    # Extractor template
    if plugin_type in ("extractor", "all"):
        (pdir / "extractor.py").write_text(f'''"""
Extractor implementation for {name} plugin.
"""


def extract_{name}(raw_output: str, profile) -> None:
    """Extract structured data from {name} tool output."""
    # TODO: Parse raw_output and update profile
    pass


# Register extractors - dict of tool_name -> extractor_function
EXTRACTORS = {{
    "{name}": extract_{name},
}}
''')

    # Knowledge directory
    if plugin_type in ("knowledge", "all"):
        kdir = pdir / "knowledge"
        kdir.mkdir()
        (kdir / f"{name}_cheatsheet.md").write_text(f"""# {name.title()} Cheatsheet

## Quick Reference

- TODO: Add your knowledge here
""")

    logger.info(f"Plugin scaffold created: {pdir}")
    return pdir


# ═══════════════════════════════════════════════════════════════════════════
# Convenience
# ═══════════════════════════════════════════════════════════════════════════


def load_plugins(plugin_dir: Path | str | None = None) -> PluginManager:
    """Load all plugins from directory. Convenience function."""
    pm = PluginManager(plugin_dir)
    pm.discover()
    pm.load_all()
    return pm
