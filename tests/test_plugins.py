"""
Tests for Plugins — plugin system.
"""

import json
import pytest
from pathlib import Path
from numasec.plugins import PluginManager, PluginMeta, scaffold_plugin, load_plugins


class TestPluginManager:
    @pytest.fixture
    def plugin_dir(self, tmp_path):
        return tmp_path / "plugins"

    @pytest.fixture
    def pm(self, plugin_dir):
        return PluginManager(plugin_dir)

    def test_ensure_plugin_dir(self, pm, plugin_dir):
        assert not plugin_dir.exists()
        pm.ensure_plugin_dir()
        assert plugin_dir.exists()

    def test_discover_empty(self, pm, plugin_dir):
        plugins = pm.discover()
        assert plugins == []

    def test_discover_plugin(self, pm, plugin_dir):
        # Create a fake plugin
        p = plugin_dir / "test_plugin"
        p.mkdir(parents=True)
        (p / "__init__.py").write_text('PLUGIN_META = {"name": "test_plugin", "version": "1.0", "type": "tool"}')
        (p / "plugin.json").write_text(json.dumps({
            "name": "test_plugin",
            "version": "1.0.0",
            "type": "tool",
            "enabled": True,
        }))

        plugins = pm.discover()
        assert len(plugins) == 1
        assert plugins[0].name == "test_plugin"

    def test_load_plugin_with_tool(self, pm, plugin_dir):
        # Create plugin with tool.py
        p = plugin_dir / "my_tool"
        p.mkdir(parents=True)
        (p / "__init__.py").write_text('PLUGIN_META = {"name": "my_tool", "type": "tool"}')
        (p / "plugin.json").write_text(json.dumps({"name": "my_tool", "type": "tool", "enabled": True}))
        (p / "tool.py").write_text('''
async def my_func(param: str) -> str:
    return f"result: {param}"

TOOLS = {"my_tool": my_func}
TOOL_SCHEMAS = {"my_tool": {"name": "my_tool", "description": "Test tool"}}
''')

        pm.discover()
        loaded = pm.load_all()
        assert len(loaded) == 1
        assert "my_tool" in loaded[0].tools

    def test_disabled_plugin_skipped(self, pm, plugin_dir):
        p = plugin_dir / "disabled"
        p.mkdir(parents=True)
        (p / "__init__.py").write_text("")
        (p / "plugin.json").write_text(json.dumps({"name": "disabled", "enabled": False}))

        pm.discover()
        loaded = pm.load_all()
        assert len(loaded) == 0

    def test_list_plugins(self, pm, plugin_dir):
        p = plugin_dir / "listed"
        p.mkdir(parents=True)
        (p / "__init__.py").write_text("")
        (p / "plugin.json").write_text(json.dumps({"name": "listed", "type": "tool", "enabled": True}))

        pm.discover()
        pm.load_all()
        listing = pm.list_plugins()
        assert len(listing) == 1
        assert listing[0]["name"] == "listed"


class TestScaffoldPlugin:
    def test_scaffold_tool(self, tmp_path):
        path = scaffold_plugin("test_tool", "tool", tmp_path)
        assert path.exists()
        assert (path / "__init__.py").exists()
        assert (path / "plugin.json").exists()
        assert (path / "tool.py").exists()

    def test_scaffold_knowledge(self, tmp_path):
        path = scaffold_plugin("test_kb", "knowledge", tmp_path)
        assert path.exists()
        assert (path / "knowledge").is_dir()

    def test_scaffold_duplicate_fails(self, tmp_path):
        scaffold_plugin("dup", "tool", tmp_path)
        with pytest.raises(FileExistsError):
            scaffold_plugin("dup", "tool", tmp_path)


class TestLoadPlugins:
    def test_load_from_empty(self, tmp_path):
        pm = load_plugins(tmp_path / "empty")
        assert len(pm.loaded) == 0
