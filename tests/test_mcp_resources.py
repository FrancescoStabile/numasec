"""
Tests for MCP Resources — knowledge base discovery, URI mapping, fuzzy search.

These tests access the REAL knowledge/ directory to verify that
the resource layer correctly discovers and maps all 46+ markdown files.
"""

import pytest
from pathlib import Path

from numasec.mcp_resources import (
    _path_to_uri_key,
    _uri_key_to_candidates,
    discover_knowledge_files,
    read_knowledge,
    list_knowledge_topics,
    KNOWLEDGE_DIR,
)


# ═══════════════════════════════════════════════════════════════════════════
# URI Key Conversion
# ═══════════════════════════════════════════════════════════════════════════


class TestPathToUriKey:
    def test_simple_file(self):
        assert _path_to_uri_key(Path("web_cheatsheet.md")) == "web-cheatsheet"

    def test_nested_file(self):
        result = _path_to_uri_key(Path("attack_chains/sqli_to_rce.md"))
        assert result == "attack-chains/sqli-to-rce"

    def test_uppercase_lowered(self):
        result = _path_to_uri_key(Path("README.md"))
        assert result == "readme"

    def test_no_md_extension(self):
        # Already without .md should still work
        result = _path_to_uri_key(Path("web_cheatsheet"))
        assert result == "web-cheatsheet"


class TestUriKeyToCandidates:
    def test_returns_multiple_candidates(self):
        candidates = _uri_key_to_candidates("web-cheatsheet")
        assert len(candidates) >= 3

    def test_candidates_include_md_extension(self):
        candidates = _uri_key_to_candidates("web-cheatsheet")
        # Should try web_cheatsheet.md
        assert any(c.name == "web_cheatsheet.md" for c in candidates)

    def test_candidates_include_readme(self):
        candidates = _uri_key_to_candidates("attack-chains")
        # Should try attack_chains/README.md
        assert any("README.md" in str(c) for c in candidates)


# ═══════════════════════════════════════════════════════════════════════════
# Knowledge File Discovery
# ═══════════════════════════════════════════════════════════════════════════


class TestDiscoverKnowledgeFiles:
    def test_discovers_files(self):
        """Should discover at least 30 knowledge files (we have 46+)."""
        mapping = discover_knowledge_files()
        assert len(mapping) >= 30, f"Only found {len(mapping)} knowledge files"

    def test_returns_dict_of_paths(self):
        mapping = discover_knowledge_files()
        for key, path in mapping.items():
            assert isinstance(key, str)
            assert isinstance(path, Path)
            assert path.exists(), f"Mapped path does not exist: {path}"
            assert path.suffix == ".md"

    def test_keys_are_uri_friendly(self):
        """Keys should only contain lowercase, hyphens, and slashes."""
        mapping = discover_knowledge_files()
        for key in mapping:
            assert key == key.lower(), f"Key not lowercase: {key}"
            # Should not have underscores (converted to hyphens)
            assert "_" not in key, f"Key has underscore: {key}"
            # Should not have .md extension
            assert not key.endswith(".md"), f"Key has .md: {key}"

    def test_known_files_present(self):
        """Core knowledge files should be discoverable."""
        mapping = discover_knowledge_files()
        expected_keys = [
            "web-cheatsheet",
            "linux-cheatsheet",
            "quick-wins",
        ]
        for key in expected_keys:
            assert key in mapping, f"Expected key '{key}' not found. Available: {sorted(mapping.keys())[:10]}..."

    def test_knowledge_dir_exists(self):
        assert KNOWLEDGE_DIR.is_dir(), f"Knowledge dir not found: {KNOWLEDGE_DIR}"


# ═══════════════════════════════════════════════════════════════════════════
# Read Knowledge
# ═══════════════════════════════════════════════════════════════════════════


class TestReadKnowledge:
    def test_read_existing_topic(self):
        """Should read web-cheatsheet successfully."""
        content = read_knowledge("web-cheatsheet")
        assert len(content) > 100
        # Should be markdown content
        assert "#" in content  # Has headings

    def test_read_with_underscores(self):
        """Should be lenient with underscore input."""
        content = read_knowledge("web_cheatsheet")
        assert len(content) > 100

    def test_read_nonexistent_returns_listing(self):
        """Should return helpful listing for unknown topic."""
        content = read_knowledge("totally-nonexistent-topic-xyz")
        assert "not found" in content.lower() or "Available" in content

    def test_read_directory_path(self):
        """Reading a directory should return listing of files."""
        content = read_knowledge("attack-chains")
        # Should list available files in the directory
        assert "numasec://kb/" in content or len(content) > 50

    def test_fuzzy_search(self):
        """Partial match should work via fuzzy search."""
        # "web" should match "web-cheatsheet"
        content = read_knowledge("web")
        # Should return some content (either the file or a listing)
        assert len(content) > 50

    def test_read_nested_file(self):
        """Should read files in subdirectories."""
        mapping = discover_knowledge_files()
        # Find any nested key
        nested_keys = [k for k in mapping if "/" in k]
        if nested_keys:
            content = read_knowledge(nested_keys[0])
            assert len(content) > 10


# ═══════════════════════════════════════════════════════════════════════════
# List Knowledge Topics
# ═══════════════════════════════════════════════════════════════════════════


class TestListKnowledgeTopics:
    def test_returns_list(self):
        topics = list_knowledge_topics()
        assert isinstance(topics, list)
        assert len(topics) >= 30

    def test_topic_structure(self):
        """Each topic should have uri, name, description."""
        topics = list_knowledge_topics()
        for topic in topics:
            assert "uri" in topic
            assert "name" in topic
            assert "description" in topic
            assert topic["uri"].startswith("numasec://kb/")
            assert len(topic["name"]) > 0
            assert len(topic["description"]) > 0

    def test_topics_sorted(self):
        """Topics should be sorted alphabetically."""
        topics = list_knowledge_topics()
        names = [t["name"] for t in topics]
        assert names == sorted(names)
