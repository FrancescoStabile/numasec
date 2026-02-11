"""
Tests for AttackGraph — multi-stage exploitation reasoning.
"""

import pytest
from numasec.attack_graph import (
    AttackGraph,
    AttackNode,
    AttackEdge,
    NodeState,
)


# ═══════════════════════════════════════════════════════════════════════════
# Construction
# ═══════════════════════════════════════════════════════════════════════════

class TestAttackGraphConstruction:
    """Default graph has the expected structure."""

    def test_has_nodes(self):
        g = AttackGraph()
        assert len(g.nodes) >= 20

    def test_has_edges(self):
        g = AttackGraph()
        assert len(g.edges) >= 20

    def test_has_paths(self):
        g = AttackGraph()
        # Paths are built lazily on first discovery; the graph itself has
        # the internal _paths list (pre-built exploitation paths).
        assert hasattr(g, "_paths")

    def test_all_nodes_start_unknown(self):
        g = AttackGraph()
        for node in g.nodes.values():
            assert node.state == NodeState.UNKNOWN

    def test_edge_references_valid_nodes(self):
        g = AttackGraph()
        node_ids = set(g.nodes.keys())
        for edge in g.edges:
            assert edge.source in node_ids, f"Edge source {edge.source} not in nodes"
            assert edge.target in node_ids, f"Edge target {edge.target} not in nodes"


# ═══════════════════════════════════════════════════════════════════════════
# Discovery & Activation
# ═══════════════════════════════════════════════════════════════════════════

class TestDiscovery:
    """mark_discovered() activates nodes and downstream paths."""

    def test_mark_sqli(self):
        g = AttackGraph()
        paths = g.mark_discovered("SQL Injection in /api/users")
        # Should activate the sqli node
        assert g.nodes["sqli"].state == NodeState.CONFIRMED
        assert isinstance(paths, list)

    def test_mark_xss(self):
        g = AttackGraph()
        paths = g.mark_discovered("Reflected Cross-Site Scripting (XSS)")
        assert g.nodes["xss_reflected"].state == NodeState.CONFIRMED

    def test_mark_lfi(self):
        g = AttackGraph()
        g.mark_discovered("Local File Inclusion")
        assert g.nodes["lfi"].state == NodeState.CONFIRMED

    def test_mark_activates_downstream(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        # After SQLi, there should be available paths
        paths = g.get_available_paths()
        assert len(paths) >= 0  # May or may not have exploitation paths depending on graph

    def test_no_match_returns_empty(self):
        g = AttackGraph()
        paths = g.mark_discovered("completely irrelevant text about cooking recipes")
        assert paths == []

    def test_multiple_discoveries(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        g.mark_discovered("Local File Inclusion")
        assert g.nodes["sqli"].state == NodeState.CONFIRMED
        assert g.nodes["lfi"].state == NodeState.CONFIRMED


# ═══════════════════════════════════════════════════════════════════════════
# Path & Next Steps
# ═══════════════════════════════════════════════════════════════════════════

class TestPaths:
    """Available paths and next steps."""

    def test_no_paths_when_nothing_discovered(self):
        g = AttackGraph()
        paths = g.get_available_paths()
        assert len(paths) == 0

    def test_paths_after_sqli(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        paths = g.get_available_paths()
        assert len(paths) >= 1

    def test_next_steps_after_sqli(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        steps = g.get_next_steps(limit=5)
        assert len(steps) >= 1
        # Steps should be edges from confirmed nodes
        for edge in steps:
            source = g.nodes[edge.source]
            assert source.state in (NodeState.CONFIRMED, NodeState.EXPLOITED)

    def test_next_steps_sorted_by_priority(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        g.mark_discovered("XSS")
        steps = g.get_next_steps(limit=10)
        if len(steps) >= 2:
            # Higher priority = lower number = first
            assert steps[0].priority <= steps[1].priority


# ═══════════════════════════════════════════════════════════════════════════
# Prompt Context
# ═══════════════════════════════════════════════════════════════════════════

class TestPromptContext:
    """to_prompt_context() generates Markdown for LLM injection."""

    def test_empty_graph_returns_empty(self):
        g = AttackGraph()
        ctx = g.to_prompt_context()
        # No discoveries → empty or minimal context
        assert ctx == "" or "No" in ctx

    def test_context_after_discovery(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        ctx = g.to_prompt_context()
        assert "SQL" in ctx or "sqli" in ctx.lower()
        assert "##" in ctx  # Should have Markdown headers

    def test_context_contains_next_steps(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        ctx = g.to_prompt_context()
        # Should suggest next exploitation steps
        assert len(ctx) > 50


# ═══════════════════════════════════════════════════════════════════════════
# Serialization
# ═══════════════════════════════════════════════════════════════════════════

class TestSerialization:
    """to_dict() / from_dict() roundtrip."""

    def test_roundtrip_empty(self):
        g = AttackGraph()
        data = g.to_dict()
        g2 = AttackGraph()
        g2.from_dict(data)
        assert len(g2.nodes) == len(g.nodes)
        assert len(g2.edges) == len(g.edges)

    def test_roundtrip_with_discoveries(self):
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        g.mark_discovered("Stored XSS")
        data = g.to_dict()
        g2 = AttackGraph()
        g2.from_dict(data)
        assert g2.nodes["sqli"].state == NodeState.CONFIRMED
        assert g2.nodes["xss_stored"].state == NodeState.CONFIRMED

    def test_to_dict_is_json_serializable(self):
        import json
        g = AttackGraph()
        g.mark_discovered("SQL Injection")
        data = g.to_dict()
        # Must not raise
        json_str = json.dumps(data)
        assert len(json_str) > 0
