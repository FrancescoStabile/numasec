"""Smoke tests for the security-mcp pipeline.

These tests validate that shared components can be instantiated and wired
together correctly WITHOUT requiring external resources (API keys, network,
Docker). They use mocks for the LLM and tool execution layers.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_mcp.core.planner import DeterministicPlanner, ReplanSignal
from security_mcp.models.enums import PhaseStatus, PTESPhase
from security_mcp.models.finding import Finding
from security_mcp.models.plan import AttackPlan, AttackPhase, AttackStep
from security_mcp.models.target import TargetProfile


# ---------------------------------------------------------------------------
# Component instantiation smoke tests
# ---------------------------------------------------------------------------

class TestComponentInstantiation:
    """Verify shared components can be created."""

    def test_planner_creates(self):
        planner = DeterministicPlanner()
        assert planner is not None

    def test_tool_registry_creates(self):
        from security_mcp.tools import create_default_tool_registry
        registry = create_default_tool_registry()
        assert len(registry.available_tools) >= 14


# ---------------------------------------------------------------------------
# Plan generation smoke tests
# ---------------------------------------------------------------------------

class TestPlanGeneration:
    """Verify plan generation for all scopes and target types."""

    def test_quick_plan(self):
        planner = DeterministicPlanner()
        profile = TargetProfile(target="http://example.com")
        plan = planner.create_plan(profile, scope="quick")

        assert isinstance(plan, AttackPlan)
        assert len(plan.phases) >= 3  # recon, mapping, vuln, reporting
        assert plan.scope == "quick"

    def test_standard_plan_has_exploitation(self):
        planner = DeterministicPlanner()
        profile = TargetProfile(target="http://example.com")
        plan = planner.create_plan(profile, scope="standard")

        phase_types = [p.phase for p in plan.phases]
        assert PTESPhase.EXPLOITATION in phase_types

    def test_deep_plan_has_more_steps(self):
        planner = DeterministicPlanner()
        profile = TargetProfile(target="http://example.com")
        quick = planner.create_plan(profile, scope="quick")
        deep = planner.create_plan(profile, scope="deep")

        quick_steps = sum(len(p.steps) for p in quick.phases)
        deep_steps = sum(len(p.steps) for p in deep.phases)
        assert deep_steps >= quick_steps

    def test_plan_with_web_technologies(self):
        from security_mcp.models.target import Port, Technology
        planner = DeterministicPlanner()
        profile = TargetProfile(
            target="http://example.com",
            ports=[Port(number=80, service="http")],
            technologies=[Technology(name="PHP", version="8.2")],
        )
        plan = planner.create_plan(profile, scope="standard")
        all_ids = [s.id for p in plan.phases for s in p.steps]
        assert "vuln_lfi" in all_ids  # PHP triggers LFI test

    def test_plan_ptt_rendering(self):
        planner = DeterministicPlanner()
        profile = TargetProfile(target="http://example.com")
        plan = planner.create_plan(profile, scope="quick")
        ptt = plan.to_prompt_context()

        assert "http://example.com" in ptt
        assert "PENDING" in ptt

    def test_replan_on_waf(self):
        planner = DeterministicPlanner()
        profile = TargetProfile(target="http://example.com")
        plan = planner.create_plan(profile, scope="standard")

        signal = ReplanSignal(type="waf_detected")
        new_plan = planner.replan(plan, signal)

        all_ids = [s.id for p in new_plan.phases for s in p.steps]
        assert "waf_evasion" in all_ids


# ---------------------------------------------------------------------------
# SARIF report smoke tests
# ---------------------------------------------------------------------------

class TestSARIFSmoke:
    """Verify SARIF report generation from findings."""

    def test_empty_report(self):
        from security_mcp.reporting.sarif import generate_sarif_report

        report = generate_sarif_report([])
        assert report["version"] == "2.1.0"
        assert len(report["runs"]) == 1
        assert report["runs"][0]["results"] == []

    def test_report_with_findings(self):
        from security_mcp.reporting.sarif import generate_sarif_report

        findings = [
            Finding(title="SQL Injection", severity="critical", url="/api", cwe_id="CWE-89"),
            Finding(title="Missing CSP Header", severity="medium", url="/"),
        ]
        report = generate_sarif_report(findings, target="http://example.com")

        assert len(report["runs"][0]["results"]) == 2
        assert report["runs"][0]["tool"]["driver"]["name"] == "security_mcp"
        assert len(report["runs"][0]["tool"]["driver"]["rules"]) == 2

    def test_sarif_json_serializable(self):
        from security_mcp.reporting.sarif import sarif_to_json

        findings = [Finding(title="Test Finding", severity="high", url="/test")]
        json_str = sarif_to_json(findings)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_sarif_dast_extensions(self):
        from security_mcp.reporting.sarif import generate_sarif_report

        findings = [
            Finding(title="SQLi in login", severity="critical", url="/login", method="POST", parameter="email"),
        ]
        report = generate_sarif_report(findings, target="http://example.com")
        result = report["runs"][0]["results"][0]

        # Check DAST-specific properties
        assert result["properties"]["security_mcp:http_method"] == "POST"
        assert result["properties"]["security_mcp:parameter"] == "email"


# ---------------------------------------------------------------------------
# Knowledge Base smoke tests
# ---------------------------------------------------------------------------

class TestKnowledgeBaseSmoke:
    """Verify KB loading and retrieval."""

    def test_kb_loads_templates(self):
        from security_mcp.knowledge import KnowledgeLoader

        loader = KnowledgeLoader()
        templates = loader.load_all()
        assert len(templates) > 0

    def test_kb_chunks_templates(self):
        from security_mcp.knowledge import KnowledgeChunker, KnowledgeLoader

        loader = KnowledgeLoader()
        templates = loader.load_all()
        chunker = KnowledgeChunker()

        total_chunks = 0
        for tpl in templates.values():
            chunks = chunker.chunk(tpl)
            total_chunks += len(chunks)

        assert total_chunks > 0

    def test_kb_retriever_queries(self):
        from security_mcp.knowledge import KnowledgeChunker, KnowledgeLoader, KnowledgeRetriever

        loader = KnowledgeLoader()
        templates = loader.load_all()
        chunker = KnowledgeChunker()

        all_chunks = []
        for tpl in templates.values():
            all_chunks.extend(chunker.chunk(tpl))

        retriever = KnowledgeRetriever(all_chunks)
        results = retriever.query("SQL injection", top_k=3)
        assert len(results) <= 3


# ---------------------------------------------------------------------------
# Scorer smoke tests
# ---------------------------------------------------------------------------

class TestScorerSmoke:
    """Verify the benchmark scorer logic."""

    def test_perfect_score(self):
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "sqli"}, {"type": "xss"}]
        truth = [{"type": "sqli"}, {"type": "xss"}]
        scores = calculate_scores(findings, truth)
        assert scores["precision"] == 1.0
        assert scores["recall"] == 1.0
        assert scores["f1"] == 1.0

    def test_zero_score(self):
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "csrf"}]
        truth = [{"type": "sqli"}]
        scores = calculate_scores(findings, truth)
        assert scores["recall"] == 0.0

    def test_partial_recall(self):
        from tests.benchmarks.scorer import calculate_scores

        findings = [{"type": "sqli"}, {"type": "info_leak"}]
        truth = [{"type": "sqli"}, {"type": "xss"}, {"type": "csrf"}]
        scores = calculate_scores(findings, truth)
        assert scores["true_positives"] == 1
        assert scores["recall"] == pytest.approx(1 / 3, abs=0.01)

    def test_empty_findings(self):
        from tests.benchmarks.scorer import calculate_scores

        scores = calculate_scores([], [{"type": "sqli"}])
        assert scores["recall"] == 0.0
        assert scores["f1"] == 0.0

    def test_weighted_recall_critical_matters_more(self):
        """Missing a critical vuln should penalise weighted_recall more than missing a medium."""
        from tests.benchmarks.scorer import calculate_scores

        truth = [
            {"type": "sqli", "severity": "critical"},
            {"type": "xss", "severity": "medium"},
        ]

        # Find only the medium-severity vuln
        scores_medium_only = calculate_scores([{"type": "xss"}], truth)
        # Find only the critical vuln
        scores_critical_only = calculate_scores([{"type": "sqli"}], truth)

        # Both have recall 0.5, but weighted_recall should differ
        assert scores_medium_only["recall"] == scores_critical_only["recall"]
        assert scores_critical_only["weighted_recall"] > scores_medium_only["weighted_recall"]

    def test_weighted_recall_in_output(self):
        """weighted_recall should always be present in scorer output."""
        from tests.benchmarks.scorer import calculate_scores

        scores = calculate_scores([{"type": "sqli"}], [{"type": "sqli", "severity": "high"}])
        assert "weighted_recall" in scores
        assert scores["weighted_recall"] == 1.0


# ---------------------------------------------------------------------------
# Ground truth completeness
# ---------------------------------------------------------------------------

class TestGroundTruth:
    """Verify ground truth data is well-formed."""

    def test_juice_shop_ground_truth(self):
        from tests.benchmarks.ground_truth import JUICE_SHOP_GROUND_TRUTH

        assert JUICE_SHOP_GROUND_TRUTH["target"] == "http://localhost:3000"
        assert len(JUICE_SHOP_GROUND_TRUTH["vulns"]) >= 10
        for vuln in JUICE_SHOP_GROUND_TRUTH["vulns"]:
            assert "type" in vuln
            assert "location" in vuln
            assert "severity" in vuln

    def test_dvwa_ground_truth(self):
        from tests.benchmarks.ground_truth import DVWA_GROUND_TRUTH

        assert DVWA_GROUND_TRUTH["target"] == "http://localhost:8080"
        assert len(DVWA_GROUND_TRUTH["vulns"]) >= 7
        for vuln in DVWA_GROUND_TRUTH["vulns"]:
            assert "type" in vuln
            assert "severity" in vuln


# ---------------------------------------------------------------------------
# Plugin system smoke tests
# ---------------------------------------------------------------------------

