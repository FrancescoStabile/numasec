"""Tests for security_mcp.reporting (SARIF, Markdown, HTML)."""

from __future__ import annotations

import json

import pytest

from security_mcp.models.finding import Finding
from security_mcp.reporting.html import generate_html_report
from security_mcp.reporting.markdown import generate_markdown_report
from security_mcp.reporting.sarif import (
    generate_sarif_report,
    sarif_to_json,
    severity_to_sarif_level,
)


@pytest.fixture()
def sample_findings() -> list[Finding]:
    return [
        Finding(
            title="SQL Injection in login",
            severity="critical",
            description="User input concatenated into SQL query",
            url="https://example.com/login",
            method="POST",
            parameter="username",
            evidence="' OR '1'='1",
            cwe_id="CWE-89",
            cvss_score=9.8,
            owasp_category="A03:2021",
            target="example.com",
            remediation_summary="Use parameterized queries",
        ),
        Finding(
            title="Missing security headers",
            severity="low",
            description="X-Frame-Options header missing",
            url="https://example.com/",
            method="GET",
            target="example.com",
            cwe_id="CWE-16",
        ),
    ]


# ---------------------------------------------------------------------------
# SARIF severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_critical_to_error(self):
        assert severity_to_sarif_level("critical") == "error"

    def test_high_to_error(self):
        assert severity_to_sarif_level("high") == "error"

    def test_medium_to_warning(self):
        assert severity_to_sarif_level("medium") == "warning"

    def test_low_to_note(self):
        assert severity_to_sarif_level("low") == "note"

    def test_info_to_none(self):
        assert severity_to_sarif_level("info") == "none"

    def test_unknown_to_none(self):
        assert severity_to_sarif_level("unknown") == "none"


# ---------------------------------------------------------------------------
# SARIF report generation
# ---------------------------------------------------------------------------


class TestSarifReport:
    def test_structure(self, sample_findings: list[Finding]):
        report = generate_sarif_report(sample_findings)

        assert report["version"] == "2.1.0"
        assert "$schema" in report
        assert len(report["runs"]) == 1

        run = report["runs"][0]
        assert run["tool"]["driver"]["name"] == "security_mcp"
        assert len(run["results"]) == 2

    def test_results_have_rule_ids(self, sample_findings: list[Finding]):
        report = generate_sarif_report(sample_findings)
        results = report["runs"][0]["results"]
        for result in results:
            assert "ruleId" in result
            assert result["ruleId"].startswith("security_mcp/")

    def test_results_have_levels(self, sample_findings: list[Finding]):
        report = generate_sarif_report(sample_findings)
        results = report["runs"][0]["results"]
        assert results[0]["level"] == "error"  # critical
        assert results[1]["level"] == "note"   # low

    def test_dast_properties(self, sample_findings: list[Finding]):
        report = generate_sarif_report(sample_findings)
        props = report["runs"][0]["results"][0]["properties"]
        assert props["security_mcp:http_method"] == "POST"
        assert props["security_mcp:parameter"] == "username"
        assert props["security_mcp:cwe"] == "CWE-89"

    def test_locations(self, sample_findings: list[Finding]):
        report = generate_sarif_report(sample_findings)
        result = report["runs"][0]["results"][0]
        assert len(result["locations"]) == 1
        loc = result["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com/login"

    def test_rules_deduplicated(self, sample_findings: list[Finding]):
        report = generate_sarif_report(sample_findings)
        rules = report["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

    def test_empty_findings(self):
        report = generate_sarif_report([])
        assert report["runs"][0]["results"] == []

    def test_sarif_to_json(self, sample_findings: list[Finding]):
        json_str = sarif_to_json(sample_findings)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


class TestMarkdownReport:
    def test_has_header(self, sample_findings: list[Finding]):
        md = generate_markdown_report(sample_findings, target="example.com")
        assert "# security-mcp" in md
        assert "example.com" in md

    def test_has_summary(self, sample_findings: list[Finding]):
        md = generate_markdown_report(sample_findings)
        assert "Executive Summary" in md
        assert "Risk Score" in md
        assert "Critical" in md

    def test_findings_listed(self, sample_findings: list[Finding]):
        md = generate_markdown_report(sample_findings)
        assert "SQL Injection in login" in md
        assert "Missing security headers" in md

    def test_evidence_included(self, sample_findings: list[Finding]):
        md = generate_markdown_report(sample_findings, include_evidence=True)
        assert "OR '1'='1" in md

    def test_evidence_excluded(self, sample_findings: list[Finding]):
        md = generate_markdown_report(sample_findings, include_evidence=False)
        # Description should still be there but not in code block evidence
        assert "```" not in md

    def test_empty_findings(self):
        md = generate_markdown_report([])
        assert "No security findings" in md

    def test_has_cwe_info(self, sample_findings: list[Finding]):
        md = generate_markdown_report(sample_findings)
        assert "CWE-89" in md

    def test_has_remediation(self, sample_findings: list[Finding]):
        md = generate_markdown_report(sample_findings)
        assert "parameterized queries" in md


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


class TestHtmlReport:
    def test_valid_html(self, sample_findings: list[Finding]):
        html = generate_html_report(sample_findings, target="example.com")
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_has_target(self, sample_findings: list[Finding]):
        html = generate_html_report(sample_findings, target="example.com")
        assert "example.com" in html

    def test_has_findings(self, sample_findings: list[Finding]):
        html = generate_html_report(sample_findings)
        assert "SQL Injection in login" in html

    def test_severity_badge(self, sample_findings: list[Finding]):
        html = generate_html_report(sample_findings)
        assert "CRITICAL" in html
        assert "LOW" in html

    def test_empty_findings(self):
        html = generate_html_report([])
        assert "No security findings" in html

    def test_evidence_excluded(self, sample_findings: list[Finding]):
        html = generate_html_report(sample_findings, include_evidence=False)
        assert "Evidence" not in html

    def test_escapes_html(self):
        finding = Finding(
            title="XSS <script>alert(1)</script>",
            severity="high",
            description="Contains <dangerous> HTML",
        )
        html = generate_html_report([finding])
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
