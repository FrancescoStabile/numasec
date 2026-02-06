"""
Tests for Report — report generation.
"""

import json
import pytest
import tempfile
from pathlib import Path
from numasec.report import (
    generate_markdown_report,
    generate_html_report,
    generate_json_report,
    write_report,
)


class TestMarkdownReport:
    def test_generates_report(self, populated_state):
        md = generate_markdown_report(populated_state, target="http://10.10.10.1:8080")
        assert "NumaSec" in md
        assert "10.10.10.1" in md
        assert "SQL Injection" in md

    def test_executive_summary(self, populated_state):
        md = generate_markdown_report(populated_state)
        assert "Executive Summary" in md
        assert "3 findings" in md or "3" in md

    def test_findings_sorted_by_severity(self, populated_state):
        md = generate_markdown_report(populated_state)
        # Critical should appear before low
        crit_pos = md.find("critical")
        low_pos = md.find("low")
        if crit_pos > -1 and low_pos > -1:
            assert crit_pos < low_pos

    def test_target_profile_section(self, populated_state):
        md = generate_markdown_report(populated_state)
        assert "Target Profile" in md
        assert "22" in md  # SSH port
        assert "Apache" in md

    def test_empty_findings(self, state):
        md = generate_markdown_report(state)
        assert "No vulnerabilities" in md

    def test_remediation_suggestions(self, populated_state):
        md = generate_markdown_report(populated_state)
        assert "Remediation" in md


class TestHtmlReport:
    def test_generates_valid_html(self, populated_state):
        html = generate_html_report(populated_state, target="http://10.10.10.1:8080")
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "NumaSec" in html

    def test_has_styles(self, populated_state):
        html = generate_html_report(populated_state)
        assert "<style>" in html
        assert "background" in html


class TestJsonReport:
    def test_generates_valid_json(self, populated_state):
        json_str = generate_json_report(populated_state, target="http://10.10.10.1:8080")
        data = json.loads(json_str)
        assert "metadata" in data
        assert "findings" in data
        assert "summary" in data

    def test_findings_in_json(self, populated_state):
        json_str = generate_json_report(populated_state)
        data = json.loads(json_str)
        assert data["summary"]["total_findings"] == 3
        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 1

    def test_target_profile_in_json(self, populated_state):
        json_str = generate_json_report(populated_state)
        data = json.loads(json_str)
        assert "target_profile" in data


class TestWriteReport:
    def test_write_markdown(self, populated_state, tmp_path):
        filepath = write_report(populated_state, output_dir=tmp_path, format="md")
        assert filepath.exists()
        assert filepath.suffix == ".md"
        content = filepath.read_text()
        assert "NumaSec" in content

    def test_write_html(self, populated_state, tmp_path):
        filepath = write_report(populated_state, output_dir=tmp_path, format="html")
        assert filepath.exists()
        assert filepath.suffix == ".html"

    def test_write_json(self, populated_state, tmp_path):
        filepath = write_report(populated_state, output_dir=tmp_path, format="json")
        assert filepath.exists()
        assert filepath.suffix == ".json"
        data = json.loads(filepath.read_text())
        assert "findings" in data
