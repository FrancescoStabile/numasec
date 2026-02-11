"""
Tests for PDF report generation.
"""

import pytest

# reportlab is optional — skip all tests if not installed
reportlab = pytest.importorskip("reportlab", reason="reportlab not installed")

from numasec.pdf_report import generate_pdf_report, _severity_chart, _check_reportlab
from numasec.state import State, Finding
from numasec.planner import generate_plan
from numasec.target_profile import TargetProfile, Port, Technology


@pytest.fixture
def state_with_findings():
    """State with diverse severity findings for PDF testing."""
    s = State()
    s.profile.target = "http://test.example.com"
    s.profile.add_port(Port(number=80, service="http", product="nginx", version="1.21"))
    s.profile.add_port(Port(number=443, service="https"))
    s.profile.add_technology(Technology(name="nginx", version="1.21", category="web_server"))

    s.plan = generate_plan("Test http://test.example.com", s.profile)

    s.add_finding(Finding(
        title="SQL Injection in login form",
        severity="critical",
        description="Error-based SQLi in username parameter allows DB dump.",
        evidence="POST /login username=admin'-- → 500 with SQL error",
    ))
    s.add_finding(Finding(
        title="Cross-Site Scripting in search",
        severity="high",
        description="Reflected XSS in q parameter.",
        evidence="GET /search?q=<script>alert(1)</script> → reflected in page",
    ))
    s.add_finding(Finding(
        title="Missing HSTS header",
        severity="low",
        description="Strict-Transport-Security header not set.",
    ))
    s.add_finding(Finding(
        title="Server version disclosure",
        severity="info",
        description="nginx/1.21 in Server header.",
    ))
    return s


class TestPDFReport:
    """PDF generation tests."""

    def test_generates_bytes(self, state_with_findings):
        pdf = generate_pdf_report(state_with_findings, target="http://test.example.com")
        assert isinstance(pdf, bytes)
        assert len(pdf) > 1000  # non-trivial size

    def test_pdf_magic_bytes(self, state_with_findings):
        """PDF files start with %PDF."""
        pdf = generate_pdf_report(state_with_findings)
        assert pdf[:5] == b"%PDF-"

    def test_empty_state(self):
        s = State()
        pdf = generate_pdf_report(s, target="empty")
        assert isinstance(pdf, bytes)
        assert pdf[:5] == b"%PDF-"

    def test_session_id_and_cost(self, state_with_findings):
        pdf = generate_pdf_report(
            state_with_findings,
            target="http://test.example.com",
            session_id="abc123def456",
            cost=0.1234,
        )
        assert len(pdf) > 1000

    def test_severity_chart(self, state_with_findings):
        chart = _severity_chart(state_with_findings.findings)
        assert chart is not None

    def test_severity_chart_empty(self):
        chart = _severity_chart([])
        assert chart is None
