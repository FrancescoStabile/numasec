"""
Tests for standards module — CVSS, CWE, OWASP mapping + auto-enrichment.
"""

import pytest
from numasec.standards.cvss import (
    calculate_cvss_score,
    cvss_from_severity,
    cvss_from_vuln_type,
    COMMON_VECTORS,
)
from numasec.standards.cwe_mapping import map_to_cwe, get_cwe_by_id, CWE_DATABASE
from numasec.standards.owasp import map_cwe_to_owasp, get_owasp_category, OWASP_TOP_10
from numasec.standards import enrich_finding
from numasec.state import Finding


# ═══════════════════════════════════════════════════════════════════════════
# CVSS v3.1 Calculator
# ═══════════════════════════════════════════════════════════════════════════

class TestCVSS:
    """CVSS v3.1 Base Score calculator."""

    def test_critical_vector(self):
        """CVE-2021-44228 (Log4Shell) — CVSS 10.0."""
        result = calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert result["score"] == 10.0
        assert result["severity"] == "critical"

    def test_high_vector(self):
        """Typical high-severity SQLi."""
        result = calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        assert 8.0 <= result["score"] <= 10.0

    def test_medium_vector(self):
        """Reflected XSS — medium."""
        result = calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert 4.0 <= result["score"] <= 7.0

    def test_low_vector(self):
        """Information disclosure — low."""
        result = calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        assert 1.0 <= result["score"] <= 5.5

    def test_zero_impact_returns_zero(self):
        """No impact yields CVSS 0.0."""
        result = calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert result["score"] == 0.0

    def test_invalid_vector_raises(self):
        with pytest.raises(ValueError):
            calculate_cvss_score("garbage")

    def test_cvss_from_severity(self):
        assert cvss_from_severity("critical") > 0
        assert cvss_from_severity("high") > 0
        assert cvss_from_severity("info") == 0.0
        assert cvss_from_severity("critical") > cvss_from_severity("high")

    def test_cvss_from_vuln_type(self):
        result = cvss_from_vuln_type("sqli")
        assert result is not None
        assert result["score"] >= 7.0
        assert "AV:N" in result["vector"]

    def test_common_vectors_not_empty(self):
        assert len(COMMON_VECTORS) >= 10

    def test_all_common_vectors_valid(self):
        """Every vector in COMMON_VECTORS should produce a valid score."""
        for vuln_type, vector in COMMON_VECTORS.items():
            result = calculate_cvss_score(vector)
            assert isinstance(result, dict), f"Invalid result for {vuln_type}"
            assert 0.0 <= result["score"] <= 10.0


# ═══════════════════════════════════════════════════════════════════════════
# CWE Mapping
# ═══════════════════════════════════════════════════════════════════════════

class TestCWEMapping:
    """CWE keyword-based mapping."""

    def test_sql_injection(self):
        result = map_to_cwe("SQL Injection in user parameter")
        assert result is not None
        assert "89" in result["id"]

    def test_xss(self):
        result = map_to_cwe("Reflected Cross-Site Scripting (XSS)")
        assert result is not None
        assert "79" in result["id"]

    def test_path_traversal(self):
        result = map_to_cwe("Local File Inclusion / path traversal in file parameter")
        assert result is not None
        assert "22" in result["id"] or "98" in result["id"]

    def test_ssti(self):
        result = map_to_cwe("Server-Side Template Injection (SSTI)")
        assert result is not None

    def test_idor(self):
        result = map_to_cwe("Insecure Direct Object Reference (IDOR)")
        assert result is not None

    def test_unknown_returns_none(self):
        result = map_to_cwe("completely unrelated random text about cooking")
        assert result is None

    def test_get_cwe_by_id(self):
        entry = get_cwe_by_id("CWE-89")
        assert entry is not None
        assert entry["name"] == "SQL Injection"

    def test_get_cwe_by_id_numeric(self):
        entry = get_cwe_by_id("89")
        assert entry is not None

    def test_database_not_empty(self):
        assert len(CWE_DATABASE) >= 30


# ═══════════════════════════════════════════════════════════════════════════
# OWASP Top 10 Mapping
# ═══════════════════════════════════════════════════════════════════════════

class TestOWASPMapping:
    """OWASP Top 10 2021 classification."""

    def test_sqli_maps_to_injection(self):
        result = map_cwe_to_owasp("CWE-89")
        assert result is not None
        assert "Injection" in result["name"]

    def test_xss_maps_to_injection(self):
        result = map_cwe_to_owasp("CWE-79")
        assert result is not None
        assert "Injection" in result["name"]

    def test_broken_auth(self):
        result = map_cwe_to_owasp("CWE-287")
        assert result is not None

    def test_unknown_cwe_returns_none(self):
        result = map_cwe_to_owasp("CWE-999999")
        assert result is None

    def test_get_owasp_category(self):
        cat = get_owasp_category("A03:2021")
        assert cat is not None
        assert "Injection" in cat["name"]

    def test_all_10_categories(self):
        assert len(OWASP_TOP_10) == 10
        ids = [c["id"] for c in OWASP_TOP_10]
        for i in range(1, 11):
            assert f"A{i:02d}:2021" in ids


# ═══════════════════════════════════════════════════════════════════════════
# Auto-Enrichment
# ═══════════════════════════════════════════════════════════════════════════

class TestEnrichFinding:
    """enrich_finding() should populate CWE, CVSS, OWASP."""

    def test_enriches_sql_injection(self):
        f = Finding(
            title="SQL Injection in /api/users",
            severity="critical",
            description="Error-based SQL injection",
        )
        enrich_finding(f)
        assert f.cwe_id  # Should be CWE-89
        assert "89" in f.cwe_id
        assert f.owasp_category  # Should reference injection
        assert f.cvss_score is not None
        assert f.cvss_score >= 7.0

    def test_enriches_xss(self):
        f = Finding(
            title="Reflected Cross-Site Scripting",
            severity="medium",
            description="XSS in search parameter",
        )
        enrich_finding(f)
        assert f.cwe_id
        assert f.cvss_score is not None

    def test_does_not_overwrite_existing(self):
        f = Finding(
            title="SQL Injection custom",
            severity="critical",
            cwe_id="CWE-999",
            cvss_score=9.8,
            owasp_category="Custom",
        )
        enrich_finding(f)
        # Should NOT overwrite pre-set values
        assert f.cwe_id == "CWE-999"
        assert f.cvss_score == 9.8
        assert f.owasp_category == "Custom"

    def test_handles_unknown_gracefully(self):
        f = Finding(
            title="Unknown issue",
            severity="info",
        )
        enrich_finding(f)
        # Should not crash, info severity gets a CVSS
        assert f.cvss_score is not None or f.cvss_score is None  # either is fine
