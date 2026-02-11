"""
NumaSec Standards — CVSS v3.1, CWE mapping, OWASP Top 10 classification.

Auto-enrichment for security findings:
  Finding title/type → CWE-ID → OWASP category → CVSS score
"""

from numasec.standards.cvss import calculate_cvss_score, cvss_from_severity
from numasec.standards.cwe_mapping import map_to_cwe, CWE_DATABASE
from numasec.standards.owasp import map_cwe_to_owasp, OWASP_TOP_10

__all__ = [
    "calculate_cvss_score",
    "cvss_from_severity",
    "map_to_cwe",
    "CWE_DATABASE",
    "map_cwe_to_owasp",
    "OWASP_TOP_10",
    "enrich_finding",
]


def enrich_finding(finding) -> None:
    """Auto-enrich a Finding with CWE, CVSS, and OWASP data.

    Modifies the finding in-place. Only fills in empty fields.

    Args:
        finding: A Finding instance (from numasec.state)
    """
    title_lower = (finding.title + " " + finding.description).lower()

    # 1. CWE mapping (if not already set)
    if not finding.cwe_id:
        cwe = map_to_cwe(title_lower)
        if cwe:
            finding.cwe_id = cwe["id"]

    # 2. CVSS score (if not already set)
    if not finding.cvss_score:
        finding.cvss_score = cvss_from_severity(finding.severity)

    # 3. OWASP category (if not already set)
    if not finding.owasp_category and finding.cwe_id:
        owasp = map_cwe_to_owasp(finding.cwe_id)
        if owasp:
            finding.owasp_category = f"{owasp['id']} - {owasp['name']}"
