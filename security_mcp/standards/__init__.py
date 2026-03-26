"""CWE/CVSS/OWASP/ATT&CK auto-enrichment for findings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from security_mcp.standards.attack import get_attack_technique
from security_mcp.standards.cvss import calculate_cvss_score
from security_mcp.standards.cvss_vectors import (
    calculate_base_score,
    derive_vector_from_cwe,
    format_vector_string,
)
from security_mcp.standards.cwe_mapping import get_cwe_info
from security_mcp.standards.owasp import CWE_OWASP_MAP, get_owasp_category

if TYPE_CHECKING:
    from security_mcp.models.finding import Finding


def enrich_finding(finding: Finding) -> Finding:
    """Auto-enrich a finding with CWE, CVSS v3.1, OWASP, and ATT&CK data.

    Called by save_finding in state_tools.py after the Finding is created.

    Enrichment order:
    1. CWE — inferred from title + description if not already set
    2. OWASP category — mapped from CWE
    3. CVSS v3.1 vector + score — computed from CWE vector map;
       falls back to severity-based approximation when CWE is unmapped
    4. MITRE ATT&CK technique — mapped from CWE
    """
    # Step 1: CWE inference
    if not finding.cwe_id:
        cwe_info = get_cwe_info(finding.title, finding.description)
        if cwe_info:
            finding.cwe_id = cwe_info["id"]

    # Step 2: OWASP category
    if not finding.owasp_category and finding.cwe_id:
        finding.owasp_category = get_owasp_category(finding.cwe_id)

    # Step 3: CVSS v3.1 — use proper vector when CWE is known
    if not finding.cvss_vector and finding.cwe_id:
        vector = derive_vector_from_cwe(finding.cwe_id)
        if vector is not None:
            finding.cvss_score = calculate_base_score(vector)
            finding.cvss_vector = format_vector_string(vector)

    # Fallback: severity-based approximate score (no CWE or unmapped CWE)
    if finding.cvss_score is None:
        finding.cvss_score = calculate_cvss_score(finding.severity.value)

    # Step 4: ATT&CK technique
    if not finding.attack_technique and finding.cwe_id:
        technique = get_attack_technique(finding.cwe_id)
        if technique:
            finding.attack_technique = f"{technique['technique_id']} - {technique['technique_name']}"

    return finding


__all__ = [
    "CWE_OWASP_MAP",
    "enrich_finding",
    "get_owasp_category",
]
