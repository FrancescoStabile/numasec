"""CVSS score utilities.

Provides:
- ``calculate_cvss_score(severity)`` — backward-compatible approximation from
  severity string.  Use ``calculate_cvss_from_cwe`` when a CWE ID is available
  for a proper CVSS 3.1 vector + score.
- ``cvss_to_severity(score)`` — convert a numeric score back to a severity label.
- ``calculate_cvss_from_cwe(cwe_id)`` — return the (score, vector_string) pair
  derived from the CWE → vector map in ``cvss_vectors.py``.
"""

from __future__ import annotations

from security_mcp.standards.cvss_vectors import (
    calculate_base_score,
    derive_vector_from_cwe,
    format_vector_string,
)

# ---------------------------------------------------------------------------
# Severity-based fallback scores (backward-compatible)
# ---------------------------------------------------------------------------

_SEVERITY_FALLBACK_MAP: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}


def calculate_cvss_score(severity: str) -> float:
    """Return an approximate CVSS score from a severity label.

    This is a **fallback** used only when no CWE ID is available.
    Prefer ``calculate_cvss_from_cwe`` for a proper CVSS 3.1 vector score.
    """
    return _SEVERITY_FALLBACK_MAP.get(severity.lower(), 0.0)


def cvss_to_severity(score: float) -> str:
    """Convert a CVSS v3.1 base score to a severity label (CVSS spec §5)."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def calculate_cvss_from_cwe(cwe_id: str) -> tuple[float, str]:
    """Return ``(score, vector_string)`` for a CWE ID.

    Uses the CWE → CVSS 3.1 vector map and the official base score formula.
    Returns ``(0.0, "")`` if the CWE ID is not in the mapping.
    """
    vector = derive_vector_from_cwe(cwe_id)
    if vector is None:
        return 0.0, ""
    score = calculate_base_score(vector)
    return score, format_vector_string(vector)
