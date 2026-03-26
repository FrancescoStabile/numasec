"""Report generation: SARIF, JSON, HTML, Markdown."""

from __future__ import annotations

from collections import Counter
from typing import Any

from security_mcp.reporting.html import generate_html_report
from security_mcp.reporting.markdown import generate_markdown_report
from security_mcp.reporting.sarif import (
    generate_sarif_report,
    sarif_to_json,
    severity_to_sarif_level,
)

__all__ = [
    "build_executive_summary",
    "calculate_risk_score",
    "generate_html_report",
    "generate_markdown_report",
    "generate_sarif_report",
    "sarif_to_json",
    "severity_to_sarif_level",
]


_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 1.0,
}


def calculate_risk_score(findings: list[Any]) -> float:
    """Compute an aggregate risk score (0-100) from findings.

    Formula: ``min(100, sum(severity_weight * confidence))``
    """
    total = 0.0
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        weight = _SEVERITY_WEIGHTS.get(sev.lower(), 1.0)
        conf = getattr(f, "confidence", 0.5)
        total += weight * conf
    return min(100.0, round(total, 1))


def build_executive_summary(findings: list[Any], target: str = "") -> dict[str, Any]:
    """Build executive summary data from findings.

    Returns a dict with risk_score, severity_counts, top_remediation,
    and owasp_coverage_pct -- suitable for embedding in any report format.
    """
    severity_counts = Counter(
        f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        for f in findings
    )
    risk_score = calculate_risk_score(findings)

    # Top 3 remediation priorities (highest severity, then highest CVSS)
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -_SEVERITY_WEIGHTS.get(
                f.severity.value if hasattr(f.severity, "value") else str(f.severity), 0
            ),
            -(f.cvss_score or 0),
        ),
    )
    top_remediation = []
    for f in sorted_findings[:3]:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        entry = f"{f.title} ({f.cwe_id})" if f.cwe_id else f.title
        entry += f" at {f.url}" if f.url else ""
        entry += f" -- {sev.upper()}"
        top_remediation.append(entry)

    # OWASP coverage
    owasp_cats = {f.owasp_category for f in findings if f.owasp_category}
    owasp_pct = round(len(owasp_cats) / 10 * 100) if owasp_cats else 0

    return {
        "risk_score": risk_score,
        "total_findings": len(findings),
        "severity_counts": dict(severity_counts),
        "top_remediation": top_remediation,
        "owasp_categories_hit": sorted(owasp_cats),
        "owasp_coverage_pct": owasp_pct,
    }
