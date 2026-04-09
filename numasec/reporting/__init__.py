"""Report generation: SARIF, JSON, HTML, Markdown."""

from __future__ import annotations

from collections import Counter
from typing import Any

from numasec.reporting.html import generate_html_report
from numasec.reporting.markdown import generate_markdown_report
from numasec.reporting.sarif import (
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

    Hybrid formula: when CVSS scores are available, uses 60% CVSS-based
    + 40% severity-based weighting. Falls back to severity-only when
    no CVSS data is present.
    """
    if not findings:
        return 0.0

    total_severity = 0.0
    total_cvss = 0.0
    cvss_count = 0

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        weight = _SEVERITY_WEIGHTS.get(sev.lower(), 1.0)
        conf = getattr(f, "confidence", 0.5)
        total_severity += weight * conf

        cvss = getattr(f, "cvss_score", None)
        if cvss and cvss > 0:
            total_cvss += cvss * conf
            cvss_count += 1

    score = 0.6 * total_cvss + 0.4 * total_severity if cvss_count > 0 else total_severity

    return min(100.0, round(score, 1))


def build_executive_summary(
    findings: list[Any], target: str = "", tools_used: list[str] | None = None
) -> dict[str, Any]:
    """Build executive summary data from findings.

    Returns a dict with risk_score, severity_counts, top_remediation,
    and owasp_coverage_pct -- suitable for embedding in any report format.

    Args:
        findings: List of Finding objects.
        target: Target URL.
        tools_used: Optional list of tool names that were run during the
            session.  Used to determine which OWASP categories were tested
            (even if no vulnerabilities were found).
    """
    severity_counts = Counter(f.severity.value if hasattr(f.severity, "value") else str(f.severity) for f in findings)
    risk_score = calculate_risk_score(findings)

    # Top 3 remediation priorities (highest severity, then highest CVSS)
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -_SEVERITY_WEIGHTS.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity), 0),
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

    # OWASP coverage: categories with findings (vulnerable)
    vulnerable_cats = {f.owasp_category for f in findings if f.owasp_category}

    # Categories tested: union of vulnerable + tool-derived coverage
    tested_cats = set(vulnerable_cats)
    if tools_used:
        from numasec.core.coverage import _TOOL_TO_OWASP

        for tool in tools_used:
            for cat in _TOOL_TO_OWASP.get(tool, []):
                # Use short form (A01) for consistency
                short = cat.split("_")[0]
                tested_cats.add(short)
    # Also normalize vulnerable cats to short form
    tested_short = set()
    for c in tested_cats:
        tested_short.add(c.split("_")[0] if "_" in c else c)

    owasp_pct = round(len(tested_short) / 10 * 100) if tested_short else 0

    return {
        "risk_score": risk_score,
        "total_findings": len(findings),
        "severity_counts": dict(severity_counts),
        "top_remediation": top_remediation,
        "owasp_categories_hit": sorted(vulnerable_cats),
        "owasp_categories_tested": sorted(tested_short),
        "owasp_coverage_pct": owasp_pct,
    }
