"""Markdown report generation."""

from __future__ import annotations

from datetime import UTC, datetime

from numasec.models.finding import Finding


def generate_markdown_report(
    findings: list[Finding],
    target: str = "",
    *,
    include_evidence: bool = True,
    tools_used: list[str] | None = None,
) -> str:
    """Generate a Markdown security assessment report."""
    lines: list[str] = []

    # Header
    lines.append("# numasec Security Assessment Report")
    lines.append("")
    if target:
        lines.append(f"**Target:** {target}")
    lines.append(f"**Date:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("No security findings were identified.")
        return "\n".join(lines)

    # Executive summary
    from numasec.reporting import build_executive_summary

    summary = build_executive_summary(findings, target=target, tools_used=tools_used)
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Findings | {summary['total_findings']} |")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary["severity_counts"].get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.capitalize()} | {count} |")
    lines.append(f"| Risk Score | {summary['risk_score']}/100 |")
    lines.append(f"| OWASP Coverage | {summary['owasp_coverage_pct']}% |")
    lines.append("")

    if summary["top_remediation"]:
        lines.append("### Top Remediation Priorities")
        lines.append("")
        for i, item in enumerate(summary["top_remediation"], 1):
            lines.append(f"{i}. **{item}**")
        lines.append("")

    # Add per-tool summaries if available
    tool_summaries: dict[str, str] = {}
    for f in findings:
        if f.tool_used and f.tool_used not in tool_summaries:
            tool_summaries[f.tool_used] = f.tool_used
    if tool_summaries:
        lines.append("### Tools Used")
        lines.append("")
        for tool in sorted(tool_summaries):
            count = sum(1 for f in findings if f.tool_used == tool)
            lines.append(f"- **{tool}**: {count} finding{'s' if count != 1 else ''}")
        lines.append("")

    # Findings by severity
    lines.append("## Findings")
    lines.append("")

    sorted_findings = sorted(
        findings,
        key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value),
    )

    for i, finding in enumerate(sorted_findings, 1):
        sev_badge = _severity_badge(finding.severity.value)
        lines.append(f"### {i}. {finding.title} {sev_badge}")
        lines.append("")

        # Metadata
        if finding.cwe_id:
            lines.append(f"- **CWE:** {finding.cwe_id}")
        if finding.cvss_score is not None:
            lines.append(f"- **CVSS:** {finding.cvss_score}")
        if finding.owasp_category:
            lines.append(f"- **OWASP:** {finding.owasp_category}")
        if finding.url:
            lines.append(f"- **URL:** `{finding.url}`")
        if finding.method:
            lines.append(f"- **Method:** {finding.method}")
        if finding.parameter:
            lines.append(f"- **Parameter:** `{finding.parameter}`")
        lines.append("")

        # Description
        if finding.description:
            lines.append(f"**Description:** {finding.description}")
            lines.append("")

        # Evidence
        if include_evidence and finding.evidence:
            lines.append("**Evidence:**")
            lines.append(f"```\n{finding.evidence[:2000]}\n```")
            lines.append("")

        # Remediation
        if finding.remediation_summary:
            lines.append(f"**Remediation:** {finding.remediation_summary}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Attack chains section
    chains = _group_chains(findings)
    if chains:
        lines.append("## Attack Chains")
        lines.append("")
        for chain_id, chain_findings in chains.items():
            chain_title = " > ".join(f.title for f in chain_findings)
            max_sev = min(
                chain_findings,
                key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value),
            )
            lines.append(f"### Chain: {chain_title} {_severity_badge(max_sev.severity.value)}")
            lines.append("")
            for j, cf in enumerate(chain_findings, 1):
                url_part = f" (`{cf.url}`)" if cf.url else ""
                lines.append(
                    f"{j}. **{cf.title}** [{cf.severity.value.upper()}]{url_part}"
                    + (f" - Parameter `{cf.parameter}`" if cf.parameter else "")
                )
            lines.append("")
            lines.append(
                f"**Combined risk:** {len(chain_findings)} linked findings. "
                f"Highest severity: {max_sev.severity.value}."
            )
            lines.append("")

    # Footer
    lines.append("*Generated by numasec*")
    return "\n".join(lines)


def _severity_badge(severity: str) -> str:
    """Return a text badge for severity level."""
    badges = {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "info": "[INFO]",
    }
    return badges.get(severity.lower(), "")


def _group_chains(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by chain_id, returning only chains with 2+ findings."""
    chains: dict[str, list[Finding]] = {}
    for f in findings:
        cid = getattr(f, "chain_id", None)
        if cid:
            chains.setdefault(cid, []).append(f)
    return {cid: fs for cid, fs in chains.items() if len(fs) >= 2}
