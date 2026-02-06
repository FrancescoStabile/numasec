"""
NumaSec v3 - Report Generator

Produces professional pentest reports from findings + target profile.

Formats:
  - Markdown (.md) — default, always generated
  - HTML (.html) — styled, shareable
  - JSON (.json) — machine-readable

Sections:
  1. Executive Summary
  2. Target Profile (from TargetProfile)
  3. Attack Timeline (from AttackPlan)
  4. Findings (severity-sorted)
  5. Evidence & Screenshots
  6. Remediation Recommendations
  7. Appendix: Raw tool outputs
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from numasec.state import State, Finding
from numasec.target_profile import TargetProfile
from numasec.planner import AttackPlan

logger = logging.getLogger("numasec.report")

# ═══════════════════════════════════════════════════════════════════════════
# Severity helpers
# ═══════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}
SEVERITY_LABEL = {
    "critical": "▲▲",
    "high": "▲",
    "medium": "■",
    "low": "●",
    "info": "○",
}


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (critical first)."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


# ═══════════════════════════════════════════════════════════════════════════
# Markdown Report
# ═══════════════════════════════════════════════════════════════════════════


def generate_markdown_report(
    state: State,
    target: str = "",
    session_id: str = "",
    cost: float = 0.0,
) -> str:
    """
    Generate a full Markdown pentest report.

    Args:
        state: Agent state with findings, profile, plan
        target: Target description
        session_id: Session identifier
        cost: Total cost of the assessment

    Returns:
        Complete Markdown report as string
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    findings = _sort_findings(state.findings)
    profile = state.profile
    plan = state.plan

    lines: list[str] = []
    w = lines.append  # shorthand

    # ── Header ──
    w("# NumaSec Penetration Test Report")
    w("")
    w(f"**Target:** {target or profile.target or 'Unknown'}")
    w(f"**Date:** {now}")
    if session_id:
        w(f"**Session:** `{session_id[:12]}`")
    w(f"**Tool:** NumaSec v3 — Autonomous Pentesting Agent")
    w("")
    w("---")
    w("")

    # ── Executive Summary ──
    w("## Executive Summary")
    w("")

    total = len(findings)
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    info = sum(1 for f in findings if f.severity == "info")

    if total == 0:
        w("No vulnerabilities were identified during this assessment.")
    else:
        w(f"A total of **{total} findings** were identified during the automated penetration test.")
        w("")
        w("| Severity | Count |")
        w("|----------|-------|")
        if critical:
            w(f"| ▲▲ Critical | {critical} |")
        if high:
            w(f"| ▲ High | {high} |")
        if medium:
            w(f"| ■ Medium | {medium} |")
        if low:
            w(f"| ● Low | {low} |")
        if info:
            w(f"| ○ Info | {info} |")

    w("")

    # Risk level
    if critical > 0:
        w("**Overall Risk Level: CRITICAL** — Immediate action required.")
    elif high > 0:
        w("**Overall Risk Level: HIGH** — Significant vulnerabilities found.")
    elif medium > 0:
        w("**Overall Risk Level: MEDIUM** — Vulnerabilities should be addressed.")
    elif low > 0:
        w("**Overall Risk Level: LOW** — Minor issues identified.")
    else:
        w("**Overall Risk Level: INFORMATIONAL** — No significant vulnerabilities found.")

    w("")
    w("---")
    w("")

    # ── Target Profile ──
    w("## Target Profile")
    w("")

    if profile.target:
        w(f"**Base URL:** `{profile.target}`")
    if profile.os_guess:
        w(f"**OS Hint:** {profile.os_guess}")
    w("")

    if profile.ports:
        w("### Open Ports")
        w("")
        w("| Port | Protocol | Service | Version |")
        w("|------|----------|---------|---------|")
        for port in profile.ports:
            w(f"| {port.number} | {port.protocol} | {port.service} | {port.version or '-'} |")
        w("")

    if profile.technologies:
        w("### Technologies Detected")
        w("")
        for tech in profile.technologies:
            version_str = f" v{tech.version}" if tech.version else ""
            w(f"- **{tech.name}**{version_str} ({tech.category})")
        w("")

    if profile.endpoints:
        w("### Endpoints Discovered")
        w("")
        w("| Path | Method | Status | Notes |")
        w("|------|--------|--------|-------|")
        for ep in profile.endpoints[:30]:  # Limit
            notes = ep.notes[:50] if ep.notes else "-"
            w(f"| `{ep.url}` | {ep.method} | {ep.status_code or '-'} | {notes} |")
        if len(profile.endpoints) > 30:
            w(f"| ... | ... | ... | *{len(profile.endpoints) - 30} more endpoints* |")
        w("")

    if profile.credentials:
        w("### Credentials Found")
        w("")
        w("| Username | Password | Source |")
        w("|----------|----------|--------|")
        for cred in profile.credentials:
            pw = cred.password if cred.password else "*hash*"
            w(f"| `{cred.username}` | `{pw}` | {cred.source} |")
        w("")

    w("---")
    w("")

    # ── Attack Plan Timeline ──
    if plan and plan.objective:
        w("## Attack Timeline")
        w("")
        w(f"**Objective:** {plan.objective}")
        w("")

        for phase in plan.phases:
            status_icon = {
                "pending": "○",
                "active": "●",
                "complete": "✓",
                "skipped": "⊘",
            }.get(phase.status.value, "○")

            w(f"### {status_icon} {phase.name}")
            w("")
            for step in phase.steps:
                step_icon = "✓" if step.status.value == "complete" else "⊘" if step.status.value == "skipped" else "○"
                w(f"- {step_icon} `{step.tool_hint or 'manual'}`: {step.description}")
                if step.result_summary:
                    w(f"  ```")
                    # Truncate and clean up for readability
                    summary = step.result_summary[:200].strip()
                    for summary_line in summary.split("\n"):
                        w(f"  {summary_line}")
                    w(f"  ```")
            w("")

        w("---")
        w("")

    # ── Detailed Findings ──
    if findings:
        w("## Detailed Findings")
        w("")

        for i, finding in enumerate(findings, 1):
            icon = SEVERITY_LABEL.get(finding.severity, "○")
            w(f"### {icon} Finding #{i}: {finding.title}")
            w("")
            w(f"**Severity:** {finding.severity.upper()}")
            w("")
            w(f"**Description:**")
            w(f"{finding.description}")
            w("")
            if finding.evidence:
                w(f"**Evidence:**")
                w(f"```")
                w(finding.evidence[:500])
                w(f"```")
                w("")

            # Remediation suggestion based on finding type
            remediation = _suggest_remediation(finding)
            if remediation:
                w(f"**Remediation:**")
                w(remediation)
                w("")

            w("---")
            w("")

    # ── Remediation Summary ──
    if findings:
        w("## Remediation Summary")
        w("")
        w("| Priority | Finding | Action |")
        w("|----------|---------|--------|")
        for i, finding in enumerate(findings, 1):
            action = _suggest_remediation_short(finding)
            w(f"| {finding.severity.upper()} | {finding.title[:50]} | {action} |")
        w("")
        w("---")
        w("")

    # ── Appendix ──
    w("## Appendix")
    w("")
    w(f"- **Total iterations:** {state.iteration}")
    w(f"- **Messages exchanged:** {len(state.messages)}")
    if cost > 0:
        w(f"- **Assessment cost:** ${cost:.4f}")
    w(f"- **Generated by:** NumaSec v3")
    w(f"- **Timestamp:** {now}")
    w("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# HTML Report
# ═══════════════════════════════════════════════════════════════════════════


def generate_html_report(
    state: State,
    target: str = "",
    session_id: str = "",
    cost: float = 0.0,
) -> str:
    """
    Generate styled HTML report.
    Wraps the Markdown content in a professional HTML template.
    """
    md_content = generate_markdown_report(state, target, session_id, cost)

    # Convert basic Markdown to HTML (minimal, no external deps)
    html_body = _md_to_html(md_content)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_name = target or state.profile.target or "Unknown"

    # Count findings for summary bar
    findings = state.findings
    total = len(findings)
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NumaSec Report — {target_name}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --fg: #c9d1d9;
            --accent: #58a6ff;
            --green: #3fb950;
            --bright-green: #00ff41;
            --red: #f85149;
            --orange: #d29922;
            --yellow: #e3b341;
            --purple: #bc8cff;
            --cyan: #79c0ff;
            --border: #21262d;
            --card: #161b22;
            --card-hover: #1c2128;
            --muted: #484f58;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', 'Cascadia Code', 'Menlo', monospace;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.7;
            padding: 2rem;
            max-width: 960px;
            margin: 0 auto;
        }}
        /* Hero header */
        .hero {{
            text-align: center;
            padding: 2.5rem 0 1.5rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        .hero-brand {{
            display: inline-block;
            padding: 0.3rem 1rem;
            border: 1px solid var(--bright-green);
            border-radius: 4px;
            color: var(--bright-green);
            font-size: 0.75rem;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            margin-bottom: 1rem;
        }}
        .hero h1 {{
            color: var(--fg);
            font-size: 1.6rem;
            letter-spacing: 0.05em;
            margin: 0 0 0.5rem;
            border: none;
            padding: 0;
        }}
        .hero .target {{
            color: var(--green);
            font-size: 1.05rem;
            font-weight: bold;
        }}
        .hero .meta {{
            color: var(--muted);
            font-size: 0.8rem;
            margin-top: 0.5rem;
        }}
        /* Severity summary bar */
        .severity-bar {{
            display: flex;
            gap: 0.75rem;
            justify-content: center;
            margin: 1.5rem 0;
            flex-wrap: wrap;
        }}
        .severity-badge {{
            padding: 0.35rem 0.9rem;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.8rem;
            border: 1px solid;
        }}
        .badge-critical {{ background: rgba(248,81,73,0.12); border-color: var(--red); color: var(--red); }}
        .badge-high {{ background: rgba(210,153,34,0.12); border-color: var(--orange); color: var(--orange); }}
        .badge-medium {{ background: rgba(227,179,65,0.12); border-color: var(--yellow); color: var(--yellow); }}
        .badge-low {{ background: rgba(121,192,255,0.12); border-color: var(--cyan); color: var(--cyan); }}
        h1 {{ color: var(--fg); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin: 2rem 0 1rem; font-size: 1.3rem; }}
        h2 {{ color: var(--purple); margin: 2rem 0 0.75rem; font-size: 1.15rem; }}
        h3 {{ color: var(--green); margin: 1.2rem 0 0.5rem; font-size: 1rem; }}
        p {{ margin: 0.5rem 0; }}
        code {{ background: var(--card); padding: 0.15em 0.4em; border-radius: 4px; font-size: 0.9em; color: var(--cyan); }}
        pre {{ background: var(--card); padding: 1rem; border-radius: 8px; overflow-x: auto; margin: 0.75rem 0; border: 1px solid var(--border); }}
        pre code {{ background: none; padding: 0; color: var(--fg); }}
        table {{ border-collapse: collapse; width: 100%; margin: 0.75rem 0; }}
        th, td {{ border: 1px solid var(--border); padding: 0.5rem 0.75rem; text-align: left; }}
        th {{ background: var(--card); color: var(--accent); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        tr:nth-child(even) {{ background: var(--card); }}
        tr:hover {{ background: var(--card-hover); }}
        hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
        ul, ol {{ padding-left: 1.5rem; margin: 0.5rem 0; }}
        li {{ margin: 0.25rem 0; }}
        strong {{ color: #e6edf3; }}
        .severity-critical {{ color: var(--red); font-weight: bold; }}
        .severity-high {{ color: var(--orange); font-weight: bold; }}
        .severity-medium {{ color: var(--yellow); }}
        .severity-low {{ color: var(--cyan); }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .footer {{
            margin-top: 3rem;
            padding: 1.5rem 0;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-size: 0.8rem;
            text-align: center;
        }}
        .footer a {{ color: var(--green); }}
        .footer .gh-badge {{
            display: inline-block;
            margin-top: 0.75rem;
            padding: 0.3rem 0.8rem;
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--fg);
            font-size: 0.75rem;
            text-decoration: none;
        }}
        .footer .gh-badge:hover {{
            border-color: var(--green);
            text-decoration: none;
        }}
        @media print {{
            body {{ background: #fff; color: #1a1a1a; }}
            .hero {{ border-bottom-color: #ddd; }}
            .hero h1 {{ color: #1a1a1a; }}
            .hero .target {{ color: #1a7f37; }}
            .hero-brand {{ border-color: #1a7f37; color: #1a7f37; }}
            pre, code {{ background: #f6f8fa; border-color: #ddd; }}
            th {{ background: #f6f8fa; color: #1a1a1a; }}
            tr:nth-child(even) {{ background: #f9f9f9; }}
            h2 {{ color: #6639ba; }}
            h3 {{ color: #1a7f37; }}
            .footer {{ color: #888; }}
        }}
    </style>
</head>
<body>
<div class="hero">
    <div class="hero-brand">◉ NumaSec</div>
    <h1>Penetration Test Report</h1>
    <div class="target">{target_name}</div>
    <div class="meta">{now}{f' &middot; ${cost:.2f}' if cost > 0 else ''}</div>
</div>
{f'''<div class="severity-bar">
    {f'<span class="severity-badge badge-critical">▲▲ {critical} CRITICAL</span>' if critical else ''}
    {f'<span class="severity-badge badge-high">▲ {high} HIGH</span>' if high else ''}
    {f'<span class="severity-badge badge-medium">■ {medium} MEDIUM</span>' if medium else ''}
    {f'<span class="severity-badge badge-low">● {low} LOW</span>' if low else ''}
</div>''' if total > 0 else ''}
{html_body}
<div class="footer">
    Generated by <a href="https://github.com/FrancescoStabile/numasec">NumaSec v3</a> &mdash; Autonomous AI Penetration Testing<br>
    <a class="gh-badge" href="https://github.com/FrancescoStabile/numasec">★ github.com/FrancescoStabile/numasec</a>
</div>
</body>
</html>"""

    return html


def _md_to_html(md: str) -> str:
    """
    Minimal Markdown-to-HTML converter.
    No external dependencies — covers tables, headers, code, lists, bold, inline code.
    """
    import re

    lines = md.split("\n")
    html_lines: list[str] = []
    in_code_block = False
    in_table = False
    in_list = False

    for line in lines:
        # Code blocks
        if line.strip().startswith("```"):
            if in_code_block:
                html_lines.append("</code></pre>")
                in_code_block = False
            else:
                html_lines.append("<pre><code>")
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(_escape_html(line))
            continue

        # Table
        if "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            # Skip separator rows
            if all(set(c) <= {"-", ":", " "} for c in cells):
                continue
            if not in_table:
                html_lines.append("<table>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            row = "".join(f"<{tag}>{_inline_md(c)}</{tag}>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")
            continue
        elif in_table:
            html_lines.append("</table>")
            in_table = False

        # Headers
        header_match = re.match(r'^(#{1,6})\s+(.+)$', line)
        if header_match:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            level = len(header_match.group(1))
            text = _inline_md(header_match.group(2))
            html_lines.append(f"<h{level}>{text}</h{level}>")
            continue

        # Horizontal rule
        if line.strip() == "---":
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append("<hr>")
            continue

        # Lists
        list_match = re.match(r'^(\s*)-\s+(.+)$', line)
        if list_match:
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_inline_md(list_match.group(2))}</li>")
            continue
        elif in_list:
            html_lines.append("</ul>")
            in_list = False

        # Empty line
        if not line.strip():
            html_lines.append("")
            continue

        # Paragraph
        html_lines.append(f"<p>{_inline_md(line)}</p>")

    # Close open tags
    if in_code_block:
        html_lines.append("</code></pre>")
    if in_table:
        html_lines.append("</table>")
    if in_list:
        html_lines.append("</ul>")

    return "\n".join(html_lines)


def _inline_md(text: str) -> str:
    """Convert inline Markdown: bold, inline code, links. HTML-safe."""
    import re
    # First: escape HTML to prevent XSS from finding evidence/payloads
    text = _escape_html(text)
    # Inline code (now uses &lt; &gt; inside, which is correct)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    # Bold
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    # Italic
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    # Links
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)
    return text


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ═══════════════════════════════════════════════════════════════════════════
# JSON Report
# ═══════════════════════════════════════════════════════════════════════════


def generate_json_report(
    state: State,
    target: str = "",
    session_id: str = "",
    cost: float = 0.0,
) -> str:
    """Generate machine-readable JSON report."""
    now = datetime.now().isoformat()
    findings = _sort_findings(state.findings)
    profile = state.profile
    plan = state.plan

    report = {
        "metadata": {
            "tool": "NumaSec v3",
            "target": target or profile.target or "Unknown",
            "session_id": session_id,
            "timestamp": now,
            "cost_usd": round(cost, 4),
            "iterations": state.iteration,
        },
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "info": sum(1 for f in findings if f.severity == "info"),
        },
        "target_profile": profile.to_dict(),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": _suggest_remediation_short(f),
            }
            for f in findings
        ],
    }

    if plan and plan.objective:
        report["attack_plan"] = plan.to_dict()

    return json.dumps(report, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════
# Remediation Engine
# ═══════════════════════════════════════════════════════════════════════════

_REMEDIATION_MAP = {
    "sqli": "Use parameterized queries (prepared statements). Never concatenate user input into SQL queries. Enable WAF rules for SQLi detection.",
    "sql injection": "Use parameterized queries (prepared statements). Never concatenate user input into SQL queries. Enable WAF rules for SQLi detection.",
    "xss": "Sanitize all user input. Use Content-Security-Policy headers. Encode output based on context (HTML, JavaScript, URL).",
    "cross-site scripting": "Sanitize all user input. Use Content-Security-Policy headers. Encode output based on context.",
    "rce": "Never pass user input to system commands. Use allowlists for expected values. Apply principle of least privilege.",
    "command injection": "Never pass user input to system commands. Use allowlists. Apply subprocess with shell=False.",
    "lfi": "Use allowlists for file paths. Never use user input in file operations. Disable directory traversal in web server config.",
    "file inclusion": "Use allowlists for file paths. Never use user input in file operations. Chroot web application.",
    "ssti": "Use sandboxed template engines. Never render user input as template code. Upgrade template library.",
    "ssrf": "Validate and allowlist URLs. Block internal IP ranges. Use a proxy for outbound requests.",
    "auth": "Implement proper authentication. Use bcrypt/argon2 for password hashing. Enable MFA. Apply rate limiting.",
    "default credentials": "Change all default passwords immediately. Enforce strong password policy. Remove default accounts.",
    "csrf": "Use anti-CSRF tokens. Validate Origin/Referer headers. Use SameSite cookie attribute.",
    "idor": "Implement proper authorization checks. Use indirect references. Validate user permissions server-side.",
    "exposed": "Remove sensitive files from web root. Add proper access controls. Review .gitignore and deployment pipeline.",
    "information disclosure": "Disable debug mode in production. Remove version headers. Implement proper error handling.",
    "open redirect": "Validate redirect URLs against allowlist. Use relative URLs. Don't use user input for redirects.",
}


def _suggest_remediation(finding: Finding) -> str:
    """Suggest remediation based on finding title/description."""
    text = f"{finding.title} {finding.description}".lower()
    for keyword, remediation in _REMEDIATION_MAP.items():
        if keyword in text:
            return remediation
    return "Review the finding and apply appropriate security controls based on the vulnerability type."


def _suggest_remediation_short(finding: Finding) -> str:
    """Short remediation suggestion for summary table."""
    text = f"{finding.title} {finding.description}".lower()
    short_map = {
        "sqli": "Use parameterized queries",
        "sql injection": "Use parameterized queries",
        "xss": "Sanitize input, set CSP",
        "cross-site scripting": "Sanitize input, set CSP",
        "rce": "Never pass user input to commands",
        "command injection": "Use allowlists, no shell",
        "lfi": "Allowlist file paths",
        "ssti": "Sandbox template engine",
        "ssrf": "Allowlist URLs, block internal IPs",
        "auth": "Fix authentication logic",
        "default credentials": "Change all defaults",
        "csrf": "Add anti-CSRF tokens",
        "exposed": "Remove from web root",
    }
    for keyword, short in short_map.items():
        if keyword in text:
            return short
    return "Review and remediate"


# ═══════════════════════════════════════════════════════════════════════════
# Report Writer
# ═══════════════════════════════════════════════════════════════════════════


def write_report(
    state: State,
    output_dir: str | Path,
    format: str = "md",
    target: str = "",
    session_id: str = "",
    cost: float = 0.0,
) -> Path:
    """
    Write report to file.

    Args:
        state: Agent state
        output_dir: Directory for output
        format: "md", "html", or "json"
        target: Target description
        session_id: Session ID
        cost: Assessment cost

    Returns:
        Path to generated report file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_slug = (target or "unknown")[:30].replace("/", "_").replace(":", "").replace(" ", "_")

    if format == "html":
        content = generate_html_report(state, target, session_id, cost)
        filename = f"numasec_report_{target_slug}_{timestamp}.html"
    elif format == "json":
        content = generate_json_report(state, target, session_id, cost)
        filename = f"numasec_report_{target_slug}_{timestamp}.json"
    else:
        content = generate_markdown_report(state, target, session_id, cost)
        filename = f"numasec_report_{target_slug}_{timestamp}.md"

    filepath = output_dir / filename
    filepath.write_text(content, encoding="utf-8")
    logger.info(f"Report written: {filepath}")

    return filepath
