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
    "critical": "#f85149",
    "high": "#f0883e",
    "medium": "#f5d547",
    "low": "#79c0ff",
    "info": "#6e7681",
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
    w("# NumaSec Security Assessment Report")
    w("")
    w(f"**Target:** {target or profile.target or 'Unknown'}")
    w(f"**Date:** {now}")
    if session_id:
        w(f"**Session:** `{session_id[:12]}`")
    w(f"**Tool:** NumaSec — AI Security Testing")
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
        w(f"A total of **{total} security issues** were identified during the automated assessment.")
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
        w("## Testing Timeline")
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
                w(f"- `{step.tool_hint or 'manual'}`: {step.description}")
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
    w(f"- **Generated by:** NumaSec — AI Security Testing")
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
    Generate styled HTML report — dark theme, SVG donut chart, shareable.
    Wraps the Markdown content in a professional HTML template.
    """
    md_content = generate_markdown_report(state, target, session_id, cost)

    # Convert basic Markdown to HTML (minimal, no external deps)
    html_body = _md_to_html(md_content)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_name = target or state.profile.target or "Unknown"

    # Count findings for summary bar and donut chart
    findings = state.findings
    total = len(findings)
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    info = sum(1 for f in findings if f.severity == "info")

    # Risk level
    if critical > 0:
        risk_level, risk_color = "CRITICAL", "#f85149"
    elif high > 0:
        risk_level, risk_color = "HIGH", "#f0883e"
    elif medium > 0:
        risk_level, risk_color = "MEDIUM", "#f5d547"
    elif low > 0:
        risk_level, risk_color = "LOW", "#79c0ff"
    else:
        risk_level, risk_color = "CLEAN", "#3fb950"

    # Build SVG donut chart
    donut_svg = _build_donut_chart(critical, high, medium, low, info, total)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NumaSec Report — {_escape_html(target_name)}</title>
    <meta name="description" content="Security assessment report for {_escape_html(target_name)} — generated by NumaSec">
    <meta property="og:title" content="Security Report — {_escape_html(target_name)}">
    <meta property="og:description" content="{total} findings · Risk: {risk_level} · Generated by NumaSec">
    <meta property="og:type" content="article">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap');
        :root {{
            --bg: #0a0a0f;
            --bg-card: #12121a;
            --bg-card-hover: #1a1a25;
            --fg: #e1e4e8;
            --fg-muted: #6e7681;
            --accent: #58a6ff;
            --green: #3fb950;
            --bright-green: #00ff41;
            --red: #f85149;
            --orange: #f0883e;
            --yellow: #f5d547;
            --purple: #bc8cff;
            --cyan: #79c0ff;
            --border: #1e1e2a;
            --border-subtle: #161620;
            --glow-green: rgba(0, 255, 65, 0.08);
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html {{ scroll-behavior: smooth; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.7;
            padding: 0;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem 2rem 4rem;
        }}
        /* ── Hero ── */
        .hero {{
            text-align: center;
            padding: 3rem 2rem 2rem;
            background: linear-gradient(180deg, rgba(0,255,65,0.04) 0%, transparent 100%);
            border-bottom: 1px solid var(--border);
            margin-bottom: 2.5rem;
        }}
        .hero-brand {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.3rem 1rem;
            border: 1px solid var(--bright-green);
            border-radius: 20px;
            color: var(--bright-green);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
            font-weight: 500;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            margin-bottom: 1.2rem;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.1);
        }}
        .hero h1 {{
            color: var(--fg);
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: -0.01em;
            margin: 0 0 0.6rem;
            border: none;
            padding: 0;
        }}
        .hero .target {{
            color: var(--bright-green);
            font-family: 'JetBrains Mono', monospace;
            font-size: 1rem;
            font-weight: 500;
        }}
        .hero .meta {{
            color: var(--fg-muted);
            font-size: 0.8rem;
            margin-top: 0.5rem;
        }}
        /* ── Risk Badge ── */
        .risk-badge {{
            display: inline-block;
            padding: 0.4rem 1.2rem;
            border-radius: 20px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.75rem;
            letter-spacing: 0.1em;
            margin: 1rem 0;
            border: 1px solid {risk_color};
            color: {risk_color};
            background: {risk_color}15;
            box-shadow: 0 0 15px {risk_color}20;
        }}
        /* ── Stats Grid ── */
        .stats-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin: 2rem 0;
            align-items: center;
        }}
        .donut-container {{
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .severity-list {{
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
        }}
        .sev-row {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem 0.75rem;
            border-radius: 8px;
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
        }}
        .sev-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .sev-label {{ color: var(--fg-muted); font-size: 0.8rem; flex: 1; }}
        .sev-count {{ font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 1rem; }}
        /* ── Content ── */
        h1 {{ color: var(--fg); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin: 2.5rem 0 1rem; font-size: 1.2rem; font-weight: 600; }}
        h2 {{ color: var(--purple); margin: 2rem 0 0.75rem; font-size: 1.05rem; font-weight: 600; }}
        h3 {{ color: var(--green); margin: 1.2rem 0 0.5rem; font-size: 0.95rem; font-weight: 600; }}
        p {{ margin: 0.5rem 0; }}
        code {{
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-card);
            padding: 0.15em 0.4em;
            border-radius: 4px;
            font-size: 0.85em;
            color: var(--cyan);
        }}
        pre {{
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-card);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            margin: 0.75rem 0;
            border: 1px solid var(--border);
            font-size: 0.85em;
        }}
        pre code {{ background: none; padding: 0; color: var(--fg); }}
        table {{ border-collapse: collapse; width: 100%; margin: 0.75rem 0; }}
        th, td {{ border: 1px solid var(--border); padding: 0.5rem 0.75rem; text-align: left; font-size: 0.85rem; }}
        th {{ background: var(--bg-card); color: var(--accent); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }}
        tr:nth-child(even) {{ background: var(--bg-card); }}
        tr:hover {{ background: var(--bg-card-hover); }}
        hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
        ul, ol {{ padding-left: 1.5rem; margin: 0.5rem 0; }}
        li {{ margin: 0.25rem 0; }}
        strong {{ color: #f0f3f6; }}
        .severity-critical {{ color: var(--red); font-weight: bold; }}
        .severity-high {{ color: var(--orange); font-weight: bold; }}
        .severity-medium {{ color: var(--yellow); }}
        .severity-low {{ color: var(--cyan); }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        /* ── Footer ── */
        .footer {{
            margin-top: 3rem;
            padding: 2rem 0;
            border-top: 1px solid var(--border);
            text-align: center;
        }}
        .footer-brand {{
            font-family: 'JetBrains Mono', monospace;
            color: var(--bright-green);
            font-size: 0.85rem;
            font-weight: 500;
            letter-spacing: 0.05em;
        }}
        .footer-sub {{
            color: var(--fg-muted);
            font-size: 0.75rem;
            margin-top: 0.5rem;
        }}
        .footer a {{ color: var(--accent); }}
        .share-links {{
            margin-top: 1rem;
            display: flex;
            justify-content: center;
            gap: 1rem;
        }}
        .share-btn {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.4rem 1rem;
            border: 1px solid var(--border);
            border-radius: 20px;
            color: var(--fg-muted);
            font-size: 0.7rem;
            text-decoration: none;
            transition: all 0.2s;
        }}
        .share-btn:hover {{
            border-color: var(--bright-green);
            color: var(--bright-green);
            text-decoration: none;
            box-shadow: 0 0 10px rgba(0,255,65,0.1);
        }}
        .gh-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            margin-top: 1rem;
            padding: 0.4rem 1rem;
            border: 1px solid var(--border);
            border-radius: 20px;
            color: var(--fg);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            text-decoration: none;
            transition: all 0.2s;
        }}
        .gh-badge:hover {{
            border-color: var(--bright-green);
            text-decoration: none;
            box-shadow: 0 0 10px rgba(0,255,65,0.1);
        }}
        @media (max-width: 640px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
            .container {{ padding: 1rem; }}
            .hero {{ padding: 2rem 1rem 1.5rem; }}
        }}
        @media print {{
            body {{ background: #fff; color: #1a1a1a; }}
            .hero {{ background: none; border-bottom-color: #ddd; }}
            .hero h1 {{ color: #1a1a1a; }}
            .hero .target {{ color: #1a7f37; }}
            .hero-brand {{ border-color: #1a7f37; color: #1a7f37; box-shadow: none; }}
            .risk-badge {{ box-shadow: none; }}
            pre, code {{ background: #f6f8fa; border-color: #ddd; }}
            th {{ background: #f6f8fa; color: #1a1a1a; }}
            tr:nth-child(even) {{ background: #f9f9f9; }}
            h2 {{ color: #6639ba; }}
            h3 {{ color: #1a7f37; }}
            .footer {{ color: #888; }}
            .sev-row {{ background: #f6f8fa; border-color: #ddd; }}
        }}
    </style>
</head>
<body>
<div class="hero">
    <div class="hero-brand">◉ NumaSec</div>
    <h1>Security Assessment Report</h1>
    <div class="target">{_escape_html(target_name)}</div>
    <div class="meta">{now}{f' &middot; ${cost:.2f}' if cost > 0 else ''}</div>
    <div class="risk-badge">{risk_level} RISK</div>
</div>
<div class="container">
{f'''<div class="stats-grid">
    <div class="donut-container">
        {donut_svg}
    </div>
    <div class="severity-list">
        <div class="sev-row"><span class="sev-dot" style="background:#f85149"></span><span class="sev-label">Critical</span><span class="sev-count" style="color:#f85149">{critical}</span></div>
        <div class="sev-row"><span class="sev-dot" style="background:#f0883e"></span><span class="sev-label">High</span><span class="sev-count" style="color:#f0883e">{high}</span></div>
        <div class="sev-row"><span class="sev-dot" style="background:#f5d547"></span><span class="sev-label">Medium</span><span class="sev-count" style="color:#f5d547">{medium}</span></div>
        <div class="sev-row"><span class="sev-dot" style="background:#79c0ff"></span><span class="sev-label">Low</span><span class="sev-count" style="color:#79c0ff">{low}</span></div>
        <div class="sev-row"><span class="sev-dot" style="background:#6e7681"></span><span class="sev-label">Info</span><span class="sev-count" style="color:#6e7681">{info}</span></div>
    </div>
</div>''' if total > 0 else ''}
{html_body}
<div class="footer">
    <div class="footer-brand">numasec.com — Vibe Security</div>
    <div class="footer-sub">AI-powered security testing for indie devs, startups, and vibe coders</div>
    <div class="share-links">
        <a class="share-btn" href="https://twitter.com/intent/tweet?text=Just%20ran%20a%20security%20check%20on%20my%20app%20with%20NumaSec%20%E2%80%94%20AI-powered%20security%20testing%20for%20%240.12.%20%F0%9F%94%92&url=https://github.com/FrancescoStabile/numasec">Share on 𝕏</a>
        <a class="share-btn" href="https://www.linkedin.com/sharing/share-offsite/?url=https://github.com/FrancescoStabile/numasec">Share on LinkedIn</a>
    </div>
    <a class="gh-badge" href="https://github.com/FrancescoStabile/numasec">★ github.com/FrancescoStabile/numasec</a>
</div>
</div>
</body>
</html>"""

    return html


def _build_donut_chart(critical: int, high: int, medium: int, low: int, info: int, total: int) -> str:
    """Build an SVG donut chart for severity breakdown."""
    if total == 0:
        return ""
    
    import math
    
    segments = [
        (critical, "#f85149", "Critical"),
        (high, "#f0883e", "High"),
        (medium, "#f5d547", "Medium"),
        (low, "#79c0ff", "Low"),
        (info, "#6e7681", "Info"),
    ]
    
    # Filter out zero-count segments
    segments = [(count, color, label) for count, color, label in segments if count > 0]
    
    radius = 60
    cx, cy = 80, 80
    stroke_width = 18
    circumference = 2 * math.pi * radius
    
    paths = []
    offset = 0
    
    for count, color, label in segments:
        pct = count / total
        dash = circumference * pct
        gap = circumference - dash
        paths.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" '
            f'stroke="{color}" stroke-width="{stroke_width}" '
            f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" '
            f'style="transition: stroke-dashoffset 0.5s ease"/>'
        )
        offset += dash
    
    return f'''<svg width="160" height="160" viewBox="0 0 160 160" xmlns="http://www.w3.org/2000/svg">
        {''.join(paths)}
        <text x="{cx}" y="{cy - 6}" text-anchor="middle" fill="#e1e4e8" font-family="JetBrains Mono, monospace" font-size="28" font-weight="700">{total}</text>
        <text x="{cx}" y="{cy + 14}" text-anchor="middle" fill="#6e7681" font-family="Inter, sans-serif" font-size="11">findings</text>
    </svg>'''


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

        # Headers — skip h1 (already in hero section)
        header_match = re.match(r'^(#{1,6})\s+(.+)$', line)
        if header_match:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            level = len(header_match.group(1))
            if level == 1:
                continue  # Skip h1 — hero section handles main title
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
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


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
            "tool": "NumaSec",
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

# Ordered list of (keywords_to_match, remediation_text) tuples.
# More specific patterns come FIRST to prevent false positives.
# Each entry: (list_of_keywords_ALL_must_match_in_title, fallback_description_keywords, remediation)
_REMEDIATION_RULES: list[tuple[list[str], list[str], str]] = [
    # --- Specific finding types (match on title keywords) ---
    (["directory", "listing"], [],
     "Disable directory listing in the web server configuration. For Apache: `Options -Indexes`. For nginx: `autoindex off`. For Express: do not serve static directories without an index file."),
    (["stack", "trace"], [],
     "Disable detailed error messages in production. Set `NODE_ENV=production` for Express, `DEBUG=False` for Django, or configure a custom error handler. Never expose internal file paths or framework details in responses."),
    (["error", "handling"], [],
     "Implement custom error pages. Return generic error messages to clients while logging detailed errors server-side."),
    (["verbose", "error"], [],
     "Disable debug mode and verbose error output in production. Implement custom error pages that do not reveal internal details."),
    (["information", "disclosure"], [],
     "Disable debug mode in production. Remove version headers. Implement proper error handling that does not reveal internal details."),
    ([".env"], [],
     "Block access to .env files in the web server or reverse proxy configuration. Add `.env` to `.gitignore`. Rotate all exposed credentials immediately."),
    (["environment", "file"], [],
     "Block access to environment files in the web server config. Rotate all exposed credentials immediately."),
    (["default", "credential"], [],
     "Change all default passwords immediately. Enforce strong password policy. Remove or disable default accounts."),
    (["open", "redirect"], [],
     "Validate redirect URLs against an allowlist. Use relative URLs for internal redirects. Never use unsanitized user input for redirect targets."),
    (["clickjack"], [],
     "Set X-Frame-Options: DENY or SAMEORIGIN header. Use Content-Security-Policy frame-ancestors directive."),
    (["security", "header"], [],
     "Add security headers: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options. Use the `helmet` package for Express or equivalent middleware."),
    (["missing", "header"], [],
     "Add missing security headers: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options."),
    (["fingerprint"], [],
     "Remove technology version headers (X-Powered-By, Server). Use `app.disable('x-powered-by')` for Express or equivalent."),
    (["x-powered-by"], [],
     "Remove the X-Powered-By header. For Express: `app.disable('x-powered-by')` or use the helmet package."),
    (["cors"], [],
     "Restrict CORS origins to trusted domains. Avoid `Access-Control-Allow-Origin: *` on authenticated endpoints."),
    # --- Vulnerability classes (match on title OR description) ---
    (["sql", "injection"], [],
     "Use parameterized queries (prepared statements). Never concatenate user input into SQL queries. Enable WAF rules for SQLi detection."),
    ([], ["sqli"],
     "Use parameterized queries (prepared statements). Never concatenate user input into SQL queries."),
    (["cross-site scripting"], [],
     "Sanitize all user input. Use Content-Security-Policy headers. Encode output based on context (HTML, JavaScript, URL)."),
    (["xss"], [],
     "Sanitize all user input. Use Content-Security-Policy headers. Encode output based on context (HTML, JavaScript, URL)."),
    (["remote code execution"], [],
     "Never pass user input to system commands. Use allowlists for expected values. Apply principle of least privilege."),
    (["command injection"], [],
     "Never pass user input to system commands. Use allowlists. Use subprocess with shell=False."),
    (["file inclusion"], [],
     "Use allowlists for file paths. Never use user input in file operations. Disable directory traversal in web server config."),
    (["local file"], [],
     "Use allowlists for file paths. Never use user input in file operations. Chroot the web application."),
    (["ssti"], [],
     "Use sandboxed template engines. Never render user input as template code. Upgrade template library."),
    (["template injection"], [],
     "Use sandboxed template engines. Never render user input as template code."),
    (["ssrf"], [],
     "Validate and allowlist URLs. Block internal IP ranges. Use a proxy for outbound requests."),
    (["server-side request"], [],
     "Validate and allowlist URLs. Block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."),
    (["authentication"], [],
     "Implement proper authentication. Use bcrypt/argon2 for password hashing. Enable MFA. Apply rate limiting."),
    (["auth", "bypass"], [],
     "Fix authentication logic. Ensure all protected endpoints validate session tokens server-side."),
    (["csrf"], [],
     "Use anti-CSRF tokens. Validate Origin/Referer headers. Use SameSite cookie attribute."),
    (["idor"], [],
     "Implement proper authorization checks. Use indirect references. Validate user permissions server-side."),
    (["insecure", "direct"], [],
     "Implement proper authorization checks. Use indirect references. Validate user permissions server-side."),
    (["exposed"], ["sensitive", "file"],
     "Remove sensitive files from the web root. Add proper access controls. Review .gitignore and deployment pipeline."),
]


def _suggest_remediation(finding: Finding) -> str:
    """Suggest remediation based on finding title/description."""
    title_lower = finding.title.lower()
    text_lower = f"{finding.title} {finding.description}".lower()

    for title_keywords, desc_keywords, remediation in _REMEDIATION_RULES:
        # Title keywords: ALL must match in title
        if title_keywords and all(kw in title_lower for kw in title_keywords):
            return remediation
        # Description keywords: ALL must match in full text (only if no title keywords)
        if not title_keywords and desc_keywords and all(kw in text_lower for kw in desc_keywords):
            return remediation

    return "Review the finding and apply appropriate security controls based on the vulnerability type."


def _suggest_remediation_short(finding: Finding) -> str:
    """Short remediation suggestion for summary table."""
    title_lower = finding.title.lower()
    text_lower = f"{finding.title} {finding.description}".lower()

    short_rules: list[tuple[list[str], list[str], str]] = [
        (["directory", "listing"], [], "Disable directory listing"),
        (["stack", "trace"], [], "Disable verbose errors"),
        ([".env"], [], "Block .env access, rotate keys"),
        (["environment", "file"], [], "Block .env access, rotate keys"),
        (["security", "header"], [], "Add security headers (helmet)"),
        (["missing", "header"], [], "Add security headers"),
        (["fingerprint"], [], "Remove version headers"),
        (["x-powered-by"], [], "Remove X-Powered-By header"),
        (["sql", "injection"], [], "Use parameterized queries"),
        ([], ["sqli"], "Use parameterized queries"),
        (["xss"], [], "Sanitize input, set CSP"),
        (["cross-site scripting"], [], "Sanitize input, set CSP"),
        (["remote code execution"], [], "Block user input in commands"),
        (["command injection"], [], "Use allowlists, no shell"),
        (["file inclusion"], [], "Allowlist file paths"),
        (["local file"], [], "Allowlist file paths"),
        (["ssti"], [], "Sandbox template engine"),
        (["ssrf"], [], "Allowlist URLs, block internal IPs"),
        (["auth"], [], "Fix authentication logic"),
        (["default", "credential"], [], "Change all defaults"),
        (["csrf"], [], "Add anti-CSRF tokens"),
        (["exposed"], [], "Restrict access, review deployment"),
        (["information", "disclosure"], [], "Disable debug mode"),
    ]

    for title_keywords, desc_keywords, short in short_rules:
        if title_keywords and all(kw in title_lower for kw in title_keywords):
            return short
        if not title_keywords and desc_keywords and all(kw in text_lower for kw in desc_keywords):
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
