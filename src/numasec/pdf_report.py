"""
NumaSec — PDF Report Generator

Professional penetration test report using reportlab.
Requires the optional ``[pdf]`` dependency: ``pip install numasec[pdf]``

Design: Clean, modern layout with dark cover page, severity-coded
finding cards, risk visualisation, and consistent header/footer.

Sections:
  Cover Page  — dark branded cover
  1. Executive Summary  — risk gauge, severity bars, donut chart
  2. Target Profile      — ports, technologies, WAF
  3. Findings            — severity-card layout with evidence
  4. Assessment Timeline  — attack plan phases + steps
  5. Remediation Summary — priority table
  Appendix A             — methodology
"""

from __future__ import annotations

import logging
import math
from datetime import datetime
from io import BytesIO
from typing import Any

from numasec.state import State, Finding

logger = logging.getLogger("numasec.report.pdf")

# Severity ordering
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Brand palette ──
BRAND_DARK = "#0d1117"
BRAND_GREEN = "#39d353"
BRAND_WHITE = "#ffffff"
BRAND_MUTED = "#8b949e"

# ── Text ──
TEXT_PRIMARY = "#1f2328"
TEXT_SECONDARY = "#57606a"
TEXT_MUTED = "#8b949e"
BG_LIGHT = "#f6f8fa"
BORDER_COLOR = "#d1d9e0"

# ── Severity colours (hex for PDF) ──
SEVERITY_HEX = {
    "critical": "#dc2626",   # Vivid red
    "high":     "#f97316",   # Vibrant orange
    "medium":   "#eab308",   # Amber / golden yellow
    "low":      "#2563eb",   # Royal blue
    "info":     "#6b7280",   # Neutral gray
}

# Severity colours as (R, G, B) 0-1 floats for chart drawing
SEVERITY_COLORS = {
    "critical": (0.863, 0.149, 0.149),   # #dc2626
    "high":     (0.976, 0.451, 0.086),   # #f97316
    "medium":   (0.918, 0.702, 0.031),   # #eab308
    "low":      (0.145, 0.388, 0.922),   # #2563eb
    "info":     (0.420, 0.447, 0.498),   # #6b7280
}

# Severity labels for human display
SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}


# ═══════════════════════════════════════════════════════════════════════════
# Import guard — reportlab is an optional dependency
# ═══════════════════════════════════════════════════════════════════════════

_HAS_REPORTLAB = False
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.lib.colors import HexColor, Color
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (
        BaseDocTemplate, PageTemplate, Frame,
        Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, HRFlowable,
        NextPageTemplate,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Circle
    from reportlab.graphics.charts.piecharts import Pie
    _HAS_REPORTLAB = True
except ImportError:
    pass


def _check_reportlab():
    """Raise if reportlab is not installed."""
    if not _HAS_REPORTLAB:
        raise ImportError(
            "PDF report generation requires reportlab.\n"
            "Install it with: pip install numasec[pdf]"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Paragraph Styles
# ═══════════════════════════════════════════════════════════════════════════

def _build_styles() -> dict[str, Any]:
    """Create custom paragraph styles."""
    if not _HAS_REPORTLAB:
        return {}

    s: dict[str, Any] = {}

    s["SectionTitle"] = ParagraphStyle(
        "SectionTitle",
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=HexColor(BRAND_DARK),
        spaceBefore=20,
        spaceAfter=10,
    )

    s["SubSection"] = ParagraphStyle(
        "SubSection",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=HexColor(TEXT_PRIMARY),
        spaceBefore=12,
        spaceAfter=4,
    )

    s["Body"] = ParagraphStyle(
        "Body",
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=HexColor(TEXT_PRIMARY),
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    )

    s["BodySmall"] = ParagraphStyle(
        "BodySmall",
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=HexColor(TEXT_SECONDARY),
        spaceAfter=4,
    )

    s["Code"] = ParagraphStyle(
        "Code",
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=HexColor(TEXT_PRIMARY),
        backColor=HexColor(BG_LIGHT),
        borderWidth=0.5,
        borderPadding=6,
        borderColor=HexColor(BORDER_COLOR),
        spaceAfter=6,
    )

    s["FindingTitle"] = ParagraphStyle(
        "FindingTitle",
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        textColor=HexColor(BRAND_DARK),
        spaceAfter=2,
    )

    s["FindingMeta"] = ParagraphStyle(
        "FindingMeta",
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=HexColor(TEXT_MUTED),
        spaceAfter=4,
    )

    s["Metric"] = ParagraphStyle(
        "Metric",
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=HexColor(BRAND_DARK),
        alignment=TA_CENTER,
    )

    s["MetricLabel"] = ParagraphStyle(
        "MetricLabel",
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=HexColor(TEXT_MUTED),
        alignment=TA_CENTER,
    )

    return s


# ═══════════════════════════════════════════════════════════════════════════
# Canvas Callbacks — Cover Page, Header, Footer
# ═══════════════════════════════════════════════════════════════════════════

def _make_cover_renderer(target: str, date_str: str, session_id: str):
    """Return onPage callback that draws the full cover page."""

    def _draw(canvas, doc):
        w, h = A4
        canvas.saveState()

        # ── Full dark background ──
        canvas.setFillColor(HexColor(BRAND_DARK))
        canvas.rect(0, 0, w, h, fill=True, stroke=False)

        # ── Green accent line at ~55 % ──
        accent_y = h * 0.55
        canvas.setStrokeColor(HexColor(BRAND_GREEN))
        canvas.setLineWidth(2.5)
        line_l = w * 0.12
        line_r = w * 0.88
        canvas.line(line_l, accent_y, line_r, accent_y)

        # Small green dot at left end
        canvas.setFillColor(HexColor(BRAND_GREEN))
        canvas.circle(line_l, accent_y, 3, fill=True, stroke=False)

        # ── Brand name ──
        canvas.setFont("Helvetica-Bold", 42)
        canvas.setFillColor(HexColor(BRAND_WHITE))
        canvas.drawCentredString(w / 2, accent_y + 65, "NUMASEC")

        # ── Tagline ──
        canvas.setFont("Helvetica", 11)
        canvas.setFillColor(HexColor(BRAND_MUTED))
        canvas.drawCentredString(w / 2, accent_y + 40, "AI-Powered Security Testing")

        # ── Report type ──
        canvas.setFont("Helvetica-Bold", 17)
        canvas.setFillColor(HexColor(BRAND_WHITE))
        canvas.drawCentredString(w / 2, accent_y - 40, "Security Assessment Report")

        # ── Target details ──
        canvas.setFont("Helvetica", 10)
        canvas.setFillColor(HexColor(BRAND_MUTED))
        info_y = accent_y - 75
        canvas.drawCentredString(w / 2, info_y, f"Target: {target}")
        canvas.drawCentredString(w / 2, info_y - 18, f"Date: {date_str}")
        if session_id:
            canvas.drawCentredString(
                w / 2, info_y - 36, f"Session: {session_id[:12]}"
            )

        # ── Bottom section ──
        canvas.setStrokeColor(HexColor("#30363d"))
        canvas.setLineWidth(0.5)
        canvas.line(w * 0.2, 80, w * 0.8, 80)

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(HexColor("#484f58"))
        canvas.drawCentredString(
            w / 2, 60, "CONFIDENTIAL \u2014 For authorized recipients only"
        )
        canvas.drawCentredString(
            w / 2, 45,
            "Generated by NumaSec \u2014 github.com/FrancescoStabile/numasec",
        )

        canvas.restoreState()

    return _draw


def _make_content_renderer(target: str):
    """Return onPage callback that draws header + footer on content pages."""

    def _draw(canvas, doc):
        w, h = A4
        canvas.saveState()

        # ── Header ──
        header_y = h - 1.4 * cm

        # Brand on left
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(HexColor(BRAND_DARK))
        canvas.drawString(2.2 * cm, header_y, "NUMASEC")

        # Green dot
        brand_w = canvas.stringWidth("NUMASEC", "Helvetica-Bold", 8)
        canvas.setFillColor(HexColor(BRAND_GREEN))
        canvas.circle(
            2.2 * cm + brand_w + 5, header_y + 2.5, 2,
            fill=True, stroke=False,
        )

        # Target on right
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(HexColor(TEXT_MUTED))
        canvas.drawRightString(w - 2 * cm, header_y, target[:60])

        # Header rule
        canvas.setStrokeColor(HexColor(BORDER_COLOR))
        canvas.setLineWidth(0.5)
        canvas.line(2.2 * cm, header_y - 6, w - 2 * cm, header_y - 6)

        # ── Footer ──
        footer_y = 1.3 * cm

        # Footer rule
        canvas.line(2.2 * cm, footer_y + 8, w - 2 * cm, footer_y + 8)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(HexColor(TEXT_MUTED))
        canvas.drawString(2.2 * cm, footer_y - 2, "CONFIDENTIAL")

        # Page number
        canvas.drawRightString(w - 2 * cm, footer_y - 2, f"Page {doc.page}")

        canvas.restoreState()

    return _draw


# ═══════════════════════════════════════════════════════════════════════════
# Visualisations — donut chart, severity bars, risk gauge
# ═══════════════════════════════════════════════════════════════════════════

def _severity_chart(findings: list[Finding]) -> Any | None:
    """Create a donut-style pie chart of severity distribution."""
    if not _HAS_REPORTLAB or not findings:
        return None

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    if not counts:
        return None

    d = Drawing(180, 140)

    pie = Pie()
    pie.x = 20
    pie.y = 5
    pie.width = 110
    pie.height = 110
    pie.innerRadiusFraction = 0.50

    labels, data, colors = [], [], []
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            labels.append(f"{SEVERITY_LABELS[sev]} ({counts[sev]})")
            data.append(counts[sev])
            r, g, b = SEVERITY_COLORS[sev]
            colors.append(Color(r, g, b))

    pie.data = data
    pie.labels = labels
    for i, c in enumerate(colors):
        pie.slices[i].fillColor = c
        pie.slices[i].strokeColor = HexColor("#ffffff")
        pie.slices[i].strokeWidth = 2
    pie.sideLabels = True
    pie.sideLabelsOffset = 0.08
    pie.slices.fontSize = 7
    pie.slices.fontName = "Helvetica"

    # Total in centre
    total = sum(data)
    d.add(pie)
    d.add(String(
        75, 60, str(total),
        fontSize=18, fontName="Helvetica-Bold",
        fillColor=HexColor(BRAND_DARK), textAnchor="middle",
    ))
    d.add(String(
        75, 47, "findings",
        fontSize=7, fontName="Helvetica",
        fillColor=HexColor(TEXT_MUTED), textAnchor="middle",
    ))
    return d


def _severity_bars_drawing(
    crit: int, high: int, med: int, low: int, info_c: int,
    total: int, width: float = 340,
) -> Any | None:
    """Horizontal stacked severity bar."""
    if not _HAS_REPORTLAB or total == 0:
        return None

    bar_h = 14
    d = Drawing(width, bar_h + 4)

    x = 0.0
    for count, sev_key in [
        (crit, "critical"), (high, "high"), (med, "medium"),
        (low, "low"), (info_c, "info"),
    ]:
        if count > 0:
            seg_w = max(4, (count / total) * width)
            d.add(Rect(
                x, 2, seg_w, bar_h,
                fillColor=HexColor(SEVERITY_HEX[sev_key]),
                strokeColor=None,
            ))
            if seg_w > 18:
                d.add(String(
                    x + seg_w / 2, 6, str(count),
                    fontSize=7, fontName="Helvetica-Bold",
                    fillColor=HexColor("#ffffff"), textAnchor="middle",
                ))
            x += seg_w

    return d


def _risk_gauge_drawing(score: int, width: float = 200) -> Any | None:
    """Horizontal risk gauge bar with score indicator."""
    if not _HAS_REPORTLAB:
        return None

    d = Drawing(width + 50, 24)

    # Background track
    d.add(Rect(0, 6, width, 12,
               fillColor=HexColor("#e8ecef"), strokeColor=None))

    # Filled portion
    if score >= 75:
        fill = HexColor(SEVERITY_HEX["critical"])
    elif score >= 50:
        fill = HexColor(SEVERITY_HEX["high"])
    elif score >= 25:
        fill = HexColor(SEVERITY_HEX["medium"])
    else:
        fill = HexColor(BRAND_GREEN)

    fill_w = max(2, score / 100 * width)
    d.add(Rect(0, 6, fill_w, 12, fillColor=fill, strokeColor=None))

    # Score text
    d.add(String(
        width + 8, 8, f"{score}/100",
        fontSize=9, fontName="Helvetica-Bold",
        fillColor=HexColor(TEXT_PRIMARY),
    ))
    return d


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _severity_color_hex(sev: str) -> str:
    return SEVERITY_HEX.get(sev, SEVERITY_HEX["info"])


def _truncate(text: str, max_len: int = 300) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "\u2026"


def _esc(text: str) -> str:
    """Escape XML entities for reportlab Paragraph.

    Handles all five standard XML entities plus newlines.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
        .replace("\n", "<br/>")
    )


def _section_title(number: str, title: str, styles: dict) -> list:
    """Build a section header with number + title + rule."""
    return [
        Spacer(1, 6),
        Paragraph(
            f'<font color="{BRAND_GREEN}" size="11">{number}.</font>'
            f'  <font size="14"><b>{title}</b></font>',
            styles["SectionTitle"],
        ),
        HRFlowable(
            width="100%", thickness=0.75,
            color=HexColor(BORDER_COLOR),
            spaceAfter=10, spaceBefore=2,
        ),
    ]


def _metric_cell(value: str, label: str, styles: dict) -> Table:
    """Small metric card (number + label)."""
    data = [
        [Paragraph(value, styles["Metric"])],
        [Paragraph(label, styles["MetricLabel"])],
    ]
    t = Table(data, colWidths=[4.4 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor(BG_LIGHT)),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor(BORDER_COLOR)),
    ]))
    return t


# ═══════════════════════════════════════════════════════════════════════════
# Finding Card
# ═══════════════════════════════════════════════════════════════════════════

def _finding_card(
    index: int,
    finding: Finding,
    styles: dict,
    content_width: float,
) -> KeepTogether:
    """Build a single finding as a severity-coloured card."""
    sev = finding.severity
    sev_color = HexColor(_severity_color_hex(sev))

    # ── Inner content rows ──
    inner_rows: list[list] = []

    # Title row
    title_html = (
        f'<font color="{_severity_color_hex(sev)}"><b>[{sev.upper()}]</b></font>'
        f'  <b>Finding #{index}: {_esc(_truncate(finding.title, 80))}</b>'
    )
    inner_rows.append([Paragraph(title_html, styles["FindingTitle"])])

    # Metadata
    meta = []
    if finding.cvss_score is not None:
        meta.append(f"CVSS {finding.cvss_score:.1f}")
    if finding.cwe_id:
        meta.append(finding.cwe_id)
    if finding.owasp_category:
        meta.append(finding.owasp_category)
    if finding.cve:
        meta.append(finding.cve)
    if meta:
        inner_rows.append([Paragraph(" \u00b7 ".join(meta), styles["FindingMeta"])])

    # Description
    if finding.description:
        desc = _esc(_truncate(finding.description, 600))
        inner_rows.append([Paragraph(desc, styles["Body"])])

    # Evidence
    if finding.evidence:
        ev = _esc(_truncate(finding.evidence, 500))
        inner_rows.append([
            Paragraph("<b>Evidence:</b>", styles["BodySmall"]),
        ])
        inner_rows.append([Paragraph(ev, styles["Code"])])

    inner_w = content_width - 7 * mm - 8
    inner_table = Table(inner_rows, colWidths=[inner_w])
    inner_table.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))

    # ── Outer card: coloured left strip + content ──
    strip_w = 4 * mm
    card_data = [["", inner_table]]
    card = Table(card_data, colWidths=[strip_w, inner_w + 8])
    card.setStyle(TableStyle([
        # Coloured left strip
        ("BACKGROUND", (0, 0), (0, -1), sev_color),
        # Card background
        ("BACKGROUND", (1, 0), (1, -1), HexColor(BG_LIGHT)),
        # Padding
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (1, 0), (1, -1), 8),
        ("RIGHTPADDING", (1, 0), (1, -1), 8),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 0),
        # Alignment
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        # Outer border
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor(BORDER_COLOR)),
    ]))

    return KeepTogether([card, Spacer(1, 8)])


# ═══════════════════════════════════════════════════════════════════════════
# Main PDF Generator
# ═══════════════════════════════════════════════════════════════════════════

def generate_pdf_report(
    state: State,
    target: str = "",
    session_id: str = "",
    cost: float = 0.0,
) -> bytes:
    """Generate a professional PDF pentest report.

    Uses ``BaseDocTemplate`` with two page templates:
      * **cover** \u2014 dark branded cover drawn via canvas callbacks
      * **content** \u2014 header + footer on every page

    Returns:
        PDF content as bytes.

    Raises:
        ImportError: if reportlab is not installed.
    """
    _check_reportlab()

    buf = BytesIO()
    PAGE_W, PAGE_H = A4
    L_MARGIN = 2.2 * cm
    R_MARGIN = 2 * cm
    T_MARGIN = 2.2 * cm
    B_MARGIN = 2 * cm
    content_width = PAGE_W - L_MARGIN - R_MARGIN

    # ── Data preparation ──
    findings = sorted(
        state.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )
    profile = state.profile
    now_full = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_str = target or profile.target or "Unknown"

    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    info_c = sum(1 for f in findings if f.severity == "info")
    total = len(findings)

    risk_score = min(100, crit * 25 + high * 15 + med * 8 + low * 3 + info_c * 1)
    risk_level = (
        "Critical" if risk_score >= 75 else
        "High" if risk_score >= 50 else
        "Medium" if risk_score >= 25 else
        "Low" if risk_score > 0 else
        "None"
    )

    styles = _build_styles()

    # ── Page templates ──
    cover_frame = Frame(
        0, 0, PAGE_W, PAGE_H, id="cover",
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )
    content_frame = Frame(
        L_MARGIN, B_MARGIN, content_width,
        PAGE_H - T_MARGIN - B_MARGIN,
        id="content",
    )

    doc = BaseDocTemplate(
        buf, pagesize=A4,
        title="NumaSec Security Assessment",
        author="NumaSec",
    )
    doc.addPageTemplates([
        PageTemplate(
            id="cover",
            frames=[cover_frame],
            onPage=_make_cover_renderer(target_str, now_full, session_id),
        ),
        PageTemplate(
            id="content",
            frames=[content_frame],
            onPage=_make_content_renderer(target_str),
        ),
    ])

    elements: list[Any] = []

    # ── Cover page ──
    elements.append(Spacer(1, 1))
    elements.append(NextPageTemplate("content"))
    elements.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════
    # Section 1 — Executive Summary
    # ══════════════════════════════════════════════════════════════════
    elements.extend(_section_title("1", "Executive Summary", styles))

    summary_text = (
        f"This automated security assessment identified <b>{total}</b> "
        f"{'finding' if total == 1 else 'findings'} across the target "
        f"<b>{_esc(target_str)}</b>. "
        f"The overall risk level is <b>{risk_level}</b> "
        f"(score: {risk_score}/100)."
    )
    elements.append(Paragraph(summary_text, styles["Body"]))
    elements.append(Spacer(1, 8))

    # Metric cards row
    metric_cells = [
        _metric_cell(str(total), "Total Findings", styles),
        _metric_cell(str(risk_score), "Risk Score", styles),
        _metric_cell(risk_level.upper(), "Risk Level", styles),
    ]
    if cost > 0:
        metric_cells.append(_metric_cell(f"${cost:.2f}", "Cost", styles))

    metrics_table = Table(
        [metric_cells],
        colWidths=[4.6 * cm] * len(metric_cells),
    )
    metrics_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 12))

    # Risk gauge
    gauge = _risk_gauge_drawing(risk_score, width=content_width * 0.6)
    if gauge:
        elements.append(gauge)
        elements.append(Spacer(1, 8))

    # Severity bars (stacked horizontal)
    bars = _severity_bars_drawing(
        crit, high, med, low, info_c, total, content_width * 0.85,
    )
    if bars:
        elements.append(
            Paragraph("<b>Severity Distribution</b>", styles["SubSection"])
        )
        elements.append(bars)
        elements.append(Spacer(1, 6))

    # Summary table + donut chart side by side
    if total > 0:
        sum_data = [
            [
                Paragraph("<b>Severity</b>", styles["BodySmall"]),
                Paragraph("<b>Count</b>", styles["BodySmall"]),
            ],
        ]
        for sev_key, count in [
            ("critical", crit), ("high", high), ("medium", med),
            ("low", low), ("info", info_c),
        ]:
            if count > 0:
                color = _severity_color_hex(sev_key)
                sum_data.append([
                    Paragraph(
                        f'<font color="{color}">'
                        f'<b>{SEVERITY_LABELS[sev_key]}</b></font>',
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        f'<font color="{color}"><b>{count}</b></font>',
                        styles["BodySmall"],
                    ),
                ])
        sum_data.append([
            Paragraph("<b>Total</b>", styles["BodySmall"]),
            Paragraph(f"<b>{total}</b>", styles["BodySmall"]),
        ])

        sum_table = Table(sum_data, colWidths=[4 * cm, 2 * cm])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor(BRAND_DARK)),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor(BRAND_WHITE)),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor(BORDER_COLOR)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2),
             [HexColor("#ffffff"), HexColor(BG_LIGHT)]),
            ("BACKGROUND", (0, -1), (-1, -1), HexColor(BG_LIGHT)),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        chart = _severity_chart(findings)

        if chart:
            side = Table(
                [[sum_table, chart]],
                colWidths=[6.5 * cm, content_width - 7 * cm],
            )
            side.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]))
            elements.append(side)
        else:
            elements.append(sum_table)

    elements.append(Spacer(1, 6))

    # ══════════════════════════════════════════════════════════════════
    # Section 2 — Target Profile
    # ══════════════════════════════════════════════════════════════════
    elements.extend(_section_title("2", "Target Profile", styles))

    if profile.target:
        elements.append(
            Paragraph(f"<b>Target:</b> {_esc(profile.target)}", styles["Body"])
        )
    if profile.os_guess:
        elements.append(
            Paragraph(f"<b>OS:</b> {_esc(profile.os_guess)}", styles["Body"])
        )
    if profile.waf_detected:
        waf = profile.waf_type or "Detected (type unknown)"
        elements.append(
            Paragraph(f"<b>WAF:</b> {_esc(waf)}", styles["Body"])
        )

    # Ports table
    if profile.ports:
        elements.append(
            Paragraph("<b>Open Ports</b>", styles["SubSection"])
        )
        port_data = [["Port", "Service", "Product", "Version"]]
        for p in profile.ports[:30]:
            port_data.append([
                f"{p.number}/{p.protocol}",
                p.service or "\u2014",
                p.product or "\u2014",
                p.version or "\u2014",
            ])
        port_table = Table(
            port_data,
            colWidths=[2.5 * cm, 3 * cm, 4 * cm, 3 * cm],
        )
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor(BRAND_DARK)),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor(BRAND_WHITE)),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor(BORDER_COLOR)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [HexColor("#ffffff"), HexColor(BG_LIGHT)]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(port_table)
        elements.append(Spacer(1, 6))

    # Technologies
    if profile.technologies:
        elements.append(
            Paragraph("<b>Technologies</b>", styles["SubSection"])
        )
        tech_items = []
        for t in profile.technologies[:20]:
            ver = f" v{t.version}" if t.version else ""
            tech_items.append(f"{t.name}{ver} ({t.category})")
        elements.append(Paragraph(", ".join(tech_items), styles["Body"]))

    elements.append(Spacer(1, 4))

    # ══════════════════════════════════════════════════════════════════
    # Section 3 — Findings
    # ══════════════════════════════════════════════════════════════════
    elements.append(PageBreak())
    elements.extend(_section_title("3", "Findings", styles))

    if not findings:
        elements.append(Paragraph(
            "No security findings were identified during this assessment.",
            styles["Body"],
        ))
    else:
        for i, finding in enumerate(findings, 1):
            elements.append(
                _finding_card(i, finding, styles, content_width)
            )

    # ══════════════════════════════════════════════════════════════════
    # Section 4 — Assessment Timeline
    # ══════════════════════════════════════════════════════════════════
    elements.extend(_section_title("4", "Assessment Timeline", styles))

    plan = state.plan
    if plan and plan.phases:
        for phase in plan.phases:
            status_icon = {
                "pending": "\u25cb",
                "active": "\u25b6",
                "complete": "\u2713",
                "skipped": "\u2014",
            }.get(phase.status.value, "?")

            elements.append(Paragraph(
                f"<b>{status_icon} {_esc(phase.name)}</b>"
                f" \u2014 {_esc(phase.objective)}",
                styles["SubSection"],
            ))

            for step in phase.steps:
                s_icon = {
                    "pending": "\u25cb",
                    "active": "\u25b6",
                    "complete": "\u2713",
                    "skipped": "\u2014",
                }.get(step.status.value, "?")
                line = f"&nbsp;&nbsp;{s_icon} {_esc(step.description)}"
                if step.result_summary:
                    line += (
                        f' <i><font color="{TEXT_MUTED}">'
                        f"({_esc(_truncate(step.result_summary, 80))})"
                        f"</font></i>"
                    )
                elements.append(Paragraph(line, styles["BodySmall"]))
    else:
        elements.append(Paragraph(
            "No structured attack plan was used for this assessment.",
            styles["Body"],
        ))

    elements.append(Spacer(1, 6))

    # ══════════════════════════════════════════════════════════════════
    # Section 5 — Remediation Summary
    # ══════════════════════════════════════════════════════════════════
    elements.extend(_section_title("5", "Remediation Summary", styles))

    actionable = [
        f for f in findings if f.severity in ("critical", "high", "medium")
    ]
    if actionable:
        elements.append(Paragraph(
            "Address findings in severity order. "
            "Critical and High findings require immediate attention.",
            styles["Body"],
        ))
        elements.append(Spacer(1, 4))

        prio_data = [["#", "Finding", "Severity", "CWE"]]
        for i, f in enumerate(actionable, 1):
            prio_data.append([
                f"P{i}",
                _truncate(f.title, 55),
                f.severity.upper(),
                f.cwe_id or "\u2014",
            ])

        prio_table = Table(
            prio_data,
            colWidths=[1.2 * cm, content_width - 8 * cm, 2.5 * cm, 3.5 * cm],
        )
        prio_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor(BRAND_DARK)),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor(BRAND_WHITE)),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor(BORDER_COLOR)),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [HexColor("#ffffff"), HexColor(BG_LIGHT)]),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(prio_table)
    elif findings:
        elements.append(Paragraph(
            "All findings are Low or Informational severity \u2014 "
            "no critical remediation is required.",
            styles["Body"],
        ))
    else:
        elements.append(Paragraph(
            "No findings require remediation.", styles["Body"],
        ))

    elements.append(Spacer(1, 6))

    # ══════════════════════════════════════════════════════════════════
    # Appendix A — Methodology
    # ══════════════════════════════════════════════════════════════════
    elements.extend(_section_title("A", "Methodology", styles))

    elements.append(Paragraph(
        "This assessment was conducted using NumaSec, an AI-powered "
        "security testing tool combining automated reconnaissance, "
        "vulnerability testing, and intelligent exploitation chaining. "
        "The methodology follows OWASP Testing Guide v4.2 and PTES "
        "(Penetration Testing Execution Standard).",
        styles["Body"],
    ))
    elements.append(Spacer(1, 4))

    for p in [
        "1. <b>Reconnaissance</b> \u2014 port scanning, service "
        "enumeration, technology fingerprinting",
        "2. <b>Mapping</b> \u2014 endpoint discovery, input "
        "identification, attack surface mapping",
        "3. <b>Vulnerability Testing</b> \u2014 injection testing, "
        "auth bypass, known CVEs",
        "4. <b>Exploitation</b> \u2014 proof-of-concept, impact "
        "demonstration, chained attacks",
        "5. <b>Reporting</b> \u2014 severity classification (CVSS v3.1), "
        "CWE mapping, OWASP categorisation",
    ]:
        elements.append(Paragraph(p, styles["Body"]))

    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        "<b>Disclaimer:</b> This report is generated by an automated "
        "tool and should be reviewed by a qualified security "
        "professional. NumaSec is intended for authorised testing only. "
        "The tool authors accept no liability for misuse.",
        styles["BodySmall"],
    ))

    # ── Build PDF ──
    doc.build(elements)
    pdf_bytes = buf.getvalue()
    buf.close()

    logger.info(f"PDF report: {len(pdf_bytes)} bytes, {total} findings")
    return pdf_bytes
