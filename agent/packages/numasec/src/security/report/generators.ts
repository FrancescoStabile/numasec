/**
 * Report generators: SARIF 2.1.0, HTML (self-contained), Markdown
 *
 * All generators accept optional attack chains for narrative sections
 * and remediation roadmaps (PRD §8.2).
 */

import type { FindingTable } from "../security.sql"
import type { ChainGroup } from "../chain-builder"
import { Installation } from "@/installation"

type Finding = typeof FindingTable.$inferSelect

interface ReportContext {
  incomplete?: boolean
  incomplete_reason?: string
  verified_risk_score?: number
  upper_bound_risk_score?: number
  provisional?: Finding[]
  suppressed?: Finding[]
  promotion_gaps?: number
  report_state?: "working_draft" | "final"
  requested_mode?: "working" | "final"
  note?: string
  truth_reasons?: string[]
}

// ── SARIF 2.1.0 ──────────────────────────────────────────────

interface SarifResult {
  ruleId: string
  level: string
  message: { text: string }
  locations: { physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } } }[]
  properties?: Record<string, any>
}

export function generateSarif(findings: Finding[], targetUrl: string, chains?: ChainGroup[], context?: ReportContext): string {
  const severityToLevel: Record<string, string> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
    info: "note",
  }

  const rules = findings.map((f) => ({
    id: f.id,
    shortDescription: { text: f.title },
    fullDescription: { text: f.description || f.title },
    defaultConfiguration: { level: severityToLevel[f.severity] ?? "note" },
    properties: {
      severity: f.severity,
      cwe: f.cwe_id || undefined,
      cvss: f.cvss_score || undefined,
      owasp: f.owasp_category || undefined,
    },
  }))

  const results: SarifResult[] = findings.map((f) => ({
    ruleId: f.id,
    level: severityToLevel[f.severity] ?? "note",
    message: { text: `${f.title}\n\n${f.description}${f.evidence ? `\n\nEvidence:\n${f.evidence}` : ""}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.url || targetUrl },
        },
      },
    ],
    properties: {
      confidence: f.confidence,
      parameter: f.parameter || undefined,
      payload: f.payload || undefined,
      remediation: f.remediation_summary || undefined,
      chainId: f.chain_id || undefined,
    },
  }))

  const invocationProperties: Record<string, any> = {
    target: targetUrl,
    timestamp: new Date().toISOString(),
  }

  if (chains && chains.length > 0) {
    invocationProperties.attackChains = chains.map((c) => ({
      id: c.id,
      title: c.title,
      severity: c.severity,
      impact: c.impact,
      findingIds: c.findings.map((f) => f.id),
    }))
  }
  if (context) {
    invocationProperties.reportTruth = {
      incomplete: context.incomplete ?? false,
      reportState: context.report_state || "final",
      requestedMode: context.requested_mode || "working",
      verifiedRiskScore: context.verified_risk_score,
      upperBoundRiskScore: context.upper_bound_risk_score,
      provisionalCount: context.provisional?.length ?? 0,
      suppressedCount: context.suppressed?.length ?? 0,
      promotionGaps: context.promotion_gaps ?? 0,
      note: context.note || context.incomplete_reason || undefined,
      truthReasons: context.truth_reasons ?? [],
    }
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "numasec",
            version: Installation.VERSION,
            informationUri: "https://github.com/FrancescoStabile/numasec",
            rules,
          },
        },
        results,
        invocations: [{ executionSuccessful: true, properties: invocationProperties }],
      },
    ],
  }

  return JSON.stringify(sarif, null, 2)
}

// ── Markdown Report ──────────────────────────────────────────

export function generateMarkdown(findings: Finding[], targetUrl: string, chains?: ChainGroup[], context?: ReportContext): string {
  const lines: string[] = []
  const now = new Date().toISOString().split("T")[0]
  const note = context?.note ?? context?.incomplete_reason ?? ""

  lines.push(`# Security Assessment Report`)
  lines.push(``)
  lines.push(`**Target:** ${targetUrl}`)
  lines.push(`**Date:** ${now}`)
  lines.push(`**Tool:** numasec v${Installation.VERSION}`)
  lines.push(`**Findings:** ${findings.length}`)
  lines.push(``)

  if (context?.report_state === "working_draft") {
    lines.push(`> REPORT_WORKING_DRAFT`)
    lines.push(`> This working report reflects the current verified state of the engagement.`)
    lines.push(`> Final readiness is not yet satisfied; see Truthfulness Notice for remaining verification debt.`)
    lines.push(``)
  }

  if (context && (context.incomplete || (context.provisional?.length ?? 0) > 0 || (context.promotion_gaps ?? 0) > 0)) {
    lines.push(`## Truthfulness Notice`)
    lines.push(``)
    lines.push(`This report includes only **verified** findings in the main risk score and findings section.`)
    lines.push(``)
    lines.push(`- Verified risk score: ${context.verified_risk_score ?? calculateRiskScore(findings)}/100`)
    if (context.upper_bound_risk_score !== undefined && context.upper_bound_risk_score !== (context.verified_risk_score ?? calculateRiskScore(findings))) {
      lines.push(`- Upper-bound risk score (verified + provisional): ${context.upper_bound_risk_score}/100`)
    }
    if ((context.provisional?.length ?? 0) > 0) lines.push(`- Provisional reportable findings excluded from verified score: ${context.provisional?.length ?? 0}`)
    if ((context.suppressed?.length ?? 0) > 0) lines.push(`- Suppressed/refuted findings: ${context.suppressed?.length ?? 0}`)
    if ((context.promotion_gaps ?? 0) > 0) lines.push(`- Promotion gaps: ${context.promotion_gaps}`)
    for (const item of context.truth_reasons ?? []) {
      if (!item.trim()) continue
      lines.push(`- ${item}`)
    }
    if (note) lines.push(`- Report note: ${note}`)
    lines.push(``)
  }

  // Executive summary
  const counts: Record<string, number> = {}
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1

  lines.push(`## Executive Summary`)
  lines.push(``)
  const riskScore = context?.verified_risk_score ?? calculateRiskScore(findings)
  lines.push(`**Verified Risk Score:** ${riskScore}/100`)
  if (context?.upper_bound_risk_score !== undefined && context.upper_bound_risk_score !== riskScore) {
    lines.push(`**Upper-Bound Risk Score:** ${context.upper_bound_risk_score}/100`)
  }
  lines.push(``)
  lines.push(`| Severity | Count |`)
  lines.push(`|----------|-------|`)
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    if (counts[sev]) lines.push(`| ${sev.charAt(0).toUpperCase() + sev.slice(1)} | ${counts[sev]} |`)
  }
  lines.push(``)

  // Attack Paths (from chains)
  if (chains && chains.length > 0) {
    lines.push(`## Attack Paths`)
    lines.push(``)
    for (const chain of chains) {
      const icon = chain.severity === "critical" ? "🔴" : chain.severity === "high" ? "🟠" : "🟡"
      lines.push(`### ${icon} ${chain.id}: ${chain.title}`)
      lines.push(``)
      lines.push(`**Severity:** ${chain.severity.toUpperCase()} | **Impact:** ${chain.impact}`)
      lines.push(``)
      for (let i = 0; i < chain.findings.length; i++) {
        const f = chain.findings[i]
        lines.push(`${i + 1}. **${f.title}** (${f.severity.toUpperCase()})`)
        lines.push(`   ${f.url} ${f.parameter ? `→ \`${f.parameter}\`` : ""}`)
      }
      lines.push(``)
    }
  }

  // OWASP coverage
  const owaspCategories = new Set(findings.map((f) => f.owasp_category).filter(Boolean))
  if (owaspCategories.size > 0) {
    lines.push(`## OWASP Top 10 Coverage`)
    lines.push(``)
    for (const cat of owaspCategories) {
      const catFindings = findings.filter((f) => f.owasp_category === cat)
      lines.push(`- **${cat}**: ${catFindings.length} finding(s)`)
    }
    lines.push(``)
  }

  // Findings
  lines.push(`## Findings`)
  lines.push(``)

  const sorted = sortBySeverity(findings)
  for (const f of sorted) {
    const icon = severityIcon(f.severity)
    lines.push(`### ${icon} ${f.title}`)
    lines.push(``)
    lines.push(`| Field | Value |`)
    lines.push(`|-------|-------|`)
    lines.push(`| ID | ${f.id} |`)
    lines.push(`| Severity | ${f.severity.toUpperCase()} |`)
    lines.push(`| URL | ${f.url} |`)
    if (f.method) lines.push(`| Method | ${f.method} |`)
    if (f.parameter) lines.push(`| Parameter | ${f.parameter} |`)
    if (f.cwe_id) lines.push(`| CWE | ${f.cwe_id} |`)
    if (f.cvss_score) lines.push(`| CVSS | ${f.cvss_score.toFixed(1)} |`)
    if (f.owasp_category) lines.push(`| OWASP | ${f.owasp_category} |`)
    lines.push(``)

    if (f.description) {
      lines.push(`**Description:** ${f.description}`)
      lines.push(``)
    }

    if (f.evidence) {
      lines.push(`<details><summary>Evidence</summary>`)
      lines.push(``)
      lines.push("```")
      lines.push(f.evidence)
      lines.push("```")
      lines.push(`</details>`)
      lines.push(``)
    }

    if (f.payload) {
      lines.push(`**Payload:** \`${f.payload}\``)
      lines.push(``)
    }

    if (f.remediation_summary) {
      lines.push(`**Remediation:** ${f.remediation_summary}`)
      lines.push(``)
    }

    lines.push(`---`)
    lines.push(``)
  }

  const provisional = sortBySeverity(context?.provisional ?? [])
  if (provisional.length > 0) {
    lines.push(`## Provisional Findings`)
    lines.push(``)
    lines.push(`These findings are reportable signals but do not yet meet the verified evidence contract.`)
    lines.push(``)
    for (const f of provisional) {
      const icon = severityIcon(f.severity)
      lines.push(`### ${icon} ${f.title}`)
      lines.push(``)
      lines.push(`| Field | Value |`)
      lines.push(`|-------|-------|`)
      lines.push(`| ID | ${f.id} |`)
      lines.push(`| Severity | ${f.severity.toUpperCase()} |`)
      lines.push(`| State | ${f.state || "provisional"} |`)
      lines.push(`| URL | ${f.url} |`)
      if (f.method) lines.push(`| Method | ${f.method} |`)
      if (f.parameter) lines.push(`| Parameter | ${f.parameter} |`)
      if (f.description) {
        lines.push(``)
        lines.push(`**Description:** ${f.description}`)
      }
      if (f.evidence) {
        lines.push(``)
        lines.push(`**Evidence refs:** \`${f.evidence}\``)
      }
      lines.push(``)
    }
  }

  // Remediation Roadmap
  lines.push(generateRemediationRoadmap(sorted))

  return lines.join("\n")
}

// ── HTML Report (self-contained) ──────────────────────────────

const INLINE_CSS = `*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8f9fa;color:#212529;line-height:1.6;padding:2rem 1rem}.container{max-width:960px;margin:0 auto}.row{display:flex;flex-wrap:wrap;gap:1rem;margin-bottom:1.5rem}.col-4{flex:0 0 calc(33.333% - .67rem)}.col-8{flex:0 0 calc(66.667% - .33rem)}.card{background:#fff;border:1px solid #dee2e6;border-radius:.375rem}.card-body{padding:1rem}.text-center{text-align:center}.badge{display:inline-block;padding:.2em .5em;font-size:.75rem;font-weight:700;color:#fff;border-radius:.25rem;margin-right:.25rem}.lead{font-size:1.05rem;color:#6c757d;margin-bottom:1rem}.text-success{color:#198754}code{background:#e9ecef;padding:.1em .25em;border-radius:.2rem;font-size:.875em}pre{background:#212529;color:#f8f9fa;padding:.75rem;border-radius:.375rem;overflow:auto;max-height:300px;margin:.5rem 0}pre code{background:transparent;padding:0}details{margin:.5rem 0}summary{cursor:pointer;font-weight:600}h1{font-size:1.75rem;margin-bottom:.25rem}h2{font-size:1.4rem;margin:1.5rem 0 .75rem;border-bottom:2px solid #dee2e6;padding-bottom:.25rem}h3{font-size:1.15rem;margin:1rem 0 .5rem}h5{font-size:1rem;margin-bottom:.4rem}p{margin:.25rem 0}strong{font-weight:600}.finding{background:#fff;border:1px solid #dee2e6;border-radius:.375rem;border-left:4px solid;padding:1rem;margin-bottom:1rem}.chain-card{background:#fff;border:1px solid #dee2e6;border-radius:.375rem;padding:1rem;margin-bottom:.75rem}.chain-step{padding:.25rem 0 .25rem 1rem;border-left:2px solid #dee2e6;margin:.25rem 0}.risk-score{font-size:3rem;font-weight:bold}.roadmap-item{padding:.5rem 0;border-bottom:1px solid #f0f0f0}@media(max-width:768px){.col-4,.col-8{flex:0 0 100%}}`

export function generateHtml(findings: Finding[], targetUrl: string, chains?: ChainGroup[], context?: ReportContext): string {
  const now = new Date().toISOString().split("T")[0]
  const riskScore = context?.verified_risk_score ?? calculateRiskScore(findings)
  const note = context?.note ?? context?.incomplete_reason ?? ""
  const counts: Record<string, number> = {}
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1

  const sorted = sortBySeverity(findings)

  const severityBadges = ["critical", "high", "medium", "low", "info"]
    .filter((s) => counts[s])
    .map((s) => `<span class="badge" style="background:${SEV_COLORS[s]}">${counts[s]} ${s}</span>`)
    .join("")

  // Attack chains HTML
  let chainsHtml = ""
  if (chains && chains.length > 0) {
    const chainCards = chains
      .map((c) => {
        const steps = c.findings
          .map((f) => `<div class="chain-step"><strong>${esc(f.title)}</strong> <span class="badge" style="background:${SEV_COLORS[f.severity]}">${f.severity}</span><br><code>${esc(f.url)}</code></div>`)
          .join("")
        return `<div class="chain-card"><h3>${esc(c.id)}: ${esc(c.title)}</h3><p><strong>Severity:</strong> ${c.severity.toUpperCase()} | <strong>Impact:</strong> ${esc(c.impact)}</p>${steps}</div>`
      })
      .join("")
    chainsHtml = `<h2>⛓ Attack Paths</h2>${chainCards}`
  }

  // Finding cards
  const findingCards = sorted
    .map(
      (f) => `
    <div class="finding" style="border-left-color:${SEV_COLORS[f.severity] ?? "#999"}">
      <h5>${esc(f.title)}</h5>
      <span class="badge" style="background:${SEV_COLORS[f.severity]}">${f.severity.toUpperCase()}</span>
      <span class="badge" style="background:#6c757d">${esc(f.id)}</span>
      ${f.cwe_id ? `<span class="badge" style="background:#0dcaf0;color:#000">${esc(f.cwe_id)}</span>` : ""}
      ${f.cvss_score ? `<span class="badge" style="background:#212529">CVSS ${f.cvss_score.toFixed(1)}</span>` : ""}
      <p style="margin-top:.5rem"><strong>URL:</strong> <code>${esc(f.url)}</code> ${f.method ? `(${f.method})` : ""} ${f.parameter ? `param: <code>${esc(f.parameter)}</code>` : ""}</p>
      ${f.description ? `<p>${esc(f.description)}</p>` : ""}
      ${f.payload ? `<p><strong>Payload:</strong> <code>${esc(f.payload)}</code></p>` : ""}
      ${f.evidence ? `<details><summary>Evidence</summary><pre><code>${esc(f.evidence)}</code></pre></details>` : ""}
      ${f.remediation_summary ? `<p class="text-success"><strong>Remediation:</strong> ${esc(f.remediation_summary)}</p>` : ""}
    </div>`,
    )
    .join("\n")

  const roadmapHtml = generateHtmlRemediation(sorted)
  const truthHtml =
    context && (context.incomplete || (context.provisional?.length ?? 0) > 0 || (context.promotion_gaps ?? 0) > 0)
      ? `<div class="card" style="margin-bottom:1rem;border-left:4px solid #dc3545"><div class="card-body">${
          context.report_state === "working_draft"
            ? `<h5>REPORT_WORKING_DRAFT</h5><p>This working report reflects the current verified state of the engagement.</p><p><strong>Final readiness is not yet satisfied.</strong></p>`
            : ""
        }<h5>Truthfulness Notice</h5><p>This report scores only verified findings.</p><p><strong>Verified risk:</strong> ${context.verified_risk_score ?? riskScore}/100${
          context.upper_bound_risk_score !== undefined && context.upper_bound_risk_score !== (context.verified_risk_score ?? riskScore)
            ? ` | <strong>Upper bound:</strong> ${context.upper_bound_risk_score}/100`
            : ""
        }</p><p><strong>Provisional:</strong> ${context.provisional?.length ?? 0} | <strong>Suppressed/refuted:</strong> ${context.suppressed?.length ?? 0} | <strong>Promotion gaps:</strong> ${context.promotion_gaps ?? 0}</p>${
          (context.truth_reasons ?? []).length > 0 ? `<p><strong>Remaining debt:</strong><br>${(context.truth_reasons ?? []).map((item) => `- ${esc(item)}`).join("<br>")}</p>` : ""
        }${note ? `<p><strong>Report note:</strong> ${esc(note)}</p>` : ""}</div></div>`
      : ""
  const provisionalHtml =
    (context?.provisional?.length ?? 0) > 0
      ? `<h2>Provisional Findings</h2><p>These findings are excluded from the verified risk score until the evidence contract is complete.</p>${sortBySeverity(context?.provisional ?? [])
          .map(
            (f) => `<div class="finding" style="border-left-color:${SEV_COLORS[f.severity] ?? "#999"}"><h5>${esc(f.title)}</h5><span class="badge" style="background:${SEV_COLORS[f.severity]}">${f.severity.toUpperCase()}</span><span class="badge" style="background:#6c757d">${esc(f.state || "provisional")}</span><p style="margin-top:.5rem"><strong>URL:</strong> <code>${esc(f.url)}</code> ${f.method ? `(${f.method})` : ""} ${f.parameter ? `param: <code>${esc(f.parameter)}</code>` : ""}</p>${f.description ? `<p>${esc(f.description)}</p>` : ""}${f.evidence ? `<details><summary>Evidence refs</summary><pre><code>${esc(f.evidence)}</code></pre></details>` : ""}</div>`,
          )
          .join("")}`
      : ""

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment — ${esc(targetUrl)}</title>
  <style>${INLINE_CSS}</style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Security Assessment Report</h1>
    <p class="lead">Target: <strong>${esc(targetUrl)}</strong> | Date: ${now} | numasec v${Installation.VERSION}</p>

    <div class="row">
      <div class="col-4">
        <div class="card">
          <div class="card-body text-center">
            <div class="risk-score" style="color:${riskScore > 70 ? "#dc3545" : riskScore > 40 ? "#ffc107" : "#28a745"}">${riskScore}</div>
            <p>Risk Score / 100</p>
          </div>
        </div>
      </div>
      <div class="col-8">
        <div class="card">
          <div class="card-body">
            <h5>Summary</h5>
            <p>${findings.length} verified findings: ${severityBadges}${
              context?.report_state === "working_draft" ? ` <span class="badge" style="background:#6c757d">WORKING DRAFT</span>` : ""
            }</p>
          </div>
        </div>
      </div>
    </div>

    ${truthHtml}

    ${chainsHtml}

    <h2>Findings</h2>
    ${findingCards}

    ${provisionalHtml}

    ${roadmapHtml}
  </div>
</body>
</html>`
}

// ── Helpers ──────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "#dc3545",
  high: "#fd7e14",
  medium: "#ffc107",
  low: "#28a745",
  info: "#6c757d",
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
}

function severityIcon(sev: string): string {
  return sev === "critical" ? "🔴" : sev === "high" ? "🟠" : sev === "medium" ? "🟡" : sev === "low" ? "🟢" : "⚪"
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
}

export function calculateRiskScore(findings: Finding[]): number {
  const weights: Record<string, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 1 }
  let score = 0
  for (const f of findings) {
    score += (weights[f.severity] ?? 1) * f.confidence
  }
  return Math.min(100, Math.round(score))
}

/** Generate Markdown remediation roadmap grouped by severity. */
function generateRemediationRoadmap(sorted: Finding[]): string {
  const lines: string[] = [`## Remediation Roadmap`, ``]
  const seen = new Set<string>()

  for (const sev of ["critical", "high", "medium", "low"] as const) {
    const group = sorted.filter((f) => f.severity === sev && f.remediation_summary)
    if (group.length === 0) continue

    const icon = severityIcon(sev)
    lines.push(`### ${icon} ${sev.charAt(0).toUpperCase() + sev.slice(1)} Priority`)
    lines.push(``)

    let idx = 0
    for (const f of group) {
      const key = f.remediation_summary.toLowerCase().trim()
      if (seen.has(key)) continue
      seen.add(key)
      idx++
      lines.push(`${idx}. **${f.title}** — ${f.remediation_summary}`)
    }
    lines.push(``)
  }

  if (seen.size === 0) {
    lines.push(`_No specific remediation guidance was provided for the findings. Review each finding individually._`)
    lines.push(``)
  }

  return lines.join("\n")
}

/** Generate HTML remediation roadmap. */
function generateHtmlRemediation(sorted: Finding[]): string {
  const items: string[] = []
  const seen = new Set<string>()

  for (const sev of ["critical", "high", "medium", "low"] as const) {
    const group = sorted.filter((f) => f.severity === sev && f.remediation_summary)
    for (const f of group) {
      const key = f.remediation_summary.toLowerCase().trim()
      if (seen.has(key)) continue
      seen.add(key)
      items.push(`<div class="roadmap-item"><span class="badge" style="background:${SEV_COLORS[sev]}">${sev}</span> <strong>${esc(f.title)}</strong> — ${esc(f.remediation_summary)}</div>`)
    }
  }

  if (items.length === 0) return ""
  return `<h2>📋 Remediation Roadmap</h2>${items.join("")}`
}
