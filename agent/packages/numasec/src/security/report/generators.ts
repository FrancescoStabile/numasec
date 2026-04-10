/**
 * Report generators: SARIF 2.1.0, HTML, Markdown
 */

import { type FindingTable } from "../security.sql"

type Finding = typeof FindingTable.$inferSelect

// ── SARIF 2.1.0 ──────────────────────────────────────────────

interface SarifResult {
  ruleId: string
  level: string
  message: { text: string }
  locations: { physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } } }[]
  properties?: Record<string, any>
}

export function generateSarif(findings: Finding[], targetUrl: string): string {
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
    },
  }))

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "numasec",
            version: "5.0.0",
            informationUri: "https://github.com/FrancescoStabile/numasec",
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            properties: {
              target: targetUrl,
              timestamp: new Date().toISOString(),
            },
          },
        ],
      },
    ],
  }

  return JSON.stringify(sarif, null, 2)
}

// ── Markdown Report ──────────────────────────────────────────

export function generateMarkdown(findings: Finding[], targetUrl: string): string {
  const lines: string[] = []
  const now = new Date().toISOString().split("T")[0]

  lines.push(`# Security Assessment Report`)
  lines.push(``)
  lines.push(`**Target:** ${targetUrl}`)
  lines.push(`**Date:** ${now}`)
  lines.push(`**Tool:** numasec v5.0.0`)
  lines.push(`**Findings:** ${findings.length}`)
  lines.push(``)

  // Executive summary
  const counts: Record<string, number> = {}
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1

  lines.push(`## Executive Summary`)
  lines.push(``)
  const riskScore = calculateRiskScore(findings)
  lines.push(`**Risk Score:** ${riskScore}/100`)
  lines.push(``)
  lines.push(`| Severity | Count |`)
  lines.push(`|----------|-------|`)
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    if (counts[sev]) lines.push(`| ${sev.charAt(0).toUpperCase() + sev.slice(1)} | ${counts[sev]} |`)
  }
  lines.push(``)

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

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sorted = [...findings].sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5))

  for (const f of sorted) {
    const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : f.severity === "low" ? "🟢" : "⚪"
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

  return lines.join("\n")
}

// ── HTML Report ──────────────────────────────────────────────

export function generateHtml(findings: Finding[], targetUrl: string): string {
  const now = new Date().toISOString().split("T")[0]
  const riskScore = calculateRiskScore(findings)
  const counts: Record<string, number> = {}
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1

  const severityColors: Record<string, string> = {
    critical: "#dc3545",
    high: "#fd7e14",
    medium: "#ffc107",
    low: "#28a745",
    info: "#6c757d",
  }

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const sorted = [...findings].sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5))

  const findingCards = sorted
    .map(
      (f) => `
    <div class="card mb-3 border-start border-4" style="border-color: ${severityColors[f.severity] ?? "#999"} !important">
      <div class="card-body">
        <h5 class="card-title">${esc(f.title)}</h5>
        <span class="badge" style="background:${severityColors[f.severity]}">${f.severity.toUpperCase()}</span>
        <span class="badge bg-secondary">${esc(f.id)}</span>
        ${f.cwe_id ? `<span class="badge bg-info">${esc(f.cwe_id)}</span>` : ""}
        ${f.cvss_score ? `<span class="badge bg-dark">CVSS ${f.cvss_score.toFixed(1)}</span>` : ""}
        <p class="mt-2"><strong>URL:</strong> <code>${esc(f.url)}</code> ${f.method ? `(${f.method})` : ""} ${f.parameter ? `param: <code>${esc(f.parameter)}</code>` : ""}</p>
        ${f.description ? `<p>${esc(f.description)}</p>` : ""}
        ${f.payload ? `<p><strong>Payload:</strong> <code>${esc(f.payload)}</code></p>` : ""}
        ${f.evidence ? `<details><summary>Evidence</summary><pre class="bg-dark text-light p-2 rounded">${esc(f.evidence)}</pre></details>` : ""}
        ${f.remediation_summary ? `<p class="text-success"><strong>Remediation:</strong> ${esc(f.remediation_summary)}</p>` : ""}
      </div>
    </div>`,
    )
    .join("\n")

  const severityBadges = ["critical", "high", "medium", "low", "info"]
    .filter((s) => counts[s])
    .map((s) => `<span class="badge me-1" style="background:${severityColors[s]}">${counts[s]} ${s}</span>`)
    .join("")

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment — ${esc(targetUrl)}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>body { background: #f8f9fa; } .risk-score { font-size: 3rem; font-weight: bold; } pre { max-height: 300px; overflow: auto; }</style>
</head>
<body>
  <div class="container py-4">
    <h1>🛡️ Security Assessment Report</h1>
    <p class="lead">Target: <strong>${esc(targetUrl)}</strong> | Date: ${now} | numasec v5.0.0</p>

    <div class="row mb-4">
      <div class="col-md-4">
        <div class="card text-center">
          <div class="card-body">
            <div class="risk-score" style="color: ${riskScore > 70 ? "#dc3545" : riskScore > 40 ? "#ffc107" : "#28a745"}">${riskScore}</div>
            <p class="card-text">Risk Score / 100</p>
          </div>
        </div>
      </div>
      <div class="col-md-8">
        <div class="card">
          <div class="card-body">
            <h5>Summary</h5>
            <p>${findings.length} findings: ${severityBadges}</p>
          </div>
        </div>
      </div>
    </div>

    <h2>Findings</h2>
    ${findingCards}
  </div>
</body>
</html>`
}

// ── Helpers ──────────────────────────────────────────────────

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
