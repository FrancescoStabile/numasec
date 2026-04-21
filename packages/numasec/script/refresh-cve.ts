#!/usr/bin/env bun
/**
 * Builds `assets/cve/index.json.gz` from the NVD `recent` + `modified` JSON
 * feeds pre-downloaded into `.cve-tmp/`. Merges with the existing bundle so
 * older CVEs are preserved across runs. Called by
 * `.github/workflows/cve-refresh.yml`.
 *
 * Shape matches src/tool/cve.ts:
 *   { id, severity, cvss, summary, cpe[], published }[]
 */

import { gzipSync, gunzipSync } from "node:zlib"
import fs from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

type Severity = "low" | "medium" | "high" | "critical"

type Entry = {
  id: string
  severity: Severity
  cvss: number
  summary: string
  cpe: string[]
  published: string
}

const SUMMARY_MAX = 280
const MAX_CPE = 8
const MAX_BYTES = 8 * 1024 * 1024
const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(__dirname, "../../..")
const out = path.join(root, "assets/cve/index.json.gz")
const tmp = path.join(root, ".cve-tmp")

function trim(summary: string): string {
  return summary.length <= SUMMARY_MAX ? summary : summary.slice(0, SUMMARY_MAX - 1).trimEnd() + "…"
}

function severityFrom(v3: number | undefined, v2: number | undefined): Severity {
  const score = typeof v3 === "number" ? v3 : typeof v2 === "number" ? v2 : 0
  if (score >= 9.0) return "critical"
  if (score >= 7.0) return "high"
  if (score >= 4.0) return "medium"
  return "low"
}

function collectCpe(nodes: unknown[] | undefined): string[] {
  if (!Array.isArray(nodes)) return []
  const out: string[] = []
  const walk = (node: any): void => {
    if (!node || typeof node !== "object") return
    if (Array.isArray(node.cpe_match)) {
      for (const m of node.cpe_match) {
        if (m?.cpe23Uri && typeof m.cpe23Uri === "string") out.push(m.cpe23Uri)
      }
    }
    if (Array.isArray(node.children)) for (const c of node.children) walk(c)
  }
  for (const n of nodes) walk(n)
  return Array.from(new Set(out)).slice(0, MAX_CPE)
}

function parseFeed(file: string): Entry[] {
  const raw = JSON.parse(fs.readFileSync(file, "utf8")) as {
    CVE_Items?: Array<any>
  }
  const items = raw.CVE_Items ?? []
  const out: Entry[] = []
  for (const item of items) {
    const id = item?.cve?.CVE_data_meta?.ID
    if (typeof id !== "string") continue
    const desc = item?.cve?.description?.description_data?.find((d: any) => d.lang === "en")?.value ?? ""
    const v3 = item?.impact?.baseMetricV3?.cvssV3?.baseScore
    const v2 = item?.impact?.baseMetricV2?.cvssV2?.baseScore
    const score = typeof v3 === "number" ? v3 : typeof v2 === "number" ? v2 : 0
    out.push({
      id,
      severity: severityFrom(v3, v2),
      cvss: Number(score.toFixed(1)),
      summary: trim(desc),
      cpe: collectCpe(item?.configurations?.nodes),
      published: item?.publishedDate ?? "",
    })
  }
  return out
}

function loadExisting(): Entry[] {
  if (!fs.existsSync(out)) return []
  try {
    const gz = fs.readFileSync(out)
    return JSON.parse(gunzipSync(gz).toString("utf8")) as Entry[]
  } catch {
    return []
  }
}

const feeds = ["recent.json", "modified.json"]
const fresh: Entry[] = feeds.flatMap((f) => {
  const p = path.join(tmp, f)
  if (!fs.existsSync(p)) {
    console.warn(`missing feed: ${p}`)
    return []
  }
  const items = parseFeed(p)
  console.log(`${f}: ${items.length} items`)
  return items
})

const byId = new Map<string, Entry>()
for (const e of loadExisting()) byId.set(e.id, e)
for (const e of fresh) byId.set(e.id, e) // newer wins

let merged = Array.from(byId.values())
merged.sort((a, b) => {
  const r = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  if (r !== 0) return r
  return b.published.localeCompare(a.published)
})

const encode = (list: Entry[]) => gzipSync(Buffer.from(JSON.stringify(list)), { level: 9 })

let gz = encode(merged)
while (gz.byteLength > MAX_BYTES && merged.length > 0) {
  // Drop lowest-severity, oldest entries first.
  merged = merged.filter((e, i, arr) => {
    if (e.severity !== "low") return true
    // drop this low-severity entry only if beyond first 100 low entries
    const lowIndex = arr.slice(0, i + 1).filter((x) => x.severity === "low").length
    return lowIndex <= 100
  })
  const next = encode(merged)
  if (next.byteLength >= gz.byteLength) {
    // no progress; hard-truncate
    merged = merged.slice(0, Math.floor(merged.length * 0.9))
  }
  gz = encode(merged)
}

fs.mkdirSync(path.dirname(out), { recursive: true })
fs.writeFileSync(out, gz)
console.log(`wrote ${out}`)
console.log(`entries: ${merged.length}`)
console.log(`gzipped: ${gz.byteLength} bytes`)
