import { access, readdir, readFile } from "node:fs/promises"
import { createHash } from "node:crypto"
import os from "node:os"
import path from "node:path"
import { Methodology } from "@/core/methodology"
import { componentSearchTerms, normalizeComponent } from "./component"
import { collectNvdRanges, evaluateNvdApplicability } from "./nvd-match"
import type {
  KnowledgeAction,
  KnowledgeCard,
  KnowledgeClaim,
  KnowledgeIntent,
  KnowledgeMode,
  KnowledgeRequest,
  KnowledgeResult,
  KnowledgeSource,
  ResearchCard,
  VulnIntelCard,
} from "./types"
import type { NormalizedComponent } from "./component"

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>
type CommandResult = { argv: string[]; stdout: string; stderr: string; exitCode: number }

export type BrokerDeps = {
  fetch?: FetchLike
  which?: (name: string) => string | null
  run?: (argv: string[], timeoutMs?: number) => Promise<CommandResult>
  now?: () => number
  readText?: (file: string) => Promise<string>
  listDir?: (dir: string) => Promise<string[]>
  readCache?: (key: string) => Promise<KnowledgeResult | undefined>
  writeCache?: (key: string, result: KnowledgeResult) => Promise<void>
}

const DAY = 24 * 60 * 60 * 1000
const WEEK = 7 * DAY
const MONTH = 30 * DAY
const USER_AGENT = "numasec-knowledge-broker/1.2"

const defaultDeps: Required<BrokerDeps> = {
  fetch: (input, init) => fetch(input, init),
  which: (name) => Bun.which(name),
  run: async (argv, timeoutMs = 10_000) => {
    const proc = Bun.spawn(argv, {
      stdout: "pipe",
      stderr: "pipe",
      timeout: timeoutMs,
    })
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ])
    const exitCode = await proc.exited
    return { argv, stdout, stderr, exitCode }
  },
  now: () => Date.now(),
  readText: (file) => readFile(file, "utf8"),
  listDir: async (dir) => {
    const entries = await readdir(dir, { withFileTypes: true })
    return entries.map((entry) => path.join(dir, entry.name))
  },
  readCache: async () => undefined,
  writeCache: async () => undefined,
}

function source(input: KnowledgeSource): KnowledgeSource {
  return input
}

function uniq<T>(items: T[]): T[] {
  return [...new Set(items)]
}

function compact<T>(items: Array<T | undefined | null | false>): T[] {
  return items.filter(Boolean) as T[]
}

function cveIDs(input: string): string[] {
  return uniq(input.match(/CVE-\d{4}-\d{4,}/gi)?.map((item) => item.toUpperCase()) ?? [])
}

function safeString(input: unknown): string | undefined {
  return typeof input === "string" && input.trim() ? input.trim() : undefined
}

function asObject(input: unknown): Record<string, unknown> | undefined {
  return input && typeof input === "object" && !Array.isArray(input) ? (input as Record<string, unknown>) : undefined
}

function asArray(input: unknown): unknown[] {
  return Array.isArray(input) ? input : []
}

function number(input: unknown): number | undefined {
  return typeof input === "number" && Number.isFinite(input) ? input : undefined
}

function requestURL(base: string, params: Record<string, string | number | boolean | undefined>) {
  const url = new URL(base)
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue
    url.searchParams.set(key, String(value))
  }
  return url.href
}

function cacheKey(input: KnowledgeRequest) {
  const stable = {
    intent: input.intent,
    action: input.action,
    query: input.query,
    observed_refs: input.observed_refs ?? [],
    limit: input.limit,
  }
  return createHash("sha256").update(JSON.stringify(stable)).digest("hex")
}

function fromCache(result: KnowledgeResult, request: KnowledgeRequest, now: number): KnowledgeResult {
  return {
    ...result,
    request,
    sources: [
      ...result.sources,
      source({
        name: "workspace knowledge cache",
        source_type: "cache",
        trust: "medium",
        fetched_at: now,
        stale_after: result.stale_after,
      }),
    ],
    summary: `${request.intent}/${request.action} "${request.query}" returned ${result.cards.length} cached card${result.cards.length === 1 ? "" : "s"}`,
  }
}

async function fetchJSON(
  deps: Required<BrokerDeps>,
  url: string,
  init?: RequestInit,
): Promise<{ json?: unknown; source: KnowledgeSource }> {
  const fetchedAt = deps.now()
  try {
    const response = await deps.fetch(url, {
      ...init,
      headers: {
        Accept: "application/json",
        "User-Agent": USER_AGENT,
        ...(init?.headers ?? {}),
      },
      signal: AbortSignal.timeout(15_000),
    })
    if (!response.ok) {
      return {
        source: source({
          name: new URL(url).hostname,
          url,
          source_type: "structured",
          trust: "high",
          fetched_at: fetchedAt,
          stale_after: fetchedAt + DAY,
          degraded: true,
          error: `HTTP ${response.status}`,
        }),
      }
    }
    return {
      json: await response.json(),
      source: source({
        name: new URL(url).hostname,
        url,
        source_type: "structured",
        trust: "high",
        fetched_at: fetchedAt,
        stale_after: fetchedAt + DAY,
      }),
    }
  } catch (error) {
    return {
      source: source({
        name: new URL(url).hostname,
        url,
        source_type: "structured",
        trust: "high",
        fetched_at: fetchedAt,
        stale_after: fetchedAt + DAY,
        degraded: true,
        error: error instanceof Error ? error.message : String(error),
      }),
    }
  }
}

type PackageSpec = { ecosystem: string; name: string; version?: string }

function normalizeEcosystem(input: string) {
  const lower = input.toLowerCase()
  if (lower === "pypi" || lower === "python") return "PyPI"
  if (lower === "go" || lower === "golang") return "Go"
  if (lower === "maven" || lower === "java") return "Maven"
  if (lower === "nuget" || lower === "dotnet") return "NuGet"
  if (lower === "rubygems" || lower === "ruby") return "RubyGems"
  if (lower === "cargo" || lower === "rust" || lower === "crates.io") return "crates.io"
  if (lower === "composer" || lower === "php" || lower === "packagist") return "Packagist"
  return lower === "npm" || lower === "node" ? "npm" : input
}

function parsePackageSpec(query: string): PackageSpec | undefined {
  const purl = query.match(/^pkg:([^/]+)\/([^@\s]+)(?:@([^\s]+))?$/i)
  if (purl) return { ecosystem: normalizeEcosystem(purl[1]!), name: purl[2]!, version: purl[3] }
  const direct = query.match(/^(npm|pypi|python|go|golang|maven|nuget|rubygems|ruby|cargo|rust|crates\.io|composer|php|packagist|node):([^@\s]+)(?:@([^\s]+))?$/i)
  if (direct) return { ecosystem: normalizeEcosystem(direct[1]!), name: direct[2]!, version: direct[3] }
  return undefined
}

function opsecSafeQuery(request: KnowledgeRequest): { query: string; blocked?: string } {
  if (request.mode !== "opsec_strict") return { query: request.query }
  const ids = cveIDs(request.query)
  if (ids.length > 0) return { query: ids.join(" ") }
  const pkg = parsePackageSpec(request.query)
  if (pkg) return { query: request.query }
  if (/https?:\/\/|\/[A-Za-z0-9._~!$&'()*+,;=:@%-]+|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(request.query)) {
    return { query: "", blocked: "opsec_strict refused to send target-specific URL, path, or email data to external sources" }
  }
  return { query: request.query.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "").trim() }
}

function cvssFromNvd(cve: Record<string, unknown>) {
  const metrics = asObject(cve.metrics)
  const v4 = asArray(metrics?.cvssMetricV40)[0]
  const v31 = asArray(metrics?.cvssMetricV31)[0] ?? asArray(metrics?.cvssMetricV30)[0]
  const v2 = asArray(metrics?.cvssMetricV2)[0]
  const primary = asObject(v4) ?? asObject(v31) ?? asObject(v2)
  const data = asObject(primary?.cvssData)
  const score = number(data?.baseScore)
  const severity = safeString(primary?.baseSeverity) ?? safeString(data?.baseSeverity)
  return {
    cvss_v4: asObject(v4) ? score : undefined,
    cvss_v3: asObject(v31) ? score : undefined,
    level: severity?.toLowerCase(),
    source: score === undefined ? undefined : "nvd",
  }
}

function nvdCard(cve: Record<string, unknown>, fetchedAt: number, sourceRef: KnowledgeSource, component?: NormalizedComponent): VulnIntelCard | undefined {
  const id = safeString(cve.id)
  if (!id) return undefined
  const descriptions = asArray(cve.descriptions)
  const description = descriptions
    .map(asObject)
    .find((item) => item?.lang === "en")
  const refs = asArray(cve.references)
    .map(asObject)
    .map((item) => safeString(item?.url))
    .filter((item): item is string => Boolean(item))
    .slice(0, 20)
  const ranges = collectNvdRanges(asObject(cve.configurations)?.nodes)
  const applicability = evaluateNvdApplicability({
    component,
    ranges,
    summary: safeString(description?.value),
  })
  return {
    kind: "vuln_intel",
    id,
    aliases: [],
    title: id,
    summary: safeString(description?.value),
    affected: ranges.slice(0, 20).map((range) => ({
      cpe: range.criteria,
      version_range: applicability.matched_criteria === range.criteria ? applicability.affected_range : undefined,
    })),
    severity: cvssFromNvd(cve),
    exploitation: {
      public_exploit_signal: refs.some((url) => /exploit-db|metasploit|packetstorm|github\.com/i.test(url)),
    },
    applicability: {
      matched_component: component?.name,
      matched_version: component?.version,
      state: applicability.state,
      confidence: applicability.confidence,
      reason: applicability.reason,
      version_match: applicability.version_match,
      affected_range: applicability.affected_range,
      matched_criteria: applicability.matched_criteria,
      preconditions: applicability.preconditions,
      distro_backport_note: component?.version ? "Distribution packages may backport security fixes without changing the upstream version string." : undefined,
      verification_steps: applicability.verification_steps,
    },
    references: refs,
    safe_next_actions: [
      ...(applicability.verification_steps.length ? applicability.verification_steps : ["Confirm the exact affected product, package, build, and backport status before promotion."]),
      "Prefer safe fingerprinting and vendor advisory comparison before exploit attempts.",
    ],
    fetched_at: fetchedAt,
    source_freshness: safeString(cve.lastModified),
    stale_after: fetchedAt + DAY,
    sources: [sourceRef],
  }
}

async function nvdLookup(deps: Required<BrokerDeps>, query: string, limit: number, component?: NormalizedComponent) {
  const ids = cveIDs(query)
  const componentCpes = component?.cpe_candidates.slice(0, 3) ?? []
  const keyword = component ? componentSearchTerms(component)[0] : query
  const urls =
    ids.length === 1
      ? [requestURL("https://services.nvd.nist.gov/rest/json/cves/2.0", { cveId: ids[0] })]
      : componentCpes.length
        ? componentCpes.map((cpe) =>
            requestURL("https://services.nvd.nist.gov/rest/json/cves/2.0", {
              virtualMatchString: cpe,
              resultsPerPage: Math.min(Math.max(limit * 4, 20), 100),
            }),
          )
        : [
            requestURL("https://services.nvd.nist.gov/rest/json/cves/2.0", {
              keywordSearch: keyword,
              resultsPerPage: Math.min(limit, 50),
            }),
          ]
  const fetchedAt = deps.now()
  const responses = await Promise.all(urls.map((url) => fetchJSON(deps, url)))
  const cards = responses.flatMap(({ json, source: sourceRef }) =>
    asArray(asObject(json)?.vulnerabilities)
      .map(asObject)
      .map((item) => asObject(item?.cve))
      .filter((item): item is Record<string, unknown> => Boolean(item))
      .map((item) => nvdCard(item, fetchedAt, sourceRef, component))
      .filter((item): item is VulnIntelCard => Boolean(item)),
  )
  return { cards, sources: responses.map((item) => item.source) }
}

async function kevSignals(deps: Required<BrokerDeps>, ids: string[]) {
  if (ids.length === 0) return { signals: new Map<string, Record<string, unknown>>(), sources: [] as KnowledgeSource[] }
  const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  const { json, source: sourceRef } = await fetchJSON(deps, url)
  const wanted = new Set(ids)
  const signals = new Map<string, Record<string, unknown>>()
  for (const item of asArray(asObject(json)?.vulnerabilities).map(asObject)) {
    const id = safeString(item?.cveID)?.toUpperCase()
    if (id && wanted.has(id)) signals.set(id, item!)
  }
  return { signals, sources: [sourceRef] }
}

async function epssSignals(deps: Required<BrokerDeps>, ids: string[]) {
  if (ids.length === 0) return { signals: new Map<string, { epss?: number; percentile?: number }>(), sources: [] as KnowledgeSource[] }
  const url = requestURL("https://api.first.org/data/v1/epss", { cve: ids.join(",") })
  const { json, source: sourceRef } = await fetchJSON(deps, url)
  const signals = new Map<string, { epss?: number; percentile?: number }>()
  for (const item of asArray(asObject(json)?.data).map(asObject)) {
    const id = safeString(item?.cve)?.toUpperCase()
    if (!id) continue
    signals.set(id, {
      epss: item?.epss === undefined ? undefined : Number(item.epss),
      percentile: item?.percentile === undefined ? undefined : Number(item.percentile),
    })
  }
  return { signals, sources: [sourceRef] }
}

function osvCard(vuln: Record<string, unknown>, pkg: PackageSpec | undefined, fetchedAt: number, sourceRef: KnowledgeSource): VulnIntelCard | undefined {
  const id = safeString(vuln.id)
  if (!id) return undefined
  const aliases = asArray(vuln.aliases)
    .map((item) => safeString(item))
    .filter((item): item is string => Boolean(item))
  const refs = asArray(vuln.references)
    .map(asObject)
    .map((item) => safeString(item?.url))
    .filter((item): item is string => Boolean(item))
    .slice(0, 20)
  return {
    kind: "vuln_intel",
    id,
    aliases,
    title: safeString(vuln.summary) ?? id,
    summary: safeString(vuln.details) ?? safeString(vuln.summary),
    affected: pkg ? [{ ecosystem: pkg.ecosystem, package: pkg.name, version_range: undefined }] : [],
    severity: { source: "osv" },
    exploitation: {
      public_exploit_signal: refs.some((url) => /exploit-db|metasploit|packetstorm|github\.com/i.test(url)),
    },
    applicability: {
      matched_component: pkg?.name,
      matched_version: pkg?.version,
      state: pkg?.version ? "possible" : "unknown",
      confidence: pkg?.version ? "medium" : "low",
      reason: pkg?.version
        ? "OSV matched the package ecosystem/name/version; confirm reachability before reporting."
        : "OSV matched an advisory, but applicability needs package/version proof.",
      version_match: pkg?.version ? "unknown" : undefined,
      verification_steps: ["Check whether the vulnerable package is reachable in the executed code path.", "Capture SCA/tool output plus code reachability before promotion."],
    },
    references: refs,
    safe_next_actions: [
      "Check whether the vulnerable package is reachable in the executed code path.",
      "Prefer SCA/tool output plus code reachability before promotion.",
    ],
    fetched_at: fetchedAt,
    stale_after: fetchedAt + DAY,
    sources: [sourceRef],
  }
}

async function osvLookup(deps: Required<BrokerDeps>, query: string, limit: number) {
  const pkg = parsePackageSpec(query)
  const ids = cveIDs(query)
  if (!pkg && ids.length === 0) return { cards: [] as VulnIntelCard[], sources: [] as KnowledgeSource[] }
  const url = "https://api.osv.dev/v1/query"
  const body = pkg
    ? { version: pkg.version, package: { ecosystem: pkg.ecosystem, name: pkg.name } }
    : { id: ids[0] }
  const fetchedAt = deps.now()
  const { json, source: sourceRef } = await fetchJSON(deps, url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
  const cards = asArray(asObject(json)?.vulns)
    .map(asObject)
    .map((item) => item && osvCard(item, pkg, fetchedAt, sourceRef))
    .filter((item): item is VulnIntelCard => Boolean(item))
    .slice(0, limit)
  return { cards, sources: [sourceRef] }
}

async function ghsaLookup(deps: Required<BrokerDeps>, query: string, limit: number) {
  const ids = cveIDs(query)
  if (ids.length === 0) return { cards: [] as VulnIntelCard[], sources: [] as KnowledgeSource[] }
  const url = requestURL("https://api.github.com/advisories", { cve_id: ids[0], per_page: Math.min(limit, 50) })
  const fetchedAt = deps.now()
  const { json, source: sourceRef } = await fetchJSON(deps, url, {
    headers: { "X-GitHub-Api-Version": "2022-11-28" },
  })
  const cards = asArray(json)
    .map(asObject)
    .map((item): VulnIntelCard | undefined => {
      const ghsa = safeString(item?.ghsa_id)
      const cve = safeString(item?.cve_id)
      const id = cve ?? ghsa
      if (!id) return undefined
      const refs = asArray(item?.references)
        .map((ref) => safeString(ref))
        .filter((ref): ref is string => Boolean(ref))
      return {
        kind: "vuln_intel",
        id,
        aliases: compact([ghsa, cve]).filter((alias) => alias !== id),
        title: safeString(item?.summary) ?? id,
        summary: safeString(item?.description),
        affected: asArray(item?.vulnerabilities)
          .map(asObject)
          .map((vuln) => {
            const pkg = asObject(vuln?.package)
            const patched = asObject(vuln?.first_patched_version)
            return {
              ecosystem: safeString(pkg?.ecosystem),
              package: safeString(pkg?.name),
              version_range: safeString(vuln?.vulnerable_version_range),
              patched_versions: compact([safeString(patched?.identifier)]),
            }
          }),
        severity: {
          level: safeString(item?.severity),
          cvss_v3: number(asObject(item?.cvss)?.score),
          source: "github_advisory",
        },
        exploitation: {},
        applicability: {
          state: "unknown",
          confidence: "unknown",
          reason: "GitHub advisory intelligence only. Applicability requires package/version and reachability proof.",
          version_match: "unknown",
          verification_steps: ["Compare vulnerable ranges with lockfile/package manager output before promotion."],
        },
        references: refs,
        safe_next_actions: ["Compare vulnerable ranges with lockfile/package manager output before promotion."],
        fetched_at: fetchedAt,
        stale_after: fetchedAt + DAY,
        sources: [sourceRef],
      }
    })
    .filter((item): item is VulnIntelCard => Boolean(item))
  return { cards, sources: [sourceRef] }
}

function mergeVulnCards(cards: VulnIntelCard[], now: number): VulnIntelCard[] {
  const byID = new Map<string, VulnIntelCard>()
  const aliasToID = new Map<string, string>()
  for (const card of cards) {
    const ids = [card.id, ...card.aliases].map((id) => id.toUpperCase())
    const existingID = ids.map((id) => aliasToID.get(id)).find(Boolean)
    const key = existingID ?? card.id
    const existing = byID.get(key)
    if (!existing) {
      byID.set(key, { ...card, aliases: uniq(card.aliases) })
      for (const id of ids) aliasToID.set(id, key)
      continue
    }
    existing.aliases = uniq([...existing.aliases, card.id, ...card.aliases].filter((id) => id !== existing.id))
    existing.summary ||= card.summary
    existing.title ||= card.title
    existing.affected = [...existing.affected, ...card.affected]
    existing.references = uniq([...existing.references, ...card.references]).slice(0, 30)
    existing.sources = [...existing.sources, ...card.sources]
    existing.safe_next_actions = uniq([...existing.safe_next_actions, ...card.safe_next_actions])
    existing.exploitation = { ...existing.exploitation, ...card.exploitation }
    if ((existing.applicability.state ?? "unknown") === "unknown" && card.applicability.state && card.applicability.state !== "unknown") {
      existing.applicability = card.applicability
    }
    existing.severity = {
      ...existing.severity,
      cvss_v4: existing.severity.cvss_v4 ?? card.severity.cvss_v4,
      cvss_v3: existing.severity.cvss_v3 ?? card.severity.cvss_v3,
      level: existing.severity.level ?? card.severity.level,
      source: existing.severity.source ?? card.severity.source,
    }
    existing.stale_after = Math.min(existing.stale_after, card.stale_after || now + DAY)
  }
  return [...byID.values()]
}

function applyExploitSignals(cards: VulnIntelCard[], kev: Map<string, Record<string, unknown>>, epss: Map<string, { epss?: number; percentile?: number }>) {
  for (const card of cards) {
    const ids = [card.id, ...card.aliases].map((id) => id.toUpperCase())
    const kevMatch = ids.map((id) => kev.get(id)).find(Boolean)
    if (kevMatch) {
      card.exploitation.kev = true
      card.exploitation.kev_due_date = safeString(kevMatch.dueDate)
      card.safe_next_actions.unshift("Treat KEV=true as a high-priority validation signal, but still prove applicability before reporting.")
    } else {
      card.exploitation.kev ??= false
    }
    const epssMatch = ids.map((id) => epss.get(id)).find(Boolean)
    if (epssMatch) {
      card.exploitation.epss_probability = epssMatch.epss
      card.exploitation.epss = epssMatch.epss
      card.exploitation.epss_percentile = epssMatch.percentile
    }
  }
}

function stateRank(card: VulnIntelCard) {
  const state = card.applicability.state ?? "unknown"
  const ranks: Record<string, number> = {
    applicable: 0,
    conditional: 1,
    possible: 2,
    unknown: 3,
    not_applicable: 4,
  }
  return ranks[state] ?? 3
}

function severityRank(card: VulnIntelCard) {
  const level = card.severity.level?.toLowerCase()
  if (level === "critical") return 0
  if (level === "high") return 1
  if (level === "medium") return 2
  if (level === "low") return 3
  return 4
}

function prioritizeVulnCards(cards: VulnIntelCard[], request: KnowledgeRequest) {
  return [...cards].sort((a, b) => {
    const state = stateRank(a) - stateRank(b)
    if (request.action === "match_component" && state !== 0) return state
    const kev = Number(Boolean(b.exploitation.kev)) - Number(Boolean(a.exploitation.kev))
    if (kev !== 0) return kev
    const epss = (b.exploitation.epss_probability ?? b.exploitation.epss ?? 0) - (a.exploitation.epss_probability ?? a.exploitation.epss ?? 0)
    if (epss !== 0) return epss
    const severity = severityRank(a) - severityRank(b)
    if (severity !== 0) return severity
    return a.id.localeCompare(b.id)
  })
}

async function vulnIntel(request: KnowledgeRequest, deps: Required<BrokerDeps>): Promise<{ cards: VulnIntelCard[]; sources: KnowledgeSource[]; errors: string[] }> {
  if (request.mode === "offline") {
    return {
      cards: [],
      sources: [source({ name: "offline", source_type: "cache", trust: "medium", degraded: true, error: "offline mode has no live source access" })],
      errors: ["offline mode has no live vulnerability intelligence unless cache is already integrated"],
    }
  }
  const safe = opsecSafeQuery(request)
  if (safe.blocked) {
    return {
      cards: [],
      sources: [source({ name: "opsec_strict", source_type: "structured", trust: "high", degraded: true, error: safe.blocked })],
      errors: [safe.blocked],
    }
  }
  const query = safe.query || request.query
  const component = request.action === "match_component" || request.action === "enrich_observed" ? normalizeComponent(query) : undefined
  const [nvd, osv, ghsa] = await Promise.all([
    nvdLookup(deps, query, request.limit, component),
    osvLookup(deps, query, request.limit),
    ghsaLookup(deps, query, request.limit),
  ])
  const merged = mergeVulnCards([...nvd.cards, ...osv.cards, ...ghsa.cards], deps.now())
  const ids = uniq(merged.flatMap((card) => [card.id, ...card.aliases]).filter((id) => /^CVE-/i.test(id)).map((id) => id.toUpperCase()))
  const [kev, epss] = await Promise.all([kevSignals(deps, ids), epssSignals(deps, ids)])
  applyExploitSignals(merged, kev.signals, epss.signals)
  const prioritized = prioritizeVulnCards(merged, request).slice(0, request.limit)
  const sources = [...nvd.sources, ...osv.sources, ...ghsa.sources, ...kev.sources, ...epss.sources]
  const errors = sources.map((item) => item.error).filter((item): item is string => Boolean(item))
  if ((request.action === "match_component" || request.action === "enrich_observed") && !component) {
    errors.push("component matcher could not normalize the requested component; falling back to keyword vulnerability intelligence")
  }
  return { cards: prioritized, sources, errors }
}

const TRADECRAFT: Record<string, { claims: string[]; actions: string[]; sources: KnowledgeSource[] }> = {
  idor: {
    claims: ["Numeric object identifiers and user-scoped resources are IDOR/BOLA testing targets only after identity comparison proves authorization impact."],
    actions: ["Use two identities and replay the same object route across both sessions.", "Record request/response pairs before promotion."],
    sources: [
      source({ name: "OWASP API Security API1", url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/", source_type: "methodology", trust: "high" }),
    ],
  },
  bola: {
    claims: ["BOLA validation requires object access comparison across identities, not a single 200 response."],
    actions: ["Collect two authorized object IDs and test cross-access with bounded requests."],
    sources: [
      source({ name: "OWASP API Security API1", url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/", source_type: "methodology", trust: "high" }),
    ],
  },
  jwt: {
    claims: ["JWT testing should inspect signing algorithm, key confusion, claim trust, expiry, and server-side authorization checks."],
    actions: ["Decode tokens locally first.", "Do not report weak JWT until a replay proves acceptance of a forged or improperly scoped token."],
    sources: [
      source({ name: "OWASP WSTG Authentication", url: "https://owasp.org/www-project-web-security-testing-guide/", source_type: "methodology", trust: "high" }),
    ],
  },
  cors: {
    claims: ["Permissive CORS is impact-bearing primarily when credentials or sensitive readable responses are involved."],
    actions: ["Replay with a controlled Origin and check ACAO/ACAC plus readable sensitive response impact."],
    sources: [
      source({ name: "OWASP WSTG Client-side Testing", url: "https://owasp.org/www-project-web-security-testing-guide/", source_type: "methodology", trust: "high" }),
    ],
  },
  xss: {
    claims: ["XSS candidates need browser-context execution or safe DOM proof before reportable promotion."],
    actions: ["Use a marker payload first, then browser replay for DOM execution proof if reflected or stored."],
    sources: [
      source({ name: "PortSwigger Web Security Academy", url: "https://portswigger.net/web-security/cross-site-scripting", source_type: "tradecraft", trust: "high" }),
    ],
  },
  sqli: {
    claims: ["SQL injection validation should distinguish error, boolean, and time signals, then capture replayable proof."],
    actions: ["Use bounded payloads and avoid destructive statements.", "Record status/body/timing deltas."],
    sources: [
      source({ name: "PortSwigger Web Security Academy", url: "https://portswigger.net/web-security/sql-injection", source_type: "tradecraft", trust: "high" }),
    ],
  },
  ssrf: {
    claims: ["SSRF proof should use controlled callback/canary targets and must respect operation scope."],
    actions: ["Prefer metadata-safe probes only with explicit authorization.", "Record callback evidence and request replay."],
    sources: [
      source({ name: "OWASP WSTG SSRF", url: "https://owasp.org/www-project-web-security-testing-guide/", source_type: "methodology", trust: "high" }),
    ],
  },
}

function methodologyCards(request: KnowledgeRequest, now: number): ResearchCard[] {
  const query = request.query.toLowerCase()
  const matches = Methodology.ids.flatMap((framework) =>
    Methodology.search(framework, query).slice(0, 8).map(({ phase, technique }) => ({
      framework,
      phase,
      technique,
    })),
  )
  const claims: KnowledgeClaim[] = matches.map((match) => ({
    claim: `[${match.technique.id}] ${match.technique.name}: ${match.technique.description}`,
    confidence: 0.85,
    freshness: "local methodology pack",
    applies_to_observed_target: (request.observed_refs?.length ? "unknown" : false) as "unknown" | false,
  }))
  return [
    {
      kind: "research",
      topic: request.query,
      source_pack: request.intent === "vuln_intel" ? "methodology" : request.intent,
      sources: [
        source({ name: "numasec local methodology", source_type: "methodology", trust: "high", fetched_at: now, stale_after: now + MONTH }),
      ],
      claims,
      recommended_next_actions:
        claims.length > 0
          ? ["Use the matching methodology IDs to choose bounded probes, then require evidence/replay before reporting."]
          : ["No local methodology match found; narrow the query or use live field research when opsec allows."],
      unsafe_or_out_of_scope_actions: ["Do not promote methodology guidance as a finding without target-specific proof."],
      applies_to_observed_target: (request.observed_refs?.length ? "unknown" : false) as "unknown" | false,
      fetched_at: now,
      stale_after: now + MONTH,
    },
  ]
}

function tradecraftCards(request: KnowledgeRequest, now: number): ResearchCard[] {
  const lower = request.query.toLowerCase()
  const keys = Object.keys(TRADECRAFT).filter((key) => lower.includes(key))
  const selected = keys.length ? keys : ["idor", "xss", "sqli"].filter((key) => lower.includes(key))
  const cards = (selected.length ? selected : [lower.split(/\s+/)[0] ?? "general"]).map((key) => {
    const data = TRADECRAFT[key]
    const claims: KnowledgeClaim[] = (data?.claims ?? ["No curated local tradecraft pack matched this exact topic."]).map((claim) => ({
      claim,
      confidence: data ? 0.8 : 0.35,
      freshness: data ? "curated source pack" : "degraded local fallback",
      source_url: data?.sources[0]?.url,
      applies_to_observed_target: (request.observed_refs?.length ? "unknown" : false) as "unknown" | false,
    }))
    return {
      kind: "research" as const,
      topic: key,
      source_pack: (request.intent === "field_research" ? "field_research" : "tradecraft") as "field_research" | "tradecraft",
      sources: data?.sources.map((item) => ({ ...item, fetched_at: now, stale_after: now + MONTH })) ?? [
        source({ name: "numasec curated tradecraft", source_type: "tradecraft", trust: "medium", fetched_at: now, stale_after: now + MONTH, degraded: true }),
      ],
      claims,
      recommended_next_actions: data?.actions ?? ["Use methodology lookup or a specific source pack query before acting."],
      unsafe_or_out_of_scope_actions: ["Do not execute exploit steps from tradecraft context without scope and a replay plan."],
      applies_to_observed_target: (request.observed_refs?.length ? "unknown" : false) as "unknown" | false,
      fetched_at: now,
      stale_after: now + MONTH,
    }
  })
  return cards
}

async function listFilesBounded(deps: Required<BrokerDeps>, roots: string[], limit = 2000) {
  const out: string[] = []
  const queue = [...roots]
  while (queue.length && out.length < limit) {
    const current = queue.shift()!
    try {
      await access(current)
      const children = await deps.listDir(current)
      for (const child of children) {
        if (out.length >= limit) break
        if (/\.(ya?ml|rb|py|txt|json|md)$/i.test(child)) out.push(child)
        if (!path.extname(child)) queue.push(child)
      }
    } catch {}
  }
  return out
}

async function exploitSignalCard(request: KnowledgeRequest, deps: Required<BrokerDeps>): Promise<ResearchCard> {
  const now = deps.now()
  const claims: KnowledgeClaim[] = []
  const sources: KnowledgeSource[] = []
  const query = request.query.trim()
  const searchsploit = deps.which("searchsploit")
  if (searchsploit) {
    const result = await deps.run(["searchsploit", "-j", query], 10_000).catch((error) => ({
      argv: ["searchsploit", "-j", query],
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error),
      exitCode: 1,
    }))
    const parsed = (() => {
      try {
        return JSON.parse(result.stdout)
      } catch {
        return undefined
      }
    })()
    const count = asArray(asObject(parsed)?.RESULTS_EXPLOIT).length
    claims.push({
      claim: `Local SearchSploit returned ${count} exploit-db signal(s) for "${query}". Treat as exploit signal, not proof.`,
      confidence: result.exitCode === 0 ? 0.75 : 0.35,
      applies_to_observed_target: "unknown",
    })
    sources.push(source({ name: "searchsploit", source_type: "local_tool", trust: "medium", fetched_at: now, stale_after: now + WEEK, degraded: result.exitCode !== 0, error: result.stderr || undefined }))
  }
  const nucleiRoots = compact([process.env.NUCLEI_TEMPLATES_PATH, path.join(os.homedir(), "nuclei-templates"), path.join(os.homedir(), ".local", "nuclei-templates")])
  const files = await listFilesBounded(deps, nucleiRoots)
  const nucleiMatches = files.filter((file) => file.toLowerCase().includes(query.toLowerCase().replace(/[^a-z0-9-]+/g, "-"))).slice(0, 10)
  if (files.length || nucleiMatches.length) {
    claims.push({
      claim: `Local nuclei templates produced ${nucleiMatches.length} filename signal(s) for "${query}". Use templates only as probe guidance.`,
      confidence: nucleiMatches.length ? 0.65 : 0.25,
      applies_to_observed_target: "unknown",
    })
    sources.push(source({ name: "local nuclei templates", source_type: "local_tool", trust: "medium", fetched_at: now, stale_after: now + WEEK, degraded: nucleiMatches.length === 0 }))
  }
  if (claims.length === 0) {
    claims.push({
      claim: "No local exploit-signal adapters were available. Install searchsploit, Metasploit, or nuclei templates for local signal enrichment.",
      confidence: 0.2,
      applies_to_observed_target: false,
    })
    sources.push(source({ name: "local exploit adapters", source_type: "local_tool", trust: "medium", fetched_at: now, stale_after: now + WEEK, degraded: true }))
  }
  return {
    kind: "research",
    topic: query,
    source_pack: "exploit_signal",
    sources,
    claims,
    recommended_next_actions: ["Use exploit signals to prioritize safe verification, not to promote findings directly."],
    unsafe_or_out_of_scope_actions: ["Do not run public exploit code unless scope and ROE explicitly allow it."],
    applies_to_observed_target: (request.observed_refs?.length ? "unknown" : false) as "unknown" | false,
    fetched_at: now,
    stale_after: now + WEEK,
  }
}

function toolName(query: string) {
  const token = query.trim().split(/\s+/)[0] ?? ""
  return /^[a-zA-Z0-9._+-]{1,64}$/.test(token) ? token : undefined
}

async function toolDocsCard(request: KnowledgeRequest, deps: Required<BrokerDeps>): Promise<ResearchCard> {
  const now = deps.now()
  const name = toolName(request.query)
  const claims: KnowledgeClaim[] = []
  const sources: KnowledgeSource[] = []
  if (!name) {
    claims.push({ claim: "Tool docs query did not contain a safe executable name.", confidence: 0.2, applies_to_observed_target: false })
  } else if (!deps.which(name)) {
    claims.push({ claim: `Tool "${name}" is not installed on PATH.`, confidence: 0.9, applies_to_observed_target: false })
    sources.push(source({ name, source_type: "local_tool", trust: "high", fetched_at: now, stale_after: now + WEEK, degraded: true }))
  } else {
    const version = await deps.run([name, "--version"], 5_000).catch(() => undefined)
    const help = await deps.run([name, "--help"], 5_000).catch(() => undefined)
    const versionLine = (version?.stdout || version?.stderr || "").split(/\r?\n/)[0]?.slice(0, 160)
    const helpText = (help?.stdout || help?.stderr || "").slice(0, 2000)
    claims.push({
      claim: `Installed ${name}${versionLine ? ` reports: ${versionLine}` : " is present"}.`,
      confidence: 0.9,
      applies_to_observed_target: false,
    })
    if (helpText) {
      claims.push({
        claim: `${name} --help was captured locally; prefer these installed flags over model memory.`,
        confidence: 0.85,
        applies_to_observed_target: false,
      })
    }
    sources.push(source({ name, source_type: "local_tool", trust: "high", fetched_at: now, stale_after: now + WEEK }))
  }
  return {
    kind: "research",
    topic: request.query,
    source_pack: "tool_docs",
    sources,
    claims,
    recommended_next_actions: ["Use the installed tool version/help output when constructing commands."],
    unsafe_or_out_of_scope_actions: ["Do not assume flags from memory when local help disagrees."],
    applies_to_observed_target: false,
    fetched_at: now,
    stale_after: now + WEEK,
  }
}

function compactCard(card: KnowledgeCard): NonNullable<KnowledgeResult["cards_compact"]>[number] {
  if (card.kind === "vuln_intel") {
    return {
      kind: card.kind,
      id: card.id,
      title: card.title,
      applicability_state: card.applicability.state ?? "unknown",
      confidence: card.applicability.confidence,
      kev: card.exploitation.kev,
      epss_probability: card.exploitation.epss_probability ?? card.exploitation.epss,
      epss_percentile: card.exploitation.epss_percentile,
      safe_next_actions: card.safe_next_actions.slice(0, 4),
    }
  }
  return {
    kind: card.kind,
    topic: card.topic,
    title: card.topic,
    confidence: card.claims[0]?.confidence === undefined ? undefined : String(card.claims[0].confidence),
    safe_next_actions: card.recommended_next_actions.slice(0, 4),
  }
}

function operatorSummary(input: KnowledgeRequest, cards: KnowledgeCard[], errors: string[]) {
  const header = `${input.intent}/${input.action} "${input.query}": ${cards.length} card${cards.length === 1 ? "" : "s"}`
  if (cards.length === 0) return `${header}. ${errors[0] ?? "No matching knowledge cards returned."}`
  const vulnCards = cards.filter((card): card is VulnIntelCard => card.kind === "vuln_intel")
  if (vulnCards.length > 0) {
    const counts = vulnCards.reduce<Record<string, number>>((acc, card) => {
      const state = card.applicability.state ?? "unknown"
      acc[state] = (acc[state] ?? 0) + 1
      return acc
    }, {})
    const top = vulnCards
      .slice(0, 5)
      .map((card) => {
        const epss = card.exploitation.epss_probability ?? card.exploitation.epss
        const signals = compact([
          `applicability=${card.applicability.state ?? "unknown"}`,
          card.exploitation.kev === true ? "KEV=true" : card.exploitation.kev === false ? "KEV=false" : undefined,
          epss === undefined ? undefined : `EPSS=${epss}`,
        ]).join(", ")
        return `${card.id} (${signals})`
      })
      .join("; ")
    return `${header}. States: ${Object.entries(counts)
      .map(([state, count]) => `${state}=${count}`)
      .join(", ")}. Top: ${top}. Intelligence only; require target evidence/replay before reporting.`
  }
  const topics = cards
    .filter((card): card is ResearchCard => card.kind === "research")
    .slice(0, 5)
    .map((card) => `${card.source_pack}:${card.topic}`)
    .join("; ")
  return `${header}. Topics: ${topics}. Guidance only; require target proof before action/reporting.`
}

export namespace KnowledgeBroker {
  export function normalize(input: {
    intent?: KnowledgeIntent
    action?: KnowledgeAction
    query: string
    observed_refs?: string[]
    mode?: KnowledgeMode
    limit?: number
    source?: "cve" | "web"
  }): KnowledgeRequest {
    const intent = input.intent ?? (input.source === "cve" ? "vuln_intel" : "field_research")
    const action = input.action ?? (input.source === "cve" ? "lookup" : "lookup")
    return {
      intent,
      action,
      query: input.query,
      observed_refs: input.observed_refs,
      mode: input.mode ?? "live",
      limit: Math.min(Math.max(input.limit ?? 10, 1), 50),
    }
  }

  export async function query(input: KnowledgeRequest, depsInput: BrokerDeps = {}): Promise<KnowledgeResult> {
    const deps = { ...defaultDeps, ...depsInput }
    const now = deps.now()
    const key = cacheKey(input)
    if (input.mode === "offline") {
      const cached = await deps.readCache(key).catch(() => undefined)
      if (cached) return fromCache(cached, input, now)
    }

    let cards: KnowledgeCard[] = []
    let sources: KnowledgeSource[] = []
    let errors: string[] = []
    if (input.intent === "vuln_intel") {
      const result = await vulnIntel(input, deps)
      cards = result.cards
      sources = result.sources
      errors = result.errors
    } else if (input.intent === "methodology") {
      cards = methodologyCards(input, now)
      sources = cards.flatMap((card) => card.sources)
    } else if (input.intent === "tradecraft" || input.intent === "field_research") {
      cards = tradecraftCards(input, now)
      sources = cards.flatMap((card) => card.sources)
      if (input.intent === "field_research") {
        errors.push("field_research is curated/local by default; generic websearch remains optional and is not used without explicit legacy source=web")
      }
    } else if (input.intent === "exploit_signal") {
      const card = await exploitSignalCard(input, deps)
      cards = [card]
      sources = card.sources
    } else if (input.intent === "tool_docs") {
      const card = await toolDocsCard(input, deps)
      cards = [card]
      sources = card.sources
    }
    const degraded = cards.length === 0 || sources.some((item) => item.degraded) || errors.length > 0
    const result: KnowledgeResult = {
      request: input,
      cards,
      sources,
      degraded,
      errors,
      fetched_at: now,
      stale_after: cards.length ? Math.min(...cards.map((card) => card.stale_after), now + DAY) : now + DAY,
      summary: `${input.intent}/${input.action} "${input.query}" returned ${cards.length} card${cards.length === 1 ? "" : "s"}`,
      operator_summary: operatorSummary(input, cards, errors),
      cards_compact: cards.map(compactCard),
    }
    if (cards.length > 0 && input.mode !== "offline") {
      await deps.writeCache(key, result).catch(() => undefined)
    }
    if (cards.length === 0 && input.mode !== "offline") {
      const cached = await deps.readCache(key).catch(() => undefined)
      if (cached) {
        const cachedResult = fromCache(cached, input, now)
        return {
          ...cachedResult,
          degraded: result.degraded,
          errors: [...result.errors, "live knowledge sources returned no cards; using workspace cache"],
        }
      }
    }
    return result
  }
}
