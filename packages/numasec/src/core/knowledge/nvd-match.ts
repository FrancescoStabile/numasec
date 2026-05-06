import type { NormalizedComponent } from "./component"

export type NvdVersionRange = {
  criteria: string
  vulnerable: boolean
  versionStartIncluding?: string
  versionStartExcluding?: string
  versionEndIncluding?: string
  versionEndExcluding?: string
  matchCriteriaId?: string
}

export type NvdApplicability = {
  state: "applicable" | "conditional" | "possible" | "not_applicable" | "unknown"
  confidence: "low" | "medium" | "high" | "unknown"
  reason: string
  matched_criteria?: string
  affected_range?: string
  version_match?: boolean | "unknown"
  preconditions: string[]
  verification_steps: string[]
}

function asObject(input: unknown): Record<string, unknown> | undefined {
  return input && typeof input === "object" && !Array.isArray(input) ? (input as Record<string, unknown>) : undefined
}

function asArray(input: unknown): unknown[] {
  return Array.isArray(input) ? input : []
}

function safeString(input: unknown): string | undefined {
  return typeof input === "string" && input.trim() ? input.trim() : undefined
}

export function collectNvdRanges(nodes: unknown): NvdVersionRange[] {
  const out: NvdVersionRange[] = []
  const walk = (node: unknown) => {
    const obj = asObject(node)
    if (!obj) return
    for (const match of asArray(obj.cpeMatch ?? obj.cpe_match)) {
      const item = asObject(match)
      const criteria = safeString(item?.criteria ?? item?.cpe23Uri)
      if (!criteria) continue
      out.push({
        criteria,
        vulnerable: item?.vulnerable !== false,
        versionStartIncluding: safeString(item?.versionStartIncluding),
        versionStartExcluding: safeString(item?.versionStartExcluding),
        versionEndIncluding: safeString(item?.versionEndIncluding),
        versionEndExcluding: safeString(item?.versionEndExcluding),
        matchCriteriaId: safeString(item?.matchCriteriaId),
      })
    }
    for (const child of asArray(obj.children)) walk(child)
  }
  for (const node of asArray(nodes)) walk(node)
  return out
}

function cpeProduct(criteria: string) {
  const parts = criteria.split(":")
  if (parts.length < 6) return undefined
  return {
    vendor: parts[3]?.toLowerCase().replace(/_/g, " "),
    product: parts[4]?.toLowerCase().replace(/_/g, " "),
    version: parts[5],
  }
}

function normalizeVersion(input: string) {
  return input
    .toLowerCase()
    .replace(/^v/, "")
    .replace(/[-+~_]/g, ".")
    .split(".")
    .map((part) => part.replace(/[^0-9a-z]/g, ""))
    .filter(Boolean)
}

function compareVersion(a: string, b: string) {
  const left = normalizeVersion(a)
  const right = normalizeVersion(b)
  const max = Math.max(left.length, right.length)
  for (let i = 0; i < max; i++) {
    const l = left[i] ?? "0"
    const r = right[i] ?? "0"
    const ln = /^\d+$/.test(l) ? Number(l) : undefined
    const rn = /^\d+$/.test(r) ? Number(r) : undefined
    const cmp = ln !== undefined && rn !== undefined ? ln - rn : l.localeCompare(r)
    if (cmp < 0) return -1
    if (cmp > 0) return 1
  }
  return 0
}

function inRange(version: string, range: NvdVersionRange) {
  if (range.versionStartIncluding && compareVersion(version, range.versionStartIncluding) < 0) return false
  if (range.versionStartExcluding && compareVersion(version, range.versionStartExcluding) <= 0) return false
  if (range.versionEndIncluding && compareVersion(version, range.versionEndIncluding) > 0) return false
  if (range.versionEndExcluding && compareVersion(version, range.versionEndExcluding) >= 0) return false
  const criteriaVersion = cpeProduct(range.criteria)?.version
  if (criteriaVersion && criteriaVersion !== "*" && criteriaVersion !== "-" && compareVersion(version, criteriaVersion) !== 0) return false
  return true
}

function hasEvaluableVersionRange(range: NvdVersionRange) {
  if (range.versionStartIncluding || range.versionStartExcluding || range.versionEndIncluding || range.versionEndExcluding) return true
  const criteriaVersion = cpeProduct(range.criteria)?.version
  return Boolean(criteriaVersion && criteriaVersion !== "*" && criteriaVersion !== "-")
}

function rangeLabel(range: NvdVersionRange) {
  const parts: string[] = []
  if (range.versionStartIncluding) parts.push(`>= ${range.versionStartIncluding}`)
  if (range.versionStartExcluding) parts.push(`> ${range.versionStartExcluding}`)
  if (range.versionEndIncluding) parts.push(`<= ${range.versionEndIncluding}`)
  if (range.versionEndExcluding) parts.push(`< ${range.versionEndExcluding}`)
  const criteriaVersion = cpeProduct(range.criteria)?.version
  if (parts.length === 0 && criteriaVersion && criteriaVersion !== "*" && criteriaVersion !== "-") parts.push(`= ${criteriaVersion}`)
  return parts.join(" and ") || range.criteria
}

function summaryMentionsComponent(component: NormalizedComponent, summary?: string) {
  if (!summary || component.type === "unknown") return false
  const lower = summary.toLowerCase()
  return [component.name, ...component.product_aliases].some((alias) => {
    const normalized = alias.toLowerCase().replace(/\s+/g, " ")
    return normalized.length > 2 && lower.includes(normalized)
  })
}

function productMatches(component: NormalizedComponent, range: NvdVersionRange) {
  const parsed = cpeProduct(range.criteria)
  if (!parsed?.product) return false
  const product = parsed.product
  const aliases = [component.name, ...component.product_aliases].map((item) => item.toLowerCase())
  if (aliases.some((alias) => product === alias || product.includes(alias.replace(/\s+/g, "_")) || alias.includes(product))) return true
  return component.cpe_candidates.some((candidate) => {
    const candidateProduct = cpeProduct(candidate)
    return candidateProduct?.product === product && (!candidateProduct.vendor || candidateProduct.vendor === parsed.vendor)
  })
}

function nginxPreconditions(summary?: string) {
  const lower = summary?.toLowerCase() ?? ""
  if (lower.includes("resolver") || lower.includes("dns")) {
    return ["nginx resolver directive/configuration is in use", "DNS response forgery or resolver-path control is plausible in the operation scope"]
  }
  if (lower.includes("http/3") || lower.includes("quic")) {
    return ["nginx HTTP/3/QUIC module is enabled in the observed build/configuration"]
  }
  return []
}

export function evaluateNvdApplicability(input: {
  component?: NormalizedComponent
  ranges: NvdVersionRange[]
  summary?: string
}): NvdApplicability {
  const { component, ranges, summary } = input
  if (!component) {
    return {
      state: "unknown",
      confidence: "unknown",
      reason: "No normalized component was supplied; applicability requires observed component/version proof.",
      version_match: "unknown",
      preconditions: [],
      verification_steps: ["Identify the exact product, version, package source, and patch/backport status."],
    }
  }
  const productRanges = ranges.filter((range) => range.vulnerable && productMatches(component, range))
  if (productRanges.length === 0) {
    if (ranges.length === 0) {
      return {
        state: "unknown",
        confidence: "unknown",
        reason: `NVD did not provide structured affected CPE/version data for ${component.name}${component.version ? ` ${component.version}` : ""}. Applicability cannot be excluded from NVD alone.`,
        version_match: "unknown",
        preconditions: nginxPreconditions(summary),
        verification_steps: ["Use vendor/package advisory data or safe target fingerprinting before concluding applicability."],
      }
    }
    if (summaryMentionsComponent(component, summary)) {
      return {
        state: "possible",
        confidence: "low",
        reason: `The advisory text mentions ${component.name}, but NVD affected CPE/version data does not contain a product/range match. Treat as possible intelligence, not exclusion.`,
        version_match: "unknown",
        preconditions: nginxPreconditions(summary),
        verification_steps: ["Check vendor advisory or package manager security metadata before excluding this CVE.", "Capture target-specific evidence before reporting."],
      }
    }
    return {
      state: "not_applicable",
      confidence: component.confidence === "high" ? "medium" : "low",
      reason: `NVD affected CPE data did not match observed component ${component.name}${component.version ? ` ${component.version}` : ""}.`,
      version_match: false,
      preconditions: [],
      verification_steps: ["Keep the advisory as background intelligence only unless another source matches the observed component."],
    }
  }
  if (!component.version) {
    return {
      state: "possible",
      confidence: "low",
      reason: `NVD affected CPE data matches ${component.name}, but no observed version was supplied.`,
      matched_criteria: productRanges[0]?.criteria,
      affected_range: rangeLabel(productRanges[0]!),
      version_match: "unknown",
      preconditions: nginxPreconditions(summary),
      verification_steps: ["Fingerprint the exact component version and package source before promotion."],
    }
  }
  const evaluableRanges = productRanges.filter(hasEvaluableVersionRange)
  if (evaluableRanges.length === 0) {
    return {
      state: "possible",
      confidence: "low",
      reason: `NVD affected CPE data matches ${component.name}, but it does not provide an evaluable affected version range. Do not treat this as not applicable.`,
      matched_criteria: productRanges[0]?.criteria,
      affected_range: rangeLabel(productRanges[0]!),
      version_match: "unknown",
      preconditions: nginxPreconditions(summary),
      verification_steps: ["Check vendor advisory or package manager security metadata for fixed/affected versions.", "Capture target-specific evidence before reporting."],
    }
  }
  const matching = evaluableRanges.find((range) => inRange(component.version!, range))
  if (!matching) {
    return {
      state: "not_applicable",
      confidence: "medium",
      reason: `${component.name} ${component.version} did not fall inside NVD affected version ranges.`,
      matched_criteria: evaluableRanges[0]?.criteria,
      affected_range: evaluableRanges.map(rangeLabel).slice(0, 3).join("; "),
      version_match: false,
      preconditions: [],
      verification_steps: ["Do not report this CVE for the observed version unless vendor/backport evidence contradicts NVD ranges."],
    }
  }
  const preconditions = nginxPreconditions(summary)
  const state = preconditions.length ? "conditional" : "applicable"
  return {
    state,
    confidence: state === "applicable" ? "high" : "medium",
    reason:
      state === "conditional"
        ? `${component.name} ${component.version} is inside the NVD affected range, but exploitability depends on target-specific preconditions.`
        : `${component.name} ${component.version} is inside the NVD affected range.`,
    matched_criteria: matching.criteria,
    affected_range: rangeLabel(matching),
    version_match: true,
    preconditions,
    verification_steps: [
      "Confirm exact package/build and distro backport status before reporting.",
      ...preconditions.map((item) => `Check whether ${item}.`),
      "Capture bounded evidence/replay before promoting any finding.",
    ],
  }
}
