export type NormalizedComponent = {
  raw: string
  name: string
  version?: string
  vendor?: string
  type: "service" | "package" | "cpe" | "unknown"
  cpe_candidates: string[]
  product_aliases: string[]
  confidence: "low" | "medium" | "high"
}

const PRODUCT_ALIASES: Record<string, { vendor?: string; aliases: string[]; cpes: string[] }> = {
  nginx: {
    vendor: "f5",
    aliases: ["nginx", "f5 nginx"],
    cpes: ["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"],
  },
  "apache httpd": {
    vendor: "apache",
    aliases: ["apache httpd", "httpd", "apache"],
    cpes: ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"],
  },
  openssh: {
    vendor: "openbsd",
    aliases: ["openssh", "openbsd openssh"],
    cpes: ["cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"],
  },
}

function cleanVersion(input?: string) {
  return input?.replace(/^v/i, "").replace(/[),;]+$/g, "")
}

function cpeParts(input: string) {
  if (!input.startsWith("cpe:2.3:")) return undefined
  const parts = input.split(":")
  if (parts.length < 6) return undefined
  return {
    part: parts[2],
    vendor: parts[3]?.replace(/_/g, " "),
    product: parts[4]?.replace(/_/g, " "),
    version: parts[5] && parts[5] !== "*" ? parts[5] : undefined,
  }
}

function aliasFor(name: string) {
  const lower = name.toLowerCase()
  if (lower === "apache" || lower === "httpd" || lower === "apache2") return "apache httpd"
  if (lower === "openssh" || lower === "ssh") return "openssh"
  if (lower === "nginx") return "nginx"
  return lower
}

export function normalizeComponent(query: string): NormalizedComponent | undefined {
  const raw = query.trim()
  if (!raw) return undefined

  const cpe = raw.match(/cpe:2\.3:[aho]:[^\s]+/i)?.[0]
  if (cpe) {
    const parsed = cpeParts(cpe)
    if (parsed?.product) {
      const name = aliasFor(parsed.product)
      const data = PRODUCT_ALIASES[name]
      return {
        raw,
        name,
        version: cleanVersion(parsed.version),
        vendor: data?.vendor ?? parsed.vendor,
        type: "cpe",
        cpe_candidates: [cpe, ...(data?.cpes ?? [])],
        product_aliases: data?.aliases ?? [name],
        confidence: parsed.version ? "high" : "medium",
      }
    }
  }

  const normalized = raw
    .replace(/^service:/i, "")
    .replace(/^component:/i, "")
    .replace(/^technology:/i, "")
    .replace(/[_/]+/g, " ")
    .trim()

  const patterns: Array<RegExp> = [
    /\b(nginx)\s+([0-9][0-9A-Za-z.+~:-]*)\b/i,
    /\b(nginx)\s*\/\s*([0-9][0-9A-Za-z.+~:-]*)\b/i,
    /\b(open(?:bsd\s+)?ssh)\s+([0-9][0-9A-Za-z.+~:-]*)\b/i,
    /\b(open(?:bsd\s+)?ssh)\s*[_/]\s*([0-9][0-9A-Za-z.+~:-]*)\b/i,
    /\b(apache(?:\s+httpd)?|httpd)\s+([0-9][0-9A-Za-z.+~:-]*)\b/i,
    /\b(apache(?:\s+httpd)?|httpd)\s*\/\s*([0-9][0-9A-Za-z.+~:-]*)\b/i,
    /\b([a-z][a-z0-9.+-]{1,64})\s+([0-9][0-9A-Za-z.+~:-]*)\b/i,
  ]
  for (const pattern of patterns) {
    const match = normalized.match(pattern)
    if (!match) continue
    const name = aliasFor(match[1]!.toLowerCase())
    const data = PRODUCT_ALIASES[name]
    return {
      raw,
      name,
      version: cleanVersion(match[2]),
      vendor: data?.vendor,
      type: data ? "service" : "unknown",
      cpe_candidates: data?.cpes ?? [],
      product_aliases: data?.aliases ?? [name],
      confidence: data ? "high" : "medium",
    }
  }

  const token = normalized.match(/\b(nginx|open(?:bsd\s+)?ssh|apache(?:\s+httpd)?|httpd)\b/i)
  if (token) {
    const name = aliasFor(token[1]!.toLowerCase())
    const data = PRODUCT_ALIASES[name]
    return {
      raw,
      name,
      vendor: data?.vendor,
      type: data ? "service" : "unknown",
      cpe_candidates: data?.cpes ?? [],
      product_aliases: data?.aliases ?? [name],
      confidence: "medium",
    }
  }

  return undefined
}

export function componentSearchTerms(component: NormalizedComponent): string[] {
  return [...new Set([component.name, ...component.product_aliases])].filter(Boolean)
}
