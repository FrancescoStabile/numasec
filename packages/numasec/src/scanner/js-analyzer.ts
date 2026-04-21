/**
 * Scanner: JS analyzer
 *
 * Fetches and analyzes JavaScript files for endpoints, secrets, API keys,
 * sensitive routes, SPA routes, and chatbot indicators.
 */

export interface JsAnalysisResult {
  endpoints: string[]
  secrets: SecretMatch[]
  apiKeys: string[]
  spaRoutes: string[]
  chatbotIndicators: string[]
  jsFiles: string[]
  elapsed: number
}

export interface SecretMatch {
  type: string
  value: string
  file: string
  context: string
}

const SECRET_PATTERNS: [string, RegExp][] = [
  ["AWS Access Key", /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g],
  ["AWS Secret Key", /(?:aws_secret_access_key|secret_access_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi],
  ["Google API Key", /AIza[0-9A-Za-z_-]{35}/g],
  ["Slack Token", /xox[bpors]-[0-9a-zA-Z-]{10,}/g],
  ["GitHub Token", /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g],
  ["JWT", /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g],
  ["Private Key", /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g],
  ["Bearer Token", /(?:bearer|authorization)\s*[:=]\s*['"]([^'"]{20,})['"]?/gi],
  ["API Key (generic)", /(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['"]([^'"]{16,})['"]?/gi],
  ["Database URL", /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"<>]+/gi],
  ["Stripe Key", /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/g],
  ["Mailgun Key", /key-[0-9a-f]{32}/g],
  ["Twilio SID", /AC[a-f0-9]{32}/g],
  ["SendGrid Key", /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g],
]

const ENDPOINT_PATTERNS = [
  /['"`]\/api\/[^'"`\s]{2,}['"`]/g,
  /['"`]\/v[0-9]+\/[^'"`\s]{2,}['"`]/g,
  /['"`]\/(?:graphql|rest|rpc|ws|socket)[^'"`\s]*['"`]/g,
  /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /axios\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /(?:url|endpoint|path|route|href)\s*[:=]\s*['"`]([^'"`]{3,})['"`]/gi,
]

const SPA_ROUTE_PATTERNS = [
  /path:\s*['"`]\/[^'"`]*['"`]/g,
  /to:\s*['"`]\/[^'"`]*['"`]/g,
  /component:\s*['"`][A-Z][^'"`]*['"`]/g,
  /Route\s+path=["']([^"']+)["']/g,
]

const CHATBOT_INDICATORS = [
  "intercom", "drift", "tawk", "livechat", "zendesk", "freshchat",
  "hubspot", "crisp", "olark", "tidio", "chatbot", "chat-widget",
  "messenger-bot", "dialogflow", "botpress", "rasa",
]

function extractJsFiles(html: string, base: string): string[] {
  const files = new Set<string>()
  const re = /(?:src|href)=["']([^"']*\.js(?:\?[^"']*)?)["']/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(html)) !== null) {
    try {
      files.add(new URL(m[1], base).href)
    } catch {
      // invalid URL
    }
  }
  return [...files]
}

function extractEndpoints(js: string): string[] {
  const endpoints = new Set<string>()
  for (const pattern of ENDPOINT_PATTERNS) {
    pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pattern.exec(js)) !== null) {
      const val = m[1] ?? m[0].replace(/['"`]/g, "")
      if (val.startsWith("/") || val.startsWith("http")) endpoints.add(val)
    }
  }
  return [...endpoints]
}

function findSecrets(js: string, file: string): SecretMatch[] {
  const secrets: SecretMatch[] = []
  for (const [type, pattern] of SECRET_PATTERNS) {
    pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pattern.exec(js)) !== null) {
      const idx = m.index
      const start = Math.max(0, idx - 30)
      const end = Math.min(js.length, idx + m[0].length + 30)
      secrets.push({
        type,
        value: m[1] ?? m[0],
        file,
        context: js.slice(start, end).replace(/\n/g, " "),
      })
    }
  }
  return secrets
}

function findSpaRoutes(js: string): string[] {
  const routes = new Set<string>()
  for (const pattern of SPA_ROUTE_PATTERNS) {
    pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pattern.exec(js)) !== null) {
      const val = m[1] ?? m[0].replace(/.*['"`](\/[^'"`]*)['"`].*/, "$1")
      if (val.startsWith("/")) routes.add(val)
    }
  }
  return [...routes]
}

function findChatbotIndicators(text: string): string[] {
  const lower = text.toLowerCase()
  return CHATBOT_INDICATORS.filter((ind) => lower.includes(ind))
}

/**
 * Analyze JavaScript files from a target URL.
 */
export async function analyzeJs(
  url: string,
  options: { maxFiles?: number; timeout?: number } = {},
): Promise<JsAnalysisResult> {
  const maxFiles = options.maxFiles ?? 20
  const timeout = options.timeout ?? 10_000
  const start = Date.now()

  const page = await fetch(url, { signal: AbortSignal.timeout(timeout) })
  const body = await page.text()
  const jsFiles = extractJsFiles(body, url).slice(0, maxFiles)
  const allEndpoints = new Set<string>()
  const allSecrets: SecretMatch[] = []
  const allSpaRoutes = new Set<string>()
  const allChatbot = new Set<string>()

  // Analyze inline scripts
  for (const e of extractEndpoints(body)) allEndpoints.add(e)
  allSecrets.push(...findSecrets(body, url))
  for (const r of findSpaRoutes(body)) allSpaRoutes.add(r)
  for (const c of findChatbotIndicators(body)) allChatbot.add(c)

  // Fetch and analyze external JS files
  const results = await Promise.all(
    jsFiles.map(async (file) => {
      try {
        const resp = await fetch(file, { signal: AbortSignal.timeout(timeout) })
        if (!resp.ok) return null
        return { file, body: await resp.text() }
      } catch {
        return null
      }
    }),
  )

  for (const r of results) {
    if (!r) continue
    for (const e of extractEndpoints(r.body)) allEndpoints.add(e)
    allSecrets.push(...findSecrets(r.body, r.file))
    for (const rt of findSpaRoutes(r.body)) allSpaRoutes.add(rt)
    for (const c of findChatbotIndicators(r.body)) allChatbot.add(c)
  }

  return {
    endpoints: [...allEndpoints],
    secrets: allSecrets,
    apiKeys: allSecrets.filter((s) => s.type.includes("Key") || s.type.includes("Token")).map((s) => s.value),
    spaRoutes: [...allSpaRoutes],
    chatbotIndicators: [...allChatbot],
    jsFiles,
    elapsed: Date.now() - start,
  }
}
