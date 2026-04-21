/**
 * Scanner: directory fuzzer
 *
 * Brute-force directory/file enumeration using a built-in wordlist.
 */

export interface DirFuzzResult {
  found: FoundPath[]
  testedCount: number
  elapsed: number
}

export interface FoundPath {
  path: string
  status: number
  length: number
  redirect?: string
}

const BUILTIN_WORDLIST = [
  // Admin / management
  "admin", "administrator", "api", "api/v1", "api/v2", "api/v3",
  "app", "assets", "auth", "backup", "bin", "cgi-bin",
  "config", "console", "cp", "dashboard", "db", "debug",
  "dev", "docs", "dump", "env", "error", "files",
  // GraphQL / introspection
  "graphql", "graphiql", "graphql/schema", "graphql/console",
  // Health / monitoring
  "health", "healthcheck", "help", "hidden",
  "images", "img", "include", "info", "install", "internal",
  "js", "json", "log", "login", "logout", "manage",
  "manager", "metrics", "monitor", "old", "panel", "phpinfo",
  "phpmyadmin", "portal", "private", "profile", "public", "redirect",
  "register", "reset", "robots.txt", "rpc", "search", "secret",
  "secure", "server-info", "server-status", "service", "settings", "setup",
  "shell", "sitemap.xml", "sql", "ssh", "staging", "static",
  "status", "swagger", "swagger-ui", "system", "temp", "test",
  "tmp", "token", "upload", "uploads", "user", "users",
  "v1", "v2", "version", "web", "webmail", "wp-admin",
  "wp-content", "wp-login.php", "xmlrpc.php", ".env", ".git",
  ".git/config", ".htaccess", ".htpasswd", ".svn",
  // Spring / Java
  "actuator", "actuator/health", "actuator/env", "actuator/beans",
  "actuator/mappings", "actuator/configprops", "actuator/trace",
  // WordPress
  "wp-json", "wp-json/wp/v2/users",
  // REST / API
  "rest", "api-docs", "openapi.json", "openapi.yaml",
  "swagger.json", "swagger.yaml", "api/swagger",
  // Node.js / Express / Juice Shop specific
  "api/Products", "api/Users", "api/Challenges", "api/Feedbacks",
  "api/Complaints", "api/Recycles", "api/SecurityQuestions",
  "api/SecurityAnswers", "api/Quantitys", "api/Cards",
  "rest/user", "rest/admin", "rest/products",
  "rest/basket", "rest/saveLoginIp", "rest/deluxe-membership",
  "rest/memories", "rest/chatbot", "rest/repeat-notification",
  "ftp", "encryptionkeys", "support/logs",
  "snippets", "promotion", "video",
  // Common API patterns
  "api/config", "api/status", "api/health", "api/debug",
  "api/internal", "api/admin", "api/export", "api/import",
  "api/backup", "api/reset", "api/token",
  // Documentation
  "redoc", "api-explorer", "api-console",
  // Security
  ".well-known/security.txt", "security.txt",
  ".well-known/openid-configuration",
  // Config files
  "package.json", "composer.json", "Gemfile",
  "web.config", "applicationContext.xml",
  ".dockerenv", "Dockerfile", "docker-compose.yml",
  // Cloud metadata
  "latest/meta-data", "metadata",
]

const INTERESTING_STATUS = new Set([200, 201, 204, 301, 302, 307, 308, 401, 403])

async function probe(url: string, timeout: number): Promise<{ status: number; length: number; location?: string } | null> {
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(timeout), redirect: "manual" })
    const body = await resp.text()
    return {
      status: resp.status,
      length: body.length,
      location: resp.headers.get("location") ?? undefined,
    }
  } catch {
    return null
  }
}

/**
 * Fuzz directories on a target URL.
 */
export async function dirFuzz(
  baseUrl: string,
  options: {
    wordlist?: string[]
    extensions?: string[]
    concurrency?: number
    timeout?: number
    filterStatus?: number[]
  } = {},
): Promise<DirFuzzResult> {
  const wordlist = options.wordlist ?? BUILTIN_WORDLIST
  const extensions = options.extensions ?? []
  const concurrency = options.concurrency ?? 10
  const timeout = options.timeout ?? 10_000
  const start = Date.now()
  const base = baseUrl.replace(/\/+$/, "")
  const found: FoundPath[] = []
  let tested = 0

  // Build full path list including extensions
  const paths: string[] = [...wordlist]
  for (const word of wordlist) {
    for (const ext of extensions) {
      paths.push(`${word}.${ext}`)
    }
  }

  // Baseline: request a definitely-not-found path
  const baseline = await probe(`${base}/numasec_404_check_${Date.now()}`, timeout)
  const baselineStatus = baseline?.status ?? 404
  const baselineLength = baseline?.length ?? 0

  const statusFilter = options.filterStatus ? new Set(options.filterStatus) : INTERESTING_STATUS

  // Scan in batches
  for (let i = 0; i < paths.length; i += concurrency) {
    const batch = paths.slice(i, i + concurrency)

    const results = await Promise.all(
      batch.map(async (path) => {
        tested++
        const resp = await probe(`${base}/${path}`, timeout)
        if (!resp) return null

        // Skip if same as 404 baseline (custom 404 pages)
        if (resp.status === baselineStatus && Math.abs(resp.length - baselineLength) < 50) return null
        if (!statusFilter.has(resp.status)) return null

        return {
          path: `/${path}`,
          status: resp.status,
          length: resp.length,
          redirect: resp.location,
        } as FoundPath
      }),
    )

    for (const r of results) {
      if (r) found.push(r)
    }
  }

  return {
    found: found.sort((a, b) => a.status - b.status),
    testedCount: tested,
    elapsed: Date.now() - start,
  }
}
