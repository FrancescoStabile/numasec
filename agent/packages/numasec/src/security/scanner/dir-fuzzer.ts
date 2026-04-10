/**
 * Scanner: directory fuzzer
 *
 * Brute-force directory/file enumeration using a built-in wordlist.
 * Also wraps ffuf/gobuster via shell when available.
 */

import { httpRequest } from "../http-client"

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

// Built-in wordlist — common web paths for quick scans
const BUILTIN_WORDLIST = [
  "admin", "administrator", "api", "api/v1", "api/v2", "api/v3",
  "app", "assets", "auth", "backup", "bin", "cgi-bin",
  "config", "console", "cp", "dashboard", "db", "debug",
  "dev", "docs", "dump", "env", "error", "files",
  "graphql", "graphiql", "health", "healthcheck", "help", "hidden",
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
  "actuator", "actuator/health", "actuator/env",
  "wp-json", "rest", "graphql/schema",
]

const INTERESTING_STATUS = new Set([200, 201, 204, 301, 302, 307, 308, 401, 403])

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
  const {
    wordlist = BUILTIN_WORDLIST,
    extensions = [],
    concurrency = 10,
    timeout = 10_000,
    filterStatus,
  } = options

  const start = Date.now()
  const base = baseUrl.replace(/\/+$/, "")
  const found: FoundPath[] = []
  let testedCount = 0

  // Build full path list including extensions
  const paths: string[] = [...wordlist]
  for (const word of wordlist) {
    for (const ext of extensions) {
      paths.push(`${word}.${ext}`)
    }
  }

  // Baseline: request a definitely-not-found path
  const notFound = await httpRequest(`${base}/numasec_404_check_${Date.now()}`, { timeout })
  const notFoundStatus = notFound.status
  const notFoundLength = notFound.body.length

  // Scan in batches
  for (let i = 0; i < paths.length; i += concurrency) {
    const batch = paths.slice(i, i + concurrency)

    const batchResults = await Promise.all(
      batch.map(async (path) => {
        testedCount++
        const url = `${base}/${path}`
        const resp = await httpRequest(url, { timeout, followRedirects: false })

        // Filter: skip if same as 404 baseline (custom 404 pages)
        if (resp.status === notFoundStatus && Math.abs(resp.body.length - notFoundLength) < 50) {
          return null
        }

        // Filter by status
        const statusFilter = filterStatus ? new Set(filterStatus) : INTERESTING_STATUS
        if (!statusFilter.has(resp.status)) return null

        return {
          path: `/${path}`,
          status: resp.status,
          length: resp.body.length,
          redirect: resp.redirectChain.length > 0 ? resp.headers["location"] : undefined,
        } as FoundPath
      }),
    )

    for (const r of batchResults) {
      if (r) found.push(r)
    }
  }

  return {
    found: found.sort((a, b) => a.status - b.status),
    testedCount,
    elapsed: Date.now() - start,
  }
}
