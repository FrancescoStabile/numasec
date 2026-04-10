/**
 * Scanner: web crawler
 *
 * Enumerates URLs by following links, parsing HTML, detecting sitemap.xml,
 * robots.txt, and OpenAPI specs. No external dependencies.
 */

import { httpRequest } from "../http-client"

export interface CrawlResult {
  urls: string[]
  forms: FormInfo[]
  technologies: string[]
  openapi?: string
  sitemap: string[]
  robotsDisallowed: string[]
  elapsed: number
}

export interface FormInfo {
  action: string
  method: string
  inputs: { name: string; type: string }[]
}

const TECH_SIGNATURES: [RegExp, string][] = [
  [/x-powered-by:\s*express/i, "Express"],
  [/x-powered-by:\s*php/i, "PHP"],
  [/server:\s*nginx/i, "Nginx"],
  [/server:\s*apache/i, "Apache"],
  [/server:\s*cloudflare/i, "Cloudflare"],
  [/x-aspnet-version/i, "ASP.NET"],
  [/x-drupal/i, "Drupal"],
  [/wp-content/i, "WordPress"],
  [/django/i, "Django"],
  [/flask/i, "Flask"],
  [/laravel/i, "Laravel"],
  [/next\.js/i, "Next.js"],
  [/nuxt/i, "Nuxt"],
  [/react/i, "React"],
  [/angular/i, "Angular"],
  [/vue/i, "Vue.js"],
  [/graphql/i, "GraphQL"],
  [/swagger|openapi/i, "OpenAPI"],
]

function extractLinks(html: string, baseUrl: string): string[] {
  const links: Set<string> = new Set()
  const re = /(?:href|src|action)=["']([^"']+)["']/gi
  let match: RegExpExecArray | null
  while ((match = re.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], baseUrl).href
      // Only follow same-origin links
      const base = new URL(baseUrl)
      const target = new URL(resolved)
      if (target.origin === base.origin) {
        links.add(target.href.split("#")[0])
      }
    } catch {
      // Invalid URL
    }
  }
  return [...links]
}

function extractForms(html: string, baseUrl: string): FormInfo[] {
  const forms: FormInfo[] = []
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi
  let formMatch: RegExpExecArray | null
  while ((formMatch = formRe.exec(html)) !== null) {
    const formTag = formMatch[0]
    const actionMatch = formTag.match(/action=["']([^"']*)["']/i)
    const methodMatch = formTag.match(/method=["']([^"']*)["']/i)

    const inputs: { name: string; type: string }[] = []
    const inputRe = /<(?:input|select|textarea)[^>]*>/gi
    let inputMatch: RegExpExecArray | null
    while ((inputMatch = inputRe.exec(formMatch[1])) !== null) {
      const nameMatch = inputMatch[0].match(/name=["']([^"']*)["']/i)
      const typeMatch = inputMatch[0].match(/type=["']([^"']*)["']/i)
      if (nameMatch) {
        inputs.push({ name: nameMatch[1], type: typeMatch?.[1] ?? "text" })
      }
    }

    forms.push({
      action: actionMatch ? new URL(actionMatch[1] || "/", baseUrl).href : baseUrl,
      method: (methodMatch?.[1] ?? "GET").toUpperCase(),
      inputs,
    })
  }
  return forms
}

function detectTechnologies(headers: Record<string, string>, body: string): string[] {
  const techs = new Set<string>()
  const combined = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n") + "\n" + body
  for (const [re, name] of TECH_SIGNATURES) {
    if (re.test(combined)) techs.add(name)
  }
  return [...techs]
}

async function fetchRobots(baseUrl: string): Promise<string[]> {
  try {
    const resp = await httpRequest(`${baseUrl}/robots.txt`, { timeout: 5000 })
    if (resp.status !== 200) return []
    const disallowed: string[] = []
    for (const line of resp.body.split("\n")) {
      const match = line.match(/^Disallow:\s*(.+)/i)
      if (match) disallowed.push(match[1].trim())
    }
    return disallowed
  } catch {
    return []
  }
}

async function fetchSitemap(baseUrl: string): Promise<string[]> {
  try {
    const resp = await httpRequest(`${baseUrl}/sitemap.xml`, { timeout: 5000 })
    if (resp.status !== 200) return []
    const urls: string[] = []
    const re = /<loc>([^<]+)<\/loc>/gi
    let match: RegExpExecArray | null
    while ((match = re.exec(resp.body)) !== null) urls.push(match[1])
    return urls
  } catch {
    return []
  }
}

async function detectOpenAPI(baseUrl: string): Promise<string | undefined> {
  const paths = ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs"]
  for (const p of paths) {
    try {
      const resp = await httpRequest(`${baseUrl}${p}`, { timeout: 5000 })
      if (resp.status === 200 && (resp.body.includes('"openapi"') || resp.body.includes('"swagger"'))) {
        return `${baseUrl}${p}`
      }
    } catch {
      // continue
    }
  }
  return undefined
}

/**
 * Crawl a web application starting from the given URL.
 */
export async function crawl(
  startUrl: string,
  options: { maxUrls?: number; maxDepth?: number; timeout?: number } = {},
): Promise<CrawlResult> {
  const { maxUrls = 100, maxDepth = 3, timeout = 10_000 } = options
  const start = Date.now()
  const visited = new Set<string>()
  const allForms: FormInfo[] = []
  const allTechs = new Set<string>()
  const queue: { url: string; depth: number }[] = [{ url: startUrl, depth: 0 }]

  const baseUrl = new URL(startUrl).origin

  // Parallel: fetch robots, sitemap, openapi while crawling
  const [robotsDisallowed, sitemap, openapi] = await Promise.all([
    fetchRobots(baseUrl),
    fetchSitemap(baseUrl),
    detectOpenAPI(baseUrl),
  ])

  // Add sitemap URLs to queue
  for (const url of sitemap.slice(0, 20)) {
    queue.push({ url, depth: 1 })
  }

  while (queue.length > 0 && visited.size < maxUrls) {
    const item = queue.shift()!
    if (visited.has(item.url) || item.depth > maxDepth) continue
    visited.add(item.url)

    try {
      const resp = await httpRequest(item.url, { timeout })
      if (resp.status === 0 || resp.status >= 400) continue

      const techs = detectTechnologies(resp.headers, resp.body)
      for (const t of techs) allTechs.add(t)

      const forms = extractForms(resp.body, item.url)
      allForms.push(...forms)

      if (item.depth < maxDepth) {
        const links = extractLinks(resp.body, item.url)
        for (const link of links) {
          if (!visited.has(link)) {
            queue.push({ url: link, depth: item.depth + 1 })
          }
        }
      }
    } catch {
      // Skip unreachable URLs
    }
  }

  return {
    urls: [...visited],
    forms: allForms,
    technologies: [...allTechs],
    openapi,
    sitemap,
    robotsDisallowed,
    elapsed: Date.now() - start,
  }
}
