/**
 * Scanner: web crawler
 *
 * Enumerates URLs by following links, parsing HTML, detecting sitemap.xml,
 * robots.txt, and OpenAPI specs.
 */

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
  [/wp-content|wp-includes/i, "WordPress"],
  [/x-powered-by:.*django|csrfmiddlewaretoken/i, "Django"],
  [/x-powered-by:.*(?:flask|werkzeug)/i, "Flask"],
  [/x-powered-by:.*laravel|laravel_session/i, "Laravel"],
  [/__NEXT_DATA__|_next\//i, "Next.js"],
  [/__NUXT__|_nuxt\//i, "Nuxt"],
  [/data-reactroot|react-dom/i, "React"],
  [/ng-version|ng-app|angular\.(?:min\.)?js/i, "Angular"],
  [/data-v-[a-f0-9]|vue\.(?:min\.)?js|__vue__/i, "Vue.js"],
  [/graphql/i, "GraphQL"],
  [/swagger|openapi/i, "OpenAPI"],
]

function extractLinks(html: string, base: string): string[] {
  const links = new Set<string>()
  const re = /(?:href|src|action)=["']([^"']+)["']/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(html)) !== null) {
    try {
      const resolved = new URL(m[1], base)
      const origin = new URL(base)
      if (resolved.origin === origin.origin) {
        links.add(resolved.href.split("#")[0])
      }
    } catch {
      // invalid URL
    }
  }
  return [...links]
}

function extractForms(html: string, base: string): FormInfo[] {
  const forms: FormInfo[] = []
  const re = /<form[^>]*>([\s\S]*?)<\/form>/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(html)) !== null) {
    const tag = m[0]
    const action = tag.match(/action=["']([^"']*)["']/i)
    const method = tag.match(/method=["']([^"']*)["']/i)

    const inputs: { name: string; type: string }[] = []
    const inputRe = /<(?:input|select|textarea)[^>]*>/gi
    let im: RegExpExecArray | null
    while ((im = inputRe.exec(m[1])) !== null) {
      const name = im[0].match(/name=["']([^"']*)["']/i)
      const type = im[0].match(/type=["']([^"']*)["']/i)
      if (name) {
        inputs.push({ name: name[1], type: type?.[1] ?? "text" })
      }
    }

    forms.push({
      action: action ? new URL(action[1] || "/", base).href : base,
      method: (method?.[1] ?? "GET").toUpperCase(),
      inputs,
    })
  }
  return forms
}

function detectTechnologies(headers: Headers, body: string): string[] {
  const techs = new Set<string>()
  const parts: string[] = []
  headers.forEach((v, k) => parts.push(`${k}: ${v}`))
  const combined = parts.join("\n") + "\n" + body
  for (const [re, name] of TECH_SIGNATURES) {
    if (re.test(combined)) techs.add(name)
  }
  return [...techs]
}

async function fetchRobots(base: string): Promise<string[]> {
  try {
    const resp = await fetch(`${base}/robots.txt`, { signal: AbortSignal.timeout(5000) })
    if (!resp.ok) return []
    const text = await resp.text()
    const disallowed: string[] = []
    for (const line of text.split("\n")) {
      const m = line.match(/^Disallow:\s*(.+)/i)
      if (m) disallowed.push(m[1].trim())
    }
    return disallowed
  } catch {
    return []
  }
}

async function fetchSitemap(base: string): Promise<string[]> {
  try {
    const resp = await fetch(`${base}/sitemap.xml`, { signal: AbortSignal.timeout(5000) })
    if (!resp.ok) return []
    const text = await resp.text()
    const urls: string[] = []
    const re = /<loc>([^<]+)<\/loc>/gi
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) urls.push(m[1])
    return urls
  } catch {
    return []
  }
}

async function detectOpenAPI(base: string): Promise<string | undefined> {
  const paths = ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs"]
  for (const p of paths) {
    try {
      const resp = await fetch(`${base}${p}`, { signal: AbortSignal.timeout(5000) })
      if (!resp.ok) continue
      const text = await resp.text()
      if (text.includes('"openapi"') || text.includes('"swagger"')) return `${base}${p}`
    } catch {
      // continue
    }
  }
  return undefined
}

async function fetchPage(url: string, timeout: number): Promise<{ status: number; headers: Headers; body: string } | null> {
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(timeout) })
    return { status: resp.status, headers: resp.headers, body: await resp.text() }
  } catch {
    return null
  }
}

/**
 * Crawl a web application starting from the given URL.
 */
export async function crawl(
  startUrl: string,
  options: { maxUrls?: number; maxDepth?: number; timeout?: number } = {},
): Promise<CrawlResult> {
  const maxUrls = options.maxUrls ?? 100
  const maxDepth = options.maxDepth ?? 3
  const timeout = options.timeout ?? 10_000
  const start = Date.now()
  const visited = new Set<string>()
  const allForms: FormInfo[] = []
  const allTechs = new Set<string>()
  const queue: { url: string; depth: number }[] = [{ url: startUrl, depth: 0 }]
  const base = new URL(startUrl).origin

  const [robotsDisallowed, sitemap, openapi] = await Promise.all([
    fetchRobots(base),
    fetchSitemap(base),
    detectOpenAPI(base),
  ])

  for (const url of sitemap.slice(0, 20)) {
    queue.push({ url, depth: 1 })
  }

  while (queue.length > 0 && visited.size < maxUrls) {
    const item = queue.shift()!
    if (visited.has(item.url) || item.depth > maxDepth) continue
    visited.add(item.url)

    const resp = await fetchPage(item.url, timeout)
    if (!resp || resp.status >= 400) continue

    const techs = detectTechnologies(resp.headers, resp.body)
    for (const t of techs) allTechs.add(t)

    allForms.push(...extractForms(resp.body, item.url))

    if (item.depth < maxDepth) {
      for (const link of extractLinks(resp.body, item.url)) {
        if (!visited.has(link)) queue.push({ url: link, depth: item.depth + 1 })
      }
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
