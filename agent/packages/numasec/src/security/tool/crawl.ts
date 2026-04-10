/**
 * Tool: crawl
 *
 * Composite crawling tool. Discovers URLs, forms, technologies, and
 * OpenAPI specs on a web application.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { crawl } from "../scanner/crawl"
import { dirFuzz } from "../scanner/dir-fuzzer"

const DESCRIPTION = `Crawl a web application to discover endpoints, forms, and technologies.
Combines: link following, sitemap.xml, robots.txt, OpenAPI detection, directory fuzzing.

Returns: discovered URLs, forms with parameters, technologies, hidden paths.

NEXT STEPS after crawl:
- For each form: test for injection (SQLi, XSS, SSTI, etc.)
- For discovered API endpoints: test with injection_test
- If auth endpoints found: test with auth_test
- If upload endpoints found: test with upload_test
- For hidden admin panels (401/403): test for auth bypass`

export const CrawlTool = Tool.define("crawl", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Target URL to crawl"),
    max_urls: z.number().optional().describe("Maximum URLs to discover (default 100)"),
    max_depth: z.number().optional().describe("Maximum crawl depth (default 3)"),
    fuzz: z.boolean().optional().describe("Also run directory fuzzing (default true)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "crawl",
      patterns: [params.url],
      always: ["*"] as string[],
      metadata: { url: params.url } as Record<string, any>,
    })

    const parts: string[] = []

    // Crawl
    ctx.metadata({ title: `Crawling ${params.url}...` })
    const crawlResult = await crawl(params.url, {
      maxUrls: params.max_urls,
      maxDepth: params.max_depth,
    })

    parts.push(`── Crawl Results (${crawlResult.elapsed}ms) ──`)
    parts.push(`URLs discovered: ${crawlResult.urls.length}`)

    if (crawlResult.technologies.length > 0) {
      parts.push(`Technologies: ${crawlResult.technologies.join(", ")}`)
    }

    if (crawlResult.openapi) {
      parts.push(`OpenAPI spec: ${crawlResult.openapi}`)
    }

    if (crawlResult.robotsDisallowed.length > 0) {
      parts.push("")
      parts.push("── robots.txt Disallowed ──")
      for (const p of crawlResult.robotsDisallowed) parts.push(`  ${p}`)
    }

    if (crawlResult.urls.length > 0) {
      parts.push("")
      parts.push("── Discovered URLs ──")
      for (const url of crawlResult.urls.slice(0, 30)) parts.push(`  ${url}`)
      if (crawlResult.urls.length > 30) parts.push(`  ... and ${crawlResult.urls.length - 30} more`)
    }

    if (crawlResult.forms.length > 0) {
      parts.push("")
      parts.push(`── Forms (${crawlResult.forms.length}) ──`)
      for (const form of crawlResult.forms) {
        const inputs = form.inputs.map((i) => `${i.name}[${i.type}]`).join(", ")
        parts.push(`  ${form.method} ${form.action} → ${inputs}`)
      }
    }

    // Directory fuzzing
    if (params.fuzz !== false) {
      ctx.metadata({ title: "Fuzzing directories..." })
      const fuzzResult = await dirFuzz(params.url)
      if (fuzzResult.found.length > 0) {
        parts.push("")
        parts.push(`── Directory Fuzzing (${fuzzResult.testedCount} tested, ${fuzzResult.elapsed}ms) ──`)
        for (const f of fuzzResult.found) {
          const redirect = f.redirect ? ` → ${f.redirect}` : ""
          parts.push(`  ${f.status} ${f.path} (${f.length} bytes)${redirect}`)
        }
      }
    }

    return {
      title: `Crawl: ${crawlResult.urls.length} URLs, ${crawlResult.forms.length} forms`,
      metadata: {
        urls: crawlResult.urls.length,
        forms: crawlResult.forms.length,
        technologies: crawlResult.technologies,
      } as any,
      output: parts.join("\n"),
    }
  },
})
