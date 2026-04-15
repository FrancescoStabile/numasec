/**
 * Tool: upload_test
 *
 * File upload vulnerability testing.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { testUpload } from "../scanner/upload-tester"

const DESCRIPTION = `Test file upload endpoints for bypass vulnerabilities.
Tests: extension bypass (double ext, null byte), content-type spoofing,
path traversal in filename, SVG XSS, polyglot payloads.

Requires: upload endpoint URL and the form field name for the file.

CHAIN POTENTIAL: Upload bypass → Remote Code Execution:
- Upload PHP/JSP webshell → execute OS commands
- SVG with JS → stored XSS affecting all viewers
- Path traversal → overwrite server config files`

export const UploadTestTool = Tool.define("upload_test", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Upload endpoint URL"),
    field: z.string().default("file").describe("Form field name for file upload"),
    headers: z.record(z.string(), z.string()).optional().describe("Extra headers"),
    cookies: z.string().optional().describe("Cookies"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "upload_test",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url, field: params.field } as Record<string, any>,
    })

    ctx.metadata({ title: "Testing file upload bypasses..." })
    const result = await testUpload(params.url, {
      fieldName: params.field,
      headers: params.headers,
      cookies: params.cookies,
      sessionID: ctx.sessionID,
    })

    const parts: string[] = []
    if (result.findings.length > 0) {
      parts.push(`⚠ ${result.findings.length} upload bypass(es) found`)
      parts.push("")
      for (const f of result.findings) {
        parts.push(`Technique: ${f.technique}`)
        parts.push(`Filename: ${f.filename}`)
        parts.push(`Content-Type: ${f.contentType}`)
        parts.push(`Status: ${f.status}`)
        parts.push(`Evidence: ${f.evidence}`)
        parts.push("")
      }
    } else {
      parts.push(`No upload bypasses found (${result.testedCount} techniques tested)`)
    }

    return {
      title: result.findings.length > 0
        ? `⚠ ${result.findings.length} upload bypass(es)`
        : "Upload: no bypasses",
      metadata: { findings: result.findings.length, tested: result.testedCount } as any,
      output: parts.join("\n"),
    }
  },
})
