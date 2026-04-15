/**
 * Tool: dir_fuzz
 *
 * Directory / path brute-force tool wrapper.
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { runObserveSurfaceProfile } from "./observe-surface"

const DESCRIPTION = `Brute-force directories and files on a web server.
Uses a built-in wordlist (~600 common paths) to discover hidden endpoints.

Returns: found paths with status codes, sizes, and redirect targets.

NEXT STEPS after finding paths:
- 403 Forbidden: try auth bypass techniques
- 401 Unauthorized: try default credentials via auth_test
- 200 with admin/config: test for sensitive data exposure
- /api/ paths: test with injection_test and access_control_test`

export const DirFuzzTool = Tool.define("dir_fuzz", {
  description: DESCRIPTION,
  parameters: z.object({
    url: z.string().describe("Base URL to fuzz"),
    wordlist: z.array(z.string()).optional().describe("Custom wordlist (default: built-in)"),
    extensions: z.array(z.string()).optional().describe("File extensions to try (e.g. php, asp, jsp)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "dir_fuzz",
      patterns: [params.url],
      always: [] as string[],
      metadata: { url: params.url } as Record<string, any>,
    })

    const profile = await runObserveSurfaceProfile(
      {
        target: params.url,
        sessionID: ctx.sessionID,
        modes: ["dir_fuzz"],
        wordlist: params.wordlist,
        extensions: params.extensions,
      },
      {
        onStage: (title) => ctx.metadata({ title }),
      },
    )
    const result = profile.dir_fuzz
    if (!result) {
      return {
        title: "Dir fuzz: 0 found / 0 tested",
        metadata: { found: 0, tested: 0 } as any,
        output: "No directory fuzzing results.",
      }
    }

    const parts: string[] = [`── Directory Fuzzing (${result.testedCount} tested, ${result.elapsed}ms) ──`]
    if (result.found.length === 0) {
      parts.push("No hidden paths found.")
    } else {
      for (const f of result.found) {
        const redirect = f.redirect ? ` → ${f.redirect}` : ""
        parts.push(`  ${f.status} ${f.path} (${f.length} bytes)${redirect}`)
      }
    }

    return {
      title: `Dir fuzz: ${result.found.length} found / ${result.testedCount} tested`,
      metadata: { found: result.found.length, tested: result.testedCount } as any,
      output: parts.join("\n"),
    }
  },
})
