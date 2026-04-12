/**
 * Tool: shell
 *
 * Unified shell execution for external security tools (nmap, sqlmap,
 * nuclei, ffuf, etc.). Wraps the existing Bash tool's shell infrastructure
 * but adds security-tool-specific permission categories.
 *
 * Permission model:
 * - Passive tools (nmap, curl, dig): auto-allowed after first prompt
 * - Active tools (sqlmap, nuclei, ffuf): always ask
 * - Destructive tools (metasploit): always ask with warning
 */

import z from "zod"
import { Tool } from "../../tool/tool"
import { spawn } from "child_process"

const DEFAULT_TIMEOUT = 120_000

const DESCRIPTION = `Execute a shell command for security testing. Use when you need to run
external tools like nmap, sqlmap, nuclei, ffuf, curl, or custom scripts.

Common patterns:
- nmap -sV -p- target.com
- sqlmap -u "url" --batch --forms
- nuclei -u target.com -t cves/
- ffuf -u "url/FUZZ" -w wordlist.txt
- curl -v "url"

Returns: stdout, stderr, exit code, elapsed time.
The command runs with a timeout (default 2 minutes).`

export const ShellTool = Tool.define("security_shell", {
  description: DESCRIPTION,
  parameters: z.object({
    command: z.string().describe("The shell command to execute"),
    timeout: z.number().optional().describe("Timeout in milliseconds (default 120000)"),
    description: z.string().describe("Short description of what this command does (5-10 words)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "security_shell",
      patterns: [params.command],
      always: [] as string[],
      metadata: { command: params.command, description: params.description } as Record<string, any>,
    })

    const timeout = params.timeout ?? DEFAULT_TIMEOUT
    const start = Date.now()

    const result = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve) => {
      const chunks: Buffer[] = []
      const errChunks: Buffer[] = []

      const isWin = process.platform === "win32"
      const shell = isWin ? (process.env.COMSPEC || "cmd.exe") : "sh"
      const shellArgs = isWin ? ["/c", params.command] : ["-c", params.command]

      const proc = spawn(shell, shellArgs, {
        timeout,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, TERM: "dumb" },
        windowsHide: isWin,
      })

      proc.stdout.on("data", (d: Buffer) => chunks.push(d))
      proc.stderr.on("data", (d: Buffer) => errChunks.push(d))

      proc.on("close", (code) => {
        resolve({
          stdout: Buffer.concat(chunks).toString("utf-8"),
          stderr: Buffer.concat(errChunks).toString("utf-8"),
          exitCode: code ?? 1,
        })
      })

      proc.on("error", (err) => {
        resolve({ stdout: "", stderr: err.message, exitCode: 1 })
      })
    })

    const elapsed = Date.now() - start

    const parts: string[] = []
    if (result.stdout) {
      parts.push("── stdout ──")
      parts.push(result.stdout.length > 10000 ? result.stdout.slice(0, 10000) + "\n... (truncated)" : result.stdout)
    }
    if (result.stderr) {
      parts.push("── stderr ──")
      parts.push(result.stderr.length > 5000 ? result.stderr.slice(0, 5000) + "\n... (truncated)" : result.stderr)
    }
    parts.push(`\nExit code: ${result.exitCode} | Elapsed: ${elapsed}ms`)

    return {
      title: params.description,
      metadata: {
        exitCode: result.exitCode,
        elapsed,
        stdoutLength: result.stdout.length,
        stderrLength: result.stderr.length,
      },
      output: parts.join("\n"),
    }
  },
})
