import z from "zod"
import { Effect } from "effect"
import { spawn } from "node:child_process"
import { which } from "../util/which"
import * as Tool from "./tool"
import DESCRIPTION from "./recon.txt"

const WEB_TOOLS = ["nuclei", "ffuf", "katana", "sqlmap", "httpx", "subfinder"] as const
const OSINT_TOOLS = ["theharvester", "sherlock", "maigret", "shodan", "whois", "holehe"] as const
const ALL_TOOLS = [...WEB_TOOLS, ...OSINT_TOOLS] as const

const parameters = z.object({
  tool: z.enum(ALL_TOOLS),
  args: z.array(z.string()).default([]),
  stdin: z.string().optional(),
  timeout_ms: z.number().int().min(1000).max(600_000).optional(),
})

type Params = z.infer<typeof parameters>
type Metadata = { tool: string; exit_code: number | null; duration_ms: number; family: string }

function familyOf(t: string): string {
  return (WEB_TOOLS as readonly string[]).includes(t) ? "web" : "osint"
}

function binaryOf(tool: string): string {
  if (tool === "theharvester") return "theHarvester"
  return tool
}

function runBinary(params: Params): Promise<{ stdout: string; stderr: string; code: number | null; ms: number }> {
  const timeout = params.timeout_ms ?? 120_000
  const start = Date.now()
  return new Promise((resolve, reject) => {
    const bin = binaryOf(params.tool)
    const child = spawn(bin, params.args, { stdio: ["pipe", "pipe", "pipe"] })
    const out: Buffer[] = []
    const err: Buffer[] = []
    const cap = 4 * 1024 * 1024
    let outSize = 0
    let errSize = 0
    child.stdout.on("data", (d: Buffer) => {
      if (outSize < cap) {
        out.push(d)
        outSize += d.length
      }
    })
    child.stderr.on("data", (d: Buffer) => {
      if (errSize < cap) {
        err.push(d)
        errSize += d.length
      }
    })
    const killer = setTimeout(() => {
      try {
        child.kill("SIGKILL")
      } catch {}
    }, timeout)
    child.on("error", (e) => {
      clearTimeout(killer)
      reject(e)
    })
    child.on("close", (code) => {
      clearTimeout(killer)
      resolve({
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
        code,
        ms: Date.now() - start,
      })
    })
    if (params.stdin) {
      child.stdin.write(params.stdin)
    }
    child.stdin.end()
  })
}

export const ReconTool = Tool.define<typeof parameters, Metadata, never>(
  "recon",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const bin = binaryOf(params.tool)
          const resolved = which(bin)
          if (!resolved) {
            return {
              title: `recon ${params.tool} (missing)`,
              output: `Binary not found on PATH: ${bin}\nInstall it and retry. numasec does not bundle external recon binaries.`,
              metadata: { tool: params.tool, exit_code: null, duration_ms: 0, family: familyOf(params.tool) } as Metadata,
            }
          }
          yield* ctx.ask({
            permission: "recon",
            patterns: [`${params.tool} ${params.args.join(" ")}`.trim()],
            always: ["*"],
            metadata: {
              tool: params.tool,
              family: familyOf(params.tool),
              args: params.args,
            },
          })
          const r = yield* Effect.tryPromise({
            try: () => runBinary(params),
            catch: (e) => new Error(`recon: ${(e as Error).message}`),
          })
          const body = [
            `$ ${bin} ${params.args.join(" ")}`.trim(),
            `exit=${r.code}  duration=${r.ms}ms`,
            "",
            "── stdout ──",
            r.stdout || "(empty)",
            "",
            "── stderr ──",
            r.stderr || "(empty)",
          ].join("\n")
          return {
            title: `recon ${params.tool} exit=${r.code}`,
            output: body,
            metadata: {
              tool: params.tool,
              exit_code: r.code,
              duration_ms: r.ms,
              family: familyOf(params.tool),
            } as Metadata,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
