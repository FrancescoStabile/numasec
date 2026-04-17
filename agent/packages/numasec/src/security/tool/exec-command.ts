import z from "zod"
import { spawn } from "child_process"
import { Tool } from "../../tool/tool"
import { manualCommandEnvelope, mergeToolEnvelopes } from "../manual-http-proof"
import { makeToolResultEnvelope } from "./result-envelope"
import { securityChildEnv } from "../child-env"
import { Scope } from "../scope"

const DESCRIPTION = `Execute a local command with explicit argv and bounded timeout.
This is the primitive-native command execution surface (security_shell compatibility path).`

export interface ExecCommandInput {
  argv: string[]
  cwd?: string
  timeout: number
  env?: Record<string, string>
}

export interface ExecCommandOutput {
  stdout: string
  stderr: string
  exitCode: number
  timedOut: boolean
}

export interface ExecCommandAlias {
  permission: string
  patterns: string[]
  always: string[]
  metadata: Record<string, any>
}

export interface ExecuteExecCommandInput {
  argv: string[]
  cwd?: string
  env_allowlist?: Record<string, string>
  timeout?: number
  description?: string
  scope_targets?: string[]
  raw_command?: string
}

export interface ExecuteExecCommandResult {
  command: string
  elapsed: number
  result: ExecCommandOutput
}

const NETWORK_BINARIES = new Set([
  "curl",
  "dig",
  "dirsearch",
  "ffuf",
  "feroxbuster",
  "gobuster",
  "host",
  "httpx",
  "masscan",
  "nc",
  "netcat",
  "nikto",
  "nmap",
  "nuclei",
  "ping",
  "rustscan",
  "sqlmap",
  "telnet",
  "traceroute",
  "whatweb",
  "wget",
  "wfuzz",
])

function binaryName(input: string) {
  const parts = input.split(/[\\/]/)
  return (parts[parts.length - 1] ?? input).toLowerCase()
}

function commandBinary(input: ExecuteExecCommandInput) {
  if (input.raw_command) {
    const parts = input.raw_command.trim().split(/\s+/)
    return binaryName(parts[0] ?? "")
  }
  if (input.argv.length === 0) return ""
  if ((input.argv[0] === "sh" || input.argv[0] === "bash" || input.argv[0] === "zsh") && input.argv[2]) {
    const parts = input.argv[2].trim().split(/\s+/)
    return binaryName(parts[0] ?? "")
  }
  if ((input.argv[0] === "cmd.exe" || input.argv[0] === "cmd") && input.argv[2]) {
    const parts = input.argv[2].trim().split(/\s+/)
    return binaryName(parts[0] ?? "")
  }
  return binaryName(input.argv[0] ?? "")
}

function normalizeTarget(input: string) {
  return input.replace(/[),.;]+$/, "")
}

function commandTargets(input: ExecuteExecCommandInput) {
  const targets = new Set<string>()
  for (const item of input.scope_targets ?? []) {
    if (!item.trim()) continue
    targets.add(item.trim())
  }
  const text = input.raw_command ?? input.argv.join(" ")
  const matches = text.match(/\bhttps?:\/\/[^\s"'`<>]+/gi) ?? []
  for (const item of matches) {
    targets.add(normalizeTarget(item))
  }
  return Array.from(targets)
}

export function enforceExecCommandScope(sessionID: string, input: ExecuteExecCommandInput) {
  const targets = commandTargets(input)
  if (targets.length > 0) {
    Scope.ensure(sessionID, targets)
    return targets
  }
  const binary = commandBinary(input)
  if (!binary || !NETWORK_BINARIES.has(binary)) return []
  throw new Scope.ScopeViolationError(
    `Command target is not explicit. Provide scope_targets for ${binary} so numasec can enforce engagement boundaries.`,
  )
}

export async function runExecCommand(input: ExecCommandInput): Promise<ExecCommandOutput> {
  return new Promise((resolve) => {
    const out: Buffer[] = []
    const err: Buffer[] = []
    let timedOut = false
    const proc = spawn(input.argv[0], input.argv.slice(1), {
      cwd: input.cwd,
      timeout: input.timeout,
      stdio: ["ignore", "pipe", "pipe"],
      env: securityChildEnv(input.env),
      windowsHide: true,
    })

    proc.stdout.on("data", (chunk: Buffer) => out.push(chunk))
    proc.stderr.on("data", (chunk: Buffer) => err.push(chunk))
    proc.on("error", (error) => {
      resolve({
        stdout: "",
        stderr: error.message,
        exitCode: 1,
        timedOut,
      })
    })
    proc.on("close", (code, signal) => {
      if (signal === "SIGTERM") timedOut = true
      resolve({
        stdout: Buffer.concat(out).toString("utf-8"),
        stderr: Buffer.concat(err).toString("utf-8"),
        exitCode: code ?? 1,
        timedOut,
      })
    })
  })
}

export async function executeExecCommand(
  params: ExecuteExecCommandInput,
  ctx: Tool.Context,
  alias?: ExecCommandAlias,
): Promise<ExecuteExecCommandResult> {
  const command = params.argv.join(" ")
  const scopeTargets = enforceExecCommandScope(ctx.sessionID, params)
  const approval = alias ?? {
    permission: "exec_command",
    patterns: [command],
    always: [],
    metadata: {
      command,
      description: params.description ?? "",
    } as Record<string, any>,
  }
  const patterns = scopeTargets.length > 0 ? scopeTargets : approval.patterns
  await ctx.ask({
    permission: approval.permission,
    patterns,
    always: approval.always,
    metadata: {
      ...approval.metadata,
      scope_targets: scopeTargets,
    } as Record<string, any>,
  })

  const timeout = params.timeout ?? 120000
  const start = Date.now()

  const result = await runExecCommand({
    argv: params.argv,
    cwd: params.cwd,
    timeout,
    env: params.env_allowlist,
  })

  return {
    command,
    elapsed: Date.now() - start,
    result,
  }
}

export const ExecCommandTool = Tool.define("exec_command", {
  description: DESCRIPTION,
  parameters: z.object({
    argv: z.array(z.string()).min(1).describe("Executable and arguments"),
    cwd: z.string().optional().describe("Working directory"),
    env_allowlist: z.record(z.string(), z.string()).optional().describe("Environment overrides"),
    timeout: z.number().min(1).max(600000).optional().describe("Timeout in milliseconds"),
    description: z.string().optional().describe("Short command intent"),
    scope_targets: z
      .array(z.string())
      .optional()
      .describe("Explicit target URLs/hosts when the command does not contain literal http(s) URLs"),
  }),
  async execute(params, ctx) {
    const execution = await executeExecCommand({
      argv: params.argv,
      cwd: params.cwd,
      env_allowlist: params.env_allowlist,
      timeout: params.timeout,
      description: params.description,
      scope_targets: params.scope_targets,
    }, ctx)

    const stdout = execution.result.stdout.length > 10000
      ? `${execution.result.stdout.slice(0, 10000)}\n... (truncated)`
      : execution.result.stdout
    const stderr = execution.result.stderr.length > 5000
      ? `${execution.result.stderr.slice(0, 5000)}\n... (truncated)`
      : execution.result.stderr
    const lines: string[] = []
    if (stdout) {
      lines.push("── stdout ──")
      lines.push(stdout)
    }
    if (stderr) {
      lines.push("── stderr ──")
      lines.push(stderr)
    }
    lines.push(`Exit code: ${execution.result.exitCode}`)
    lines.push(`Elapsed: ${execution.elapsed}ms`)
    if (execution.result.timedOut) {
      lines.push("Timeout reached")
    }

    const baseEnvelope = makeToolResultEnvelope({
      status: execution.result.exitCode === 0 ? "ok" : execution.result.timedOut ? "timeout" : "inconclusive",
      artifacts: [
        {
          type: "process_result",
          argv: params.argv,
          exit_code: execution.result.exitCode,
          elapsed_ms: execution.elapsed,
          timed_out: execution.result.timedOut,
        },
      ],
      metrics: {
        elapsed_ms: execution.elapsed,
        exit_code: execution.result.exitCode,
        stdout_bytes: execution.result.stdout.length,
        stderr_bytes: execution.result.stderr.length,
      },
    })
    const manualEnvelope = manualCommandEnvelope({
      tool: "exec_command",
      command: params.argv.join(" "),
      output: `${execution.result.stdout}\n${execution.result.stderr}`.trim(),
      exitCode: execution.result.exitCode,
    })

    return {
      title: params.description ?? `exec_command: ${params.argv[0]}`,
      metadata: {
        exitCode: execution.result.exitCode,
        elapsed: execution.elapsed,
        timedOut: execution.result.timedOut,
        stdoutLength: execution.result.stdout.length,
        stderrLength: execution.result.stderr.length,
      } as any,
      envelope: manualEnvelope ? mergeToolEnvelopes(baseEnvelope, manualEnvelope) : baseEnvelope,
      output: lines.join("\n"),
    }
  },
})
