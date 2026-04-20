// numasec benchmark runner.
//
// Usage:
//   bun run script/bench/run.ts --scenario pwn
//
// Scenarios: web-surface | appsec-triage | pwn
//
// Boots a headless numasec server (src/index.ts serve), opens a session in a
// disposable workspace, sends the scenario's slash command via the public HTTP
// API, collects artifacts from the operation directory, scores them with
// rubric.ts, and writes bench-results-<ts>.json to the package root.

import { spawn, type ChildProcess } from "node:child_process"
import { mkdirSync, writeFileSync, readdirSync, readFileSync, existsSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { provision, teardown, type Fixture } from "./provision-juiceshop"
import { scoreFor, type Score } from "./rubric"

type Scenario = "web-surface" | "appsec-triage" | "pwn"

const SCENARIOS: Scenario[] = ["web-surface", "appsec-triage", "pwn"]

function parseArgs(argv: string[]): { scenario: Scenario } {
  const i = argv.indexOf("--scenario")
  const v = i >= 0 ? argv[i + 1] : undefined
  if (!v || !SCENARIOS.includes(v as Scenario)) {
    throw new Error(`--scenario required, one of: ${SCENARIOS.join(", ")}`)
  }
  return { scenario: v as Scenario }
}

async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(1500) })
      if (r.ok || r.status < 500) return
    } catch {}
    await new Promise((r) => setTimeout(r, 1000))
  }
  throw new Error(`timeout waiting for ${url}`)
}

async function startServer(workspace: string): Promise<{ proc: ChildProcess; baseUrl: string }> {
  const port = 4100 + Math.floor(Math.random() * 800)
  const entry = join(import.meta.dir, "..", "..", "src", "index.ts")
  const proc = spawn("bun", ["run", entry, "serve", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: workspace,
    env: { ...process.env, NUMASEC_CONFIG_CONTENT: process.env.NUMASEC_CONFIG_CONTENT ?? "{}" },
    stdio: ["ignore", "pipe", "pipe"],
  })
  proc.stdout?.on("data", (b) => process.stdout.write(`[server] ${b}`))
  proc.stderr?.on("data", (b) => process.stderr.write(`[server] ${b}`))
  const baseUrl = `http://127.0.0.1:${port}`
  await waitForHttp(`${baseUrl}/app`, 20_000).catch(() => waitForHttp(`${baseUrl}/`, 5_000))
  return { proc, baseUrl }
}

function stopServer(proc: ChildProcess): void {
  try { proc.kill("SIGTERM") } catch {}
  setTimeout(() => { try { proc.kill("SIGKILL") } catch {} }, 2000).unref()
}

type CreatedSession = { id: string }

async function createSession(baseUrl: string, directory: string): Promise<CreatedSession> {
  const r = await fetch(`${baseUrl}/session?directory=${encodeURIComponent(directory)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  })
  if (!r.ok) throw new Error(`session create failed: ${r.status} ${await r.text()}`)
  const j = (await r.json()) as { id: string }
  return { id: j.id }
}

function scenarioCommand(scenario: Scenario, target: string): { command: string; arguments: string } {
  if (scenario === "pwn") return { command: "pwn", arguments: target }
  if (scenario === "web-surface") return { command: "play", arguments: `web-surface ${target}` }
  if (scenario === "appsec-triage") return { command: "play", arguments: `appsec-triage ${target}` }
  throw new Error(`unknown scenario: ${scenario}`)
}

type CommandResult = { ok: boolean; raw: unknown; error?: string }

async function runCommand(
  baseUrl: string,
  sessionID: string,
  directory: string,
  command: string,
  args: string,
): Promise<CommandResult> {
  try {
    const r = await fetch(
      `${baseUrl}/session/${sessionID}/command?directory=${encodeURIComponent(directory)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command, arguments: args }),
      },
    )
    const body = await r.text()
    if (!r.ok) return { ok: false, raw: body, error: `${r.status}: ${body.slice(0, 500)}` }
    return { ok: true, raw: JSON.parse(body) }
  } catch (e) {
    return { ok: false, raw: null, error: e instanceof Error ? e.message : String(e) }
  }
}

function collectArtifacts(workspace: string): {
  corpus: string
  slug?: string
  observations: number
} {
  const opsDir = join(workspace, ".numasec", "operation")
  if (!existsSync(opsDir)) return { corpus: "", observations: 0 }
  const slugs = readdirSync(opsDir, { withFileTypes: true }).filter((d) => d.isDirectory())
  let corpus = ""
  let observations = 0
  let slug: string | undefined
  for (const s of slugs) {
    slug ??= s.name
    const sdir = join(opsDir, s.name)
    const md = join(sdir, "numasec.md")
    if (existsSync(md)) corpus += "\n\n" + readFileSync(md, "utf8")
    const evidence = join(sdir, "evidence")
    if (existsSync(evidence)) {
      const files = readdirSync(evidence, { withFileTypes: true }).filter((f) => f.isFile())
      observations += files.length
      for (const f of files.slice(0, 50)) {
        try { corpus += "\n\n" + readFileSync(join(evidence, f.name), "utf8") } catch {}
      }
    }
  }
  return { corpus, slug, observations }
}

function extractAssistantText(raw: unknown): string {
  if (!raw || typeof raw !== "object") return ""
  const r = raw as { parts?: Array<{ type?: string; text?: string }> }
  return (r.parts ?? [])
    .filter((p) => p.type === "text" && typeof p.text === "string")
    .map((p) => p.text!)
    .join("\n")
}

async function main() {
  const { scenario } = parseArgs(process.argv.slice(2))
  const target = `http://localhost:3000`

  const ts = Date.now()
  const pkgRoot = join(import.meta.dir, "..", "..")
  const workspace = join(tmpdir(), `numasec-bench-ws-${ts}`)
  mkdirSync(workspace, { recursive: true })

  let fx: Fixture | null = null
  let server: { proc: ChildProcess; baseUrl: string } | null = null
  const startedAt = new Date().toISOString()
  let finalScore: Score | { scenario: string; score: number; max: number; checks: []; error: string }
  let commandResult: CommandResult = { ok: false, raw: null }
  let artifacts: { corpus: string; slug?: string; observations: number } = { corpus: "", observations: 0 }

  try {
    fx = await provision()
    console.log(`[bench] juice-shop ready on :${fx.port} (reused=${fx.reused})`)

    server = await startServer(workspace)
    console.log(`[bench] numasec server up on ${server.baseUrl}`)

    const { command, arguments: cmdArgs } = scenarioCommand(scenario, target)
    const session = await createSession(server.baseUrl, workspace)
    console.log(`[bench] session=${session.id} sending /${command} ${cmdArgs}`)

    commandResult = await runCommand(server.baseUrl, session.id, workspace, command, cmdArgs)
    if (!commandResult.ok) console.log(`[bench] command error: ${commandResult.error}`)

    artifacts = collectArtifacts(workspace)
    const assistantText = extractAssistantText(commandResult.raw)
    const corpus = artifacts.corpus + "\n\n" + assistantText
    finalScore = scoreFor(scenario, corpus, { slug: artifacts.slug, observations: artifacts.observations })
  } catch (err) {
    finalScore = {
      scenario,
      score: 0,
      max: 100,
      checks: [],
      error: err instanceof Error ? err.message : String(err),
    }
  } finally {
    if (server) stopServer(server.proc)
    if (fx) teardown(fx)
  }

  const out = {
    scenario,
    target,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    result: finalScore,
    operation_slug: artifacts.slug ?? null,
    observations: artifacts.observations,
    command_ok: commandResult.ok,
    command_error: commandResult.error ?? null,
  }

  const outPath = join(pkgRoot, `bench-results-${ts}.json`)
  writeFileSync(outPath, JSON.stringify(out, null, 2))
  console.log(`[bench] wrote ${outPath}`)
  console.log(`[bench] score: ${out.result.score}/${out.result.max}`)

  try { rmSync(workspace, { recursive: true, force: true }) } catch {}

  process.exit(0)
}

if (import.meta.main) {
  main().catch((e) => {
    console.error(e)
    process.exit(1)
  })
}
