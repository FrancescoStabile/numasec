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
import { Cyber } from "../../src/core/cyber"
import { provision, teardown, type Fixture } from "./provision-juiceshop"
import { scoreFor, type Score } from "./rubric"

type Scenario = "web-surface" | "appsec-triage" | "pwn"

const SCENARIOS: Scenario[] = ["web-surface", "appsec-triage", "pwn"]
const BENCH_COMMAND_TIMEOUT_MS = 5 * 60_000
const PROVIDER_PREREQ_ENV = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "GOOGLE_GENERATIVE_AI_API_KEY",
  "GROQ_API_KEY",
  "XAI_API_KEY",
  "OPENROUTER_API_KEY",
  "AWS_PROFILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_ACCESS_KEY_ID",
  "AZURE_OPENAI_API_KEY",
]

function parseArgs(argv: string[]): { scenario: Scenario } {
  const i = argv.indexOf("--scenario")
  const v = i >= 0 ? argv[i + 1] : undefined
  if (!v || !SCENARIOS.includes(v as Scenario)) {
    throw new Error(`--scenario required, one of: ${SCENARIOS.join(", ")}`)
  }
  return { scenario: v as Scenario }
}

function hasProviderCredential() {
  return PROVIDER_PREREQ_ENV.some((name) => {
    const value = process.env[name]
    return typeof value === "string" && value.trim().length > 0
  })
}

function ensurePrerequisites() {
  if (!Bun.which("git")) throw new Error("benchmark prerequisite failed: git is not installed or not on PATH")
  if (!Bun.which("npm")) throw new Error("benchmark prerequisite failed: npm is not installed or not on PATH")
  if (!hasProviderCredential()) {
    throw new Error(
      `benchmark prerequisite failed: no provider credentials detected; set one of ${PROVIDER_PREREQ_ENV.join(", ")}`,
    )
  }
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
  if (scenario === "web-surface") return { command: "runbook", arguments: `web-surface ${target}` }
  if (scenario === "appsec-triage") return { command: "runbook", arguments: `appsec-triage ${target}` }
  throw new Error(`unknown scenario: ${scenario}`)
}

type CommandResult = { ok: boolean; raw: unknown; error?: string }
type BenchArtifacts = {
  corpus: string
  slug?: string
  observations: number
  observations_projected: number
  context_artifacts: number
  workflows: number
  completed_steps: number
  route_facts: number
  relations_projected: number
  workflow_step_statuses: number
  candidate_findings: number
  findings: number
  knowledge_queries: number
  identities: number
  active_identities: number
  deliverables: number
  tool_adapters_present: number
  tool_adapters_missing: number
  capsules: number
  executed_capsules: number
  recommended_capsules: number
  ready_capsules: number
  degraded_capsules: number
  unavailable_capsules: number
  ready_verticals: number
  degraded_verticals: number
  unavailable_verticals: number
  reportable_findings: number
  suspected_findings: number
  rejected_findings: number
  verified_findings: number
  evidence_backed_findings: number
  replay_backed_findings: number
  replay_exempt_findings: number
  operation_state_facts: number
  scope_policy_facts: number
  autonomy_policy_facts: number
}

async function runCommand(
  baseUrl: string,
  sessionID: string,
  directory: string,
  command: string,
  args: string,
): Promise<CommandResult> {
  try {
    const signal = AbortSignal.timeout(BENCH_COMMAND_TIMEOUT_MS)
    const r = await fetch(
      `${baseUrl}/session/${sessionID}/command?directory=${encodeURIComponent(directory)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command, arguments: args }),
        signal,
      },
    )
    const body = await r.text()
    if (!r.ok) return { ok: false, raw: body, error: `${r.status}: ${body.slice(0, 500)}` }
    return { ok: true, raw: JSON.parse(body) }
  } catch (e) {
    return { ok: false, raw: null, error: e instanceof Error ? e.message : String(e) }
  }
}

async function collectArtifacts(workspace: string): Promise<BenchArtifacts> {
  const opsDir = join(workspace, ".numasec", "operation")
  if (!existsSync(opsDir)) {
    return {
      corpus: "",
      observations: 0,
      observations_projected: 0,
      context_artifacts: 0,
      workflows: 0,
      completed_steps: 0,
      route_facts: 0,
      relations_projected: 0,
      workflow_step_statuses: 0,
      candidate_findings: 0,
      findings: 0,
      knowledge_queries: 0,
      identities: 0,
      active_identities: 0,
      deliverables: 0,
      tool_adapters_present: 0,
      tool_adapters_missing: 0,
      capsules: 0,
      executed_capsules: 0,
      recommended_capsules: 0,
      ready_capsules: 0,
      degraded_capsules: 0,
      unavailable_capsules: 0,
      ready_verticals: 0,
      degraded_verticals: 0,
      unavailable_verticals: 0,
      reportable_findings: 0,
      suspected_findings: 0,
      rejected_findings: 0,
      verified_findings: 0,
      evidence_backed_findings: 0,
      replay_backed_findings: 0,
      replay_exempt_findings: 0,
      operation_state_facts: 0,
      scope_policy_facts: 0,
      autonomy_policy_facts: 0,
    }
  }
  const slugs = readdirSync(opsDir, { withFileTypes: true }).filter((d) => d.isDirectory())
  let corpus = ""
  let observations = 0
  let observations_projected = 0
  let context_artifacts = 0
  let workflows = 0
  let completed_steps = 0
  let route_facts = 0
  let relations_projected = 0
  let workflow_step_statuses = 0
  let candidate_findings = 0
  let findings = 0
  let knowledge_queries = 0
  let identities = 0
  let active_identities = 0
  let deliverables = 0
  let tool_adapters_present = 0
  let tool_adapters_missing = 0
  let capsules = 0
  let executed_capsules = 0
  let recommended_capsules = 0
  let ready_capsules = 0
  let degraded_capsules = 0
  let unavailable_capsules = 0
  let ready_verticals = 0
  let degraded_verticals = 0
  let unavailable_verticals = 0
  let reportable_findings = 0
  let suspected_findings = 0
  let rejected_findings = 0
  let verified_findings = 0
  let evidence_backed_findings = 0
  let replay_backed_findings = 0
  let replay_exempt_findings = 0
  let operation_state_facts = 0
  let scope_policy_facts = 0
  let autonomy_policy_facts = 0
  let slug: string | undefined
  for (const s of slugs) {
    slug ??= s.name
    const sdir = join(opsDir, s.name)
    const activeContext = join(sdir, "context", "active-context.md")
    const md = join(sdir, "numasec.md")
    if (existsSync(activeContext)) {
      context_artifacts += 1
      corpus += "\n\n" + readFileSync(activeContext, "utf8")
    }
    else if (existsSync(md)) corpus += "\n\n" + readFileSync(md, "utf8")
    const evidence = join(sdir, "evidence")
    if (existsSync(evidence)) {
      const files = readdirSync(evidence, { withFileTypes: true }).filter((f) => f.isFile())
      observations += files.length
      for (const f of files.slice(0, 50)) {
        try { corpus += "\n\n" + readFileSync(join(evidence, f.name), "utf8") } catch {}
      }
    }
    const workflow = join(sdir, "workflow")
    if (existsSync(workflow)) {
      const files = readdirSync(workflow, { withFileTypes: true }).filter((f) => f.isFile() && f.name.endsWith(".json"))
      workflows += files.length
      for (const f of files.slice(0, 20)) {
        try {
          const raw = readFileSync(join(workflow, f.name), "utf8")
          corpus += "\n\n" + raw
          const parsed = JSON.parse(raw) as { completed_steps?: number }
          completed_steps += Number(parsed.completed_steps ?? 0)
        } catch {}
      }
    }
    const cyberDir = join(sdir, "cyber")
    if (existsSync(cyberDir)) {
      const projected = await Cyber.readProjectedState(workspace, s.name)
      route_facts += projected.summary.route_facts
      relations_projected += projected.relations.length
      observations_projected += projected.summary.observations_projected
      workflow_step_statuses += projected.summary.workflow_step_statuses
      candidate_findings += projected.summary.candidate_findings
      findings += projected.summary.findings
      knowledge_queries += projected.summary.knowledge_queries
      identities += projected.summary.identities
      active_identities += projected.summary.active_identities
      deliverables += projected.summary.deliverables
      tool_adapters_present += projected.summary.tool_adapters_present
      tool_adapters_missing += projected.summary.tool_adapters_missing
      capsules += projected.summary.ready_capsules + projected.summary.degraded_capsules + projected.summary.unavailable_capsules
      executed_capsules += projected.summary.executed_capsules
      recommended_capsules += projected.summary.recommended_capsules
      ready_capsules += projected.summary.ready_capsules
      degraded_capsules += projected.summary.degraded_capsules
      unavailable_capsules += projected.summary.unavailable_capsules
      ready_verticals += projected.summary.ready_verticals
      degraded_verticals += projected.summary.degraded_verticals
      unavailable_verticals += projected.summary.unavailable_verticals
      reportable_findings += projected.summary.reportable_findings
      suspected_findings += projected.summary.suspected_findings
      rejected_findings += projected.summary.rejected_findings
      verified_findings += projected.summary.verified_findings
      evidence_backed_findings += projected.summary.evidence_backed_findings
      replay_backed_findings += projected.summary.replay_backed_findings
      replay_exempt_findings += projected.summary.replay_exempt_findings
      operation_state_facts += projected.operation_state ? 1 : 0
      scope_policy_facts += projected.scope_policy ? 1 : 0
      autonomy_policy_facts += projected.autonomy_policy ? 1 : 0
      corpus += "\n\n" + JSON.stringify({
        findings: projected.findings,
        knowledge: projected.knowledge,
        identities: projected.identities,
        deliverables: projected.deliverables,
        tool_adapters: projected.tool_adapters,
        capsules: projected.capsules,
        verticals: projected.verticals,
        observations: projected.observations,
        workflows: projected.workflows,
        workflow_steps: projected.workflow_steps,
        relations: projected.relations,
        timeline: projected.timeline,
        summary: projected.summary,
        operation_state: projected.operation_state,
        scope_policy: projected.scope_policy,
        autonomy_policy: projected.autonomy_policy,
      })
    }
  }
  return {
    corpus,
    slug,
    observations,
    observations_projected,
    context_artifacts,
    workflows,
    completed_steps,
    route_facts,
    relations_projected,
    workflow_step_statuses,
    candidate_findings,
    findings,
    knowledge_queries,
    identities,
    active_identities,
    deliverables,
    tool_adapters_present,
    tool_adapters_missing,
    capsules,
    executed_capsules,
    recommended_capsules,
    ready_capsules,
    degraded_capsules,
    unavailable_capsules,
    ready_verticals,
    degraded_verticals,
    unavailable_verticals,
    reportable_findings,
    suspected_findings,
    rejected_findings,
    verified_findings,
    evidence_backed_findings,
    replay_backed_findings,
    replay_exempt_findings,
    operation_state_facts,
    scope_policy_facts,
    autonomy_policy_facts,
  }
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
  let artifacts: BenchArtifacts = {
    corpus: "",
    observations: 0,
    observations_projected: 0,
    context_artifacts: 0,
    workflows: 0,
    completed_steps: 0,
    route_facts: 0,
    relations_projected: 0,
    workflow_step_statuses: 0,
    candidate_findings: 0,
    findings: 0,
    knowledge_queries: 0,
    identities: 0,
    active_identities: 0,
    deliverables: 0,
    tool_adapters_present: 0,
    tool_adapters_missing: 0,
    capsules: 0,
    executed_capsules: 0,
    recommended_capsules: 0,
    ready_capsules: 0,
    degraded_capsules: 0,
    unavailable_capsules: 0,
    ready_verticals: 0,
    degraded_verticals: 0,
    unavailable_verticals: 0,
    reportable_findings: 0,
    suspected_findings: 0,
    rejected_findings: 0,
    verified_findings: 0,
    evidence_backed_findings: 0,
    replay_backed_findings: 0,
    replay_exempt_findings: 0,
    operation_state_facts: 0,
    scope_policy_facts: 0,
    autonomy_policy_facts: 0,
  }

  try {
    ensurePrerequisites()
    fx = await provision()
    console.log(`[bench] juice-shop ready on :${fx.port} (reused=${fx.reused})`)

    server = await startServer(workspace)
    console.log(`[bench] numasec server up on ${server.baseUrl}`)

    const { command, arguments: cmdArgs } = scenarioCommand(scenario, target)
    const session = await createSession(server.baseUrl, workspace)
    console.log(`[bench] session=${session.id} sending /${command} ${cmdArgs}`)

    commandResult = await runCommand(server.baseUrl, session.id, workspace, command, cmdArgs)
    if (!commandResult.ok) console.log(`[bench] command error: ${commandResult.error}`)
    else {
      const reportResult = await runCommand(server.baseUrl, session.id, workspace, "report", "build")
      if (!reportResult.ok) console.log(`[bench] report build error: ${reportResult.error}`)
    }

    artifacts = await collectArtifacts(workspace)
    const assistantText = extractAssistantText(commandResult.raw)
    const corpus = artifacts.corpus + "\n\n" + assistantText
    finalScore = scoreFor(scenario, corpus, {
      slug: artifacts.slug,
      observations: artifacts.observations,
      observations_projected: artifacts.observations_projected,
      context_artifacts: artifacts.context_artifacts,
      workflows: artifacts.workflows,
      completed_steps: artifacts.completed_steps,
      route_facts: artifacts.route_facts,
      relations_projected: artifacts.relations_projected,
      workflow_step_statuses: artifacts.workflow_step_statuses,
      candidate_findings: artifacts.candidate_findings,
      findings: artifacts.findings,
      knowledge_queries: artifacts.knowledge_queries,
      identities: artifacts.identities,
      active_identities: artifacts.active_identities,
      deliverables: artifacts.deliverables,
      tool_adapters_present: artifacts.tool_adapters_present,
      tool_adapters_missing: artifacts.tool_adapters_missing,
      capsules: artifacts.capsules,
      executed_capsules: artifacts.executed_capsules,
      recommended_capsules: artifacts.recommended_capsules,
      ready_capsules: artifacts.ready_capsules,
      degraded_capsules: artifacts.degraded_capsules,
      unavailable_capsules: artifacts.unavailable_capsules,
      ready_verticals: artifacts.ready_verticals,
      degraded_verticals: artifacts.degraded_verticals,
      unavailable_verticals: artifacts.unavailable_verticals,
      reportable_findings: artifacts.reportable_findings,
      suspected_findings: artifacts.suspected_findings,
      rejected_findings: artifacts.rejected_findings,
      verified_findings: artifacts.verified_findings,
      evidence_backed_findings: artifacts.evidence_backed_findings,
      replay_backed_findings: artifacts.replay_backed_findings,
      replay_exempt_findings: artifacts.replay_exempt_findings,
      operation_state_facts: artifacts.operation_state_facts,
      scope_policy_facts: artifacts.scope_policy_facts,
      autonomy_policy_facts: artifacts.autonomy_policy_facts,
    })
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
    observations_projected: artifacts.observations_projected,
    context_artifacts: artifacts.context_artifacts,
    workflows: artifacts.workflows,
    completed_steps: artifacts.completed_steps,
    route_facts: artifacts.route_facts,
    workflow_step_statuses: artifacts.workflow_step_statuses,
    candidate_findings: artifacts.candidate_findings,
    findings: artifacts.findings,
    knowledge_queries: artifacts.knowledge_queries,
    identities: artifacts.identities,
    active_identities: artifacts.active_identities,
    deliverables: artifacts.deliverables,
    tool_adapters_present: artifacts.tool_adapters_present,
    tool_adapters_missing: artifacts.tool_adapters_missing,
    capsules: artifacts.capsules,
    executed_capsules: artifacts.executed_capsules,
    recommended_capsules: artifacts.recommended_capsules,
    ready_capsules: artifacts.ready_capsules,
    degraded_capsules: artifacts.degraded_capsules,
    unavailable_capsules: artifacts.unavailable_capsules,
    ready_verticals: artifacts.ready_verticals,
    degraded_verticals: artifacts.degraded_verticals,
    unavailable_verticals: artifacts.unavailable_verticals,
    reportable_findings: artifacts.reportable_findings,
    suspected_findings: artifacts.suspected_findings,
    rejected_findings: artifacts.rejected_findings,
    verified_findings: artifacts.verified_findings,
    evidence_backed_findings: artifacts.evidence_backed_findings,
    replay_backed_findings: artifacts.replay_backed_findings,
    replay_exempt_findings: artifacts.replay_exempt_findings,
    operation_state_facts: artifacts.operation_state_facts,
    scope_policy_facts: artifacts.scope_policy_facts,
    autonomy_policy_facts: artifacts.autonomy_policy_facts,
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
