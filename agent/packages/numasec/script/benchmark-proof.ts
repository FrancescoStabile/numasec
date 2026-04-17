#!/usr/bin/env bun

import fs from "fs/promises"
import os from "os"
import path from "path"
import pkg from "../package.json"
import { startSecurityTarget } from "../test/fixture/security-target"

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : "false"
  return ""
}

function bool(input: string) {
  return input === "true" || input === "1" || input === "yes"
}

function optional(name: string) {
  return process.env[name] ?? ""
}

function assign(env: Record<string, string>, name: string, value: string) {
  if (value === "") return
  env[name] = value
}

async function runText(cmd: string[]) {
  const proc = Bun.spawn({
    cmd,
    cwd: dir,
    stdout: "pipe",
    stderr: "pipe",
  })
  const out = await new Response(proc.stdout).text()
  await proc.exited
  return out.trim()
}

async function reachable(url: string) {
  try {
    const response = await fetch(url, { redirect: "manual" })
    return response.status > 0
  } catch {
    return false
  }
}

async function ensure(input: string) {
  await fs.mkdir(input, { recursive: true })
  return input
}

async function run(
  name: string,
  cmd: string[],
  env: Record<string, string>,
  root: string,
) {
  const stdoutPath = path.join(root, `${name}.stdout.log`)
  const stderrPath = path.join(root, `${name}.stderr.log`)
  const proc = Bun.spawn({
    cmd,
    cwd: dir,
    env: {
      ...process.env,
      ...env,
    },
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])
  await Promise.all([Bun.write(stdoutPath, stdout), Bun.write(stderrPath, stderr)])
  return {
    name,
    cmd: cmd.join(" "),
    exit_code: code,
    stdout_path: stdoutPath,
    stderr_path: stderrPath,
    stdout: stdout.trim(),
    stderr: stderr.trim(),
  }
}

function stamp() {
  return new Date().toISOString().replace(/[:.]/g, "-")
}

async function live(name: string, env: Record<string, string>, root: string) {
  const artifactPath = path.join(root, `runtime-live-${name}.json`)
  const runout = await run(
    `runtime-live-${name}`,
    ["bun", "run", "script/runtime-live.ts"],
    {
      ...env,
      NUMASEC_RUNTIME_LIVE_OUTPUT_PATH: artifactPath,
    },
    root,
  )
  const artifact = await Bun.file(artifactPath)
    .json()
    .catch(() => undefined)
  return {
    target: env.NUMASEC_RUNTIME_LIVE_URL,
    exit_code: runout.exit_code,
    stdout_path: runout.stdout_path,
    stderr_path: runout.stderr_path,
    artifact_path: artifactPath,
    summary: artifact,
  }
}

const dir = new URL("..", import.meta.url).pathname
const outputRoot =
  optional("NUMASEC_BENCHMARK_PROOF_DIR") || path.join(os.tmpdir(), `numasec-benchmark-proof-${stamp()}`)
const skipJuice = bool(optional("NUMASEC_BENCHMARK_PROOF_SKIP_JUICE"))
const requireJuice = bool(optional("NUMASEC_BENCHMARK_PROOF_REQUIRE_JUICE"))
const juiceUrl = optional("NUMASEC_BENCHMARK_PROOF_JUICE_URL") || "http://127.0.0.1:3000"
const extraName = optional("NUMASEC_BENCHMARK_PROOF_EXTRA_NAME")
const extraUrl = optional("NUMASEC_BENCHMARK_PROOF_EXTRA_URL")
const requireExtra = bool(optional("NUMASEC_BENCHMARK_PROOF_REQUIRE_EXTRA"))

await ensure(outputRoot)

const gitSha = await runText(["git", "--no-pager", "rev-parse", "HEAD"])
const gitBranch = await runText(["git", "--no-pager", "rev-parse", "--abbrev-ref", "HEAD"])
const gitStatus = await runText(["git", "--no-pager", "status", "--short"])

const proof: Record<string, unknown> = {
  generated_at: new Date().toISOString(),
  output_dir: outputRoot,
  git: {
    sha: gitSha,
    branch: gitBranch,
    dirty: gitStatus.length > 0,
  },
  runtime: {
    platform: process.platform,
    arch: process.arch,
    bun_version: Bun.version,
    node_version: process.version,
  },
  numasec: {
    package_version: pkg.version,
  },
  runs: {},
}

const runs = proof.runs as Record<string, unknown>

const evalRun = await run("runtime-eval", ["bun", "run", "script/runtime-eval.ts"], {}, outputRoot)
runs.runtime_eval = {
  exit_code: evalRun.exit_code,
  stdout_path: evalRun.stdout_path,
  stderr_path: evalRun.stderr_path,
}

const fixture = startSecurityTarget()
try {
  const fixtureRun = await live(
    "fixture",
    {
      NUMASEC_RUNTIME_LIVE_MODE: "generic",
      NUMASEC_RUNTIME_LIVE_URL: fixture.baseUrl,
      NUMASEC_RUNTIME_LIVE_BROWSER_URL: fixture.baseUrl,
      NUMASEC_RUNTIME_LIVE_LOGIN_URL: new URL("/rest/user/login", fixture.baseUrl).toString(),
      NUMASEC_RUNTIME_LIVE_LOGIN_EMAIL: fixture.admin.email,
      NUMASEC_RUNTIME_LIVE_LOGIN_PASSWORD: fixture.admin.password,
      NUMASEC_RUNTIME_LIVE_AUTH_CHECK_URL: new URL("/api/Projects", fixture.baseUrl).toString(),
    },
    outputRoot,
  )
  runs.live_fixture = {
    target: fixture.baseUrl,
    exit_code: fixtureRun.exit_code,
    stdout_path: fixtureRun.stdout_path,
    stderr_path: fixtureRun.stderr_path,
    artifact_path: fixtureRun.artifact_path,
    summary: fixtureRun.summary,
  }
} finally {
  fixture.stop()
}

if (skipJuice) {
  runs.live_juice = {
    status: "skipped",
    reason: "NUMASEC_BENCHMARK_PROOF_SKIP_JUICE=1",
  }
} else if (!(await reachable(juiceUrl))) {
  runs.live_juice = {
    status: "skipped",
    reason: `${juiceUrl} not reachable`,
  }
} else {
  const juiceRun = await live(
    "juice",
    {
      NUMASEC_RUNTIME_LIVE_MODE: "juice",
      NUMASEC_RUNTIME_LIVE_URL: juiceUrl,
      NUMASEC_RUNTIME_LIVE_BROWSER_URL: juiceUrl,
    },
    outputRoot,
  )
  runs.live_juice = {
    target: juiceUrl,
    exit_code: juiceRun.exit_code,
    stdout_path: juiceRun.stdout_path,
    stderr_path: juiceRun.stderr_path,
    artifact_path: juiceRun.artifact_path,
    summary: juiceRun.summary,
  }
}

const extraKey = extraName ? `live_${extraName}` : ""
if (extraName && !extraUrl) {
  runs[extraKey] = {
    status: "skipped",
    reason: "NUMASEC_BENCHMARK_PROOF_EXTRA_URL not set",
  }
} else if (extraName && !(await reachable(extraUrl))) {
  runs[extraKey] = {
    status: "skipped",
    reason: `${extraUrl} not reachable`,
  }
} else if (extraName && extraUrl) {
  const env: Record<string, string> = {
    NUMASEC_RUNTIME_LIVE_MODE: optional("NUMASEC_BENCHMARK_PROOF_EXTRA_MODE") || "generic",
    NUMASEC_RUNTIME_LIVE_URL: extraUrl,
    NUMASEC_RUNTIME_LIVE_BROWSER_URL: optional("NUMASEC_BENCHMARK_PROOF_EXTRA_BROWSER_URL") || extraUrl,
  }
  assign(env, "NUMASEC_RUNTIME_LIVE_ACTOR", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_ACTOR"))
  assign(env, "NUMASEC_RUNTIME_LIVE_SKIP_BROWSER", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_SKIP_BROWSER"))
  assign(env, "NUMASEC_RUNTIME_LIVE_BROWSER_STEPS", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_BROWSER_STEPS"))
  assign(env, "NUMASEC_RUNTIME_LIVE_LOGIN_URL", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_LOGIN_URL"))
  assign(env, "NUMASEC_RUNTIME_LIVE_LOGIN_IDENTITY", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_LOGIN_IDENTITY"))
  assign(env, "NUMASEC_RUNTIME_LIVE_LOGIN_PASSWORD", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_LOGIN_PASSWORD"))
  assign(env, "NUMASEC_RUNTIME_LIVE_LOGIN_METHOD", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_LOGIN_METHOD"))
  assign(env, "NUMASEC_RUNTIME_LIVE_LOGIN_BODY", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_LOGIN_BODY"))
  assign(env, "NUMASEC_RUNTIME_LIVE_LOGIN_HEADERS_JSON", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_LOGIN_HEADERS_JSON"))
  assign(env, "NUMASEC_RUNTIME_LIVE_LOGIN_FOLLOW_REDIRECTS", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_LOGIN_FOLLOW_REDIRECTS"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_URL", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_URL"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_FIRST", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_FIRST"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_IDENTITY", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_IDENTITY"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_PASSWORD", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_PASSWORD"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_METHOD", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_METHOD"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_BODY", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_BODY"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_HEADERS_JSON", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_HEADERS_JSON"))
  assign(env, "NUMASEC_RUNTIME_LIVE_REGISTER_FOLLOW_REDIRECTS", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_REGISTER_FOLLOW_REDIRECTS"))
  assign(env, "NUMASEC_RUNTIME_LIVE_AUTH_CHECK_URL", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_AUTH_CHECK_URL"))
  assign(env, "NUMASEC_RUNTIME_LIVE_AUTH_CHECK_METHOD", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_AUTH_CHECK_METHOD"))
  assign(env, "NUMASEC_RUNTIME_LIVE_AUTH_CHECK_BODY", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_AUTH_CHECK_BODY"))
  assign(env, "NUMASEC_RUNTIME_LIVE_AUTH_PROOF_SUBSTRING", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_AUTH_PROOF_SUBSTRING"))
  assign(env, "NUMASEC_RUNTIME_LIVE_WORKFLOW_URL", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_WORKFLOW_URL"))
  assign(env, "NUMASEC_RUNTIME_LIVE_RESOURCE_URL", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_RESOURCE_URL"))
  assign(env, "NUMASEC_RUNTIME_LIVE_WORKFLOW_METHOD", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_WORKFLOW_METHOD"))
  assign(env, "NUMASEC_RUNTIME_LIVE_WORKFLOW_BODY", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_WORKFLOW_BODY"))
  assign(env, "NUMASEC_RUNTIME_LIVE_ACTION_KIND", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_ACTION_KIND"))
  assign(env, "NUMASEC_RUNTIME_LIVE_TARGET_STATE", optional("NUMASEC_BENCHMARK_PROOF_EXTRA_TARGET_STATE"))
  runs[extraKey] = await live(extraName, env, outputRoot)
}

const failures: string[] = []
if (evalRun.exit_code !== 0) failures.push("runtime-eval failed")

const fixtureRun = runs.live_fixture as Record<string, unknown>
if (Number(fixtureRun.exit_code) !== 0) failures.push("runtime-live fixture failed")

const juiceRun = runs.live_juice as Record<string, unknown>
if (juiceRun.status === "skipped") {
  if (requireJuice) failures.push(text(juiceRun.reason) || "Juice Shop proof skipped")
} else if (Number(juiceRun.exit_code) !== 0) {
  failures.push("runtime-live juice failed")
}

if (requireExtra && !extraName) failures.push("extra benchmark proof not configured")

if (extraKey) {
  const extraRun = runs[extraKey] as Record<string, unknown>
  if (extraRun.status === "skipped") {
    if (requireExtra) failures.push(text(extraRun.reason) || `${extraName} proof skipped`)
  } else if (Number(extraRun.exit_code) !== 0) {
    failures.push(`runtime-live ${extraName} failed`)
  }
}

proof.status = failures.length === 0 ? "ok" : "failed"
proof.failures = failures

const proofPath = path.join(outputRoot, "benchmark-proof.json")
await Bun.write(proofPath, JSON.stringify(proof, null, 2))

console.log(
  [
    `benchmark_proof=${proofPath}`,
    `status=${text(proof.status)}`,
    `git_sha=${gitSha}`,
    `git_branch=${gitBranch}`,
    `worktree_dirty=${gitStatus.length > 0 ? "true" : "false"}`,
      `runtime_eval_exit=${evalRun.exit_code}`,
      `fixture_exit=${text(fixtureRun.exit_code)}`,
      `juice_status=${text(juiceRun.status) || `exit:${text(juiceRun.exit_code)}`}`,
      extraKey
        ? `${extraName}_status=${text((runs[extraKey] as Record<string, unknown>).status) || `exit:${text((runs[extraKey] as Record<string, unknown>).exit_code)}`}`
        : "",
    ].join("\n"),
  )

process.exit(failures.length === 0 ? 0 : 1)
