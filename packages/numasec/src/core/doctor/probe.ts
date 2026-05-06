import { Effect } from "effect"
import { access, constants, stat } from "fs/promises"
import path from "path"
import os from "os"
import { BINARIES } from "./catalog"
import { evaluateCapabilitySurface, type CapabilityReadiness, type CapabilitySurface } from "./readiness"

export type BinaryReport = { name: string; present: boolean; path?: string; version?: string }
export type VaultReport = { present: boolean; path: string; mode?: string }
export type KnowledgeBrokerReport = {
  live_sources: string[]
  local_sources: string[]
  cache_path: string
  api_keys_required: boolean
}
export type WorkspaceReport = { path: string; writable: boolean }
export type BrowserReport = { present: boolean; executable?: string; reason?: string }
export type BrowserRuntimeDriver = {
  chromium: {
    executablePath(): string
    launch(options: { headless: boolean }): Promise<{ close(): Promise<void> | void }>
  }
}

export type Report = {
  runtime: { bun?: string; node: string }
  os: { platform: NodeJS.Platform; arch: string; release: string }
  binaries: BinaryReport[]
  browser: BrowserReport
  knowledge: KnowledgeBrokerReport
  vault: VaultReport
  workspace: WorkspaceReport
  capability: CapabilitySurface
}

const BROWSER_INSTALL_HINT = "Playwright unavailable. Run: bun add playwright && npx playwright install chromium"
const BROWSER_LAUNCH_TIMEOUT_MS = 10_000
const BROWSER_FALLBACK_TIMEOUT_MS = 5_000
let browserRuntimeCache: { result: Promise<BrowserReport>; at: number } | undefined

const VERSION_TIMEOUT_MS = 500

const whichOf = (name: string): string | null => {
  const fn = (Bun as unknown as { which?: (n: string) => string | null }).which
  return typeof fn === "function" ? fn(name) : null
}

const CHROMIUM_SYSTEM_NAMES = ["chromium", "chromium-browser", "google-chrome", "chrome"] as const

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}

async function probeVersion(bin: string): Promise<string | undefined> {
  try {
    const proc = Bun.spawn([bin, "--version"], {
      stdout: "pipe",
      stderr: "pipe",
      timeout: VERSION_TIMEOUT_MS,
    })
    const [out, err] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ])
    await proc.exited
    const raw = (out || err).trim()
    if (!raw) return undefined
    const first = raw.split(/\r?\n/)[0].trim()
    return first.length > 120 ? first.slice(0, 120) : first
  } catch {
    return undefined
  }
}

async function probeBinary(name: string): Promise<BinaryReport> {
  const found = whichOf(name)
  if (!found) return { name, present: false }
  const version = await probeVersion(name)
  return { name, present: true, path: found, version }
}

async function probeVault(): Promise<VaultReport> {
  const p = path.join(os.homedir(), ".config", "numasec", "vault.json")
  try {
    const s = await stat(p)
    const mode = (s.mode & 0o777).toString(8).padStart(3, "0")
    return { present: true, path: p, mode }
  } catch {
    return { present: false, path: p }
  }
}

function probeKnowledge(workspace: string): KnowledgeBrokerReport {
  return {
    live_sources: ["NVD", "CISA KEV", "FIRST EPSS", "OSV", "GitHub Security Advisories"],
    local_sources: ["numasec methodology", "curated tradecraft", "searchsploit", "nuclei templates", "installed tool help"],
    cache_path: path.join(workspace, ".numasec", "knowledge-cache"),
    api_keys_required: false,
  }
}

async function probeWorkspace(workspace: string): Promise<WorkspaceReport> {
  try {
    await access(workspace, constants.W_OK)
    return { path: workspace, writable: true }
  } catch {
    return { path: workspace, writable: false }
  }
}

function browserUnavailable(reason?: string): BrowserReport {
  return {
    present: false,
    reason: reason ?? BROWSER_INSTALL_HINT,
  }
}

async function findSystemChromium(): Promise<string | null> {
  const envPath = process.env.NUMASEC_CHROMIUM_PATH
  if (envPath) {
    try {
      await access(envPath, constants.X_OK)
      return envPath
    } catch {
      return null
    }
  }
  for (const name of CHROMIUM_SYSTEM_NAMES) {
    const found = whichOf(name)
    if (found) return found
  }
  return null
}

async function tryLaunchWithDriver(
  driver: BrowserRuntimeDriver,
  timeoutMs: number,
  executablePath?: string,
): Promise<{ close(): Promise<void> | void }> {
  const launchOpts: any = { headless: true }
  if (executablePath) launchOpts.executablePath = executablePath
  if (process.platform === "win32" && typeof globalThis.Bun !== "undefined") {
    launchOpts.headless = false
    launchOpts.args = ["--headless=new"]
  }
  const launchPromise = driver.chromium.launch(launchOpts)
  const result = await Promise.race([
    launchPromise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("browser launch timed out")), timeoutMs),
    ),
  ])
  return result
}

async function tryResolveExecutable(driver: BrowserRuntimeDriver): Promise<string> {
  const executable = driver.chromium.executablePath()
  await access(executable, constants.X_OK)
  return executable
}

export async function evaluateBrowserRuntime(driver: BrowserRuntimeDriver): Promise<BrowserReport> {
  // First try Playwright's managed Chromium
  let firstError: string | undefined
  try {
    const executable = await tryResolveExecutable(driver)
    const browser = await tryLaunchWithDriver(driver, BROWSER_LAUNCH_TIMEOUT_MS)
    await browser.close()
    return { present: true, executable }
  } catch (err) {
    firstError = errorMessage(err)
  }

  // Fallback: system Chromium via env var or PATH — shorter timeout since it's secondary
  try {
    const systemPath = await findSystemChromium()
    if (systemPath) {
      const browser = await tryLaunchWithDriver(driver, BROWSER_FALLBACK_TIMEOUT_MS, systemPath)
      await browser.close()
      return { present: true, executable: systemPath }
    }
  } catch (err) {
    // system chromium found but failed to launch
  }

  const pathHint = process.env.NUMASEC_CHROMIUM_PATH
    ? ` | Tried NUMASEC_CHROMIUM_PATH=${process.env.NUMASEC_CHROMIUM_PATH}`
    : ""
  return browserUnavailable(`${BROWSER_INSTALL_HINT} — ${firstError ?? "unknown error"}${pathHint}`)
}

async function probeBrowserRuntime(workspace: string): Promise<BrowserReport> {
  const now = Date.now()
  if (browserRuntimeCache && now - browserRuntimeCache.at < 30_000) return browserRuntimeCache.result

  const result = (async (): Promise<BrowserReport> => {
    // Try Playwright's built-in import (works in dev mode)
    let driver: BrowserRuntimeDriver | undefined
    try {
      driver = await import("playwright")
    } catch {
      // import failed — not installed or bundled CI path issue
    }

    // In compiled binaries, import may succeed but chromium is undefined.
    // Try local filesystem fallback via createRequire.
    if (!driver?.chromium?.launch) {
      try {
        const { createRequire } = await import("module")
        const require = createRequire(path.join(workspace, "package.json"))
        driver = require("playwright") as BrowserRuntimeDriver
      } catch {
        // local filesystem fallback also failed
      }
    }

    if (driver?.chromium?.launch) {
      try {
        return await evaluateBrowserRuntime(driver)
      } catch (err) {
        return browserUnavailable(`${BROWSER_INSTALL_HINT} — ${err instanceof Error ? err.message : String(err)}`)
      }
    }

    // Playwright unavailable — fallback: detect Chromium on the system
    const systemPath = await findSystemChromium()
    if (systemPath) {
      try {
        const proc = Bun.spawn([systemPath, "--version"], {
          stdout: "pipe",
          stderr: "pipe",
          timeout: BROWSER_LAUNCH_TIMEOUT_MS,
        })
        const output = await new Response(proc.stdout).text()
        await proc.exited
        if (proc.exitCode === 0 && output.trim()) {
          return {
            present: true,
            executable: systemPath,
            reason: output.trim().split("\n")[0],
          }
        }
      } catch {
        // binary exists but can't run (missing deps, etc.)
      }
      return {
        present: true,
        executable: systemPath,
        reason: "Found on system but Playwright can't load (bundled binary). Set NUMASEC_CHROMIUM_PATH and install playwright locally: bun add playwright",
      }
    }

    return browserUnavailable(BROWSER_INSTALL_HINT)
  })()

  browserRuntimeCache = { result, at: now }
  return result
}

function renderCapabilityLine(item: CapabilityReadiness) {
  const mark = item.status === "ready" ? "✓" : item.status === "degraded" ? "~" : "x"
  const missing = [...item.missing_required, ...item.missing_optional]

  if (missing.length === 0) return `- ${mark} ${item.label}`
  return `- ${mark} ${item.label} — missing ${missing.join(", ")}`
}

export function probe(workspace: string = process.cwd()): Effect.Effect<Report> {
  return Effect.promise(async () => {
    const binaries = await Promise.all(BINARIES.map((item) => probeBinary(item.name)))
    const [browser, vault, ws] = await Promise.all([
      probeBrowserRuntime(workspace).catch(
        (err): BrowserReport =>
          browserUnavailable(`${BROWSER_INSTALL_HINT} — ${err instanceof Error ? err.message : String(err)}`),
      ),
      probeVault(),
      probeWorkspace(workspace),
    ])
    const knowledge = probeKnowledge(workspace)
    const bunVersion = (globalThis as unknown as { Bun?: { version?: string } }).Bun?.version
    const present = new Set(binaries.filter((item) => item.present).map((item) => item.name))
    return {
      runtime: { bun: bunVersion, node: process.versions.node },
      os: { platform: process.platform, arch: process.arch, release: os.release() },
      binaries,
      browser,
      knowledge,
      vault,
      workspace: ws,
      capability: evaluateCapabilitySurface({ binaries: present, browser_present: browser.present }),
    }
  })
}

export async function probePromise(workspace?: string): Promise<Report> {
  return Effect.runPromise(probe(workspace))
}

export function format(report: Report): string {
  const lines: string[] = []
  lines.push("# numasec doctor")
  lines.push("")
  lines.push("## runtime")
  lines.push(`- node ${report.runtime.node}${report.runtime.bun ? ` · bun ${report.runtime.bun}` : ""}`)
  lines.push(`- os ${report.os.platform}/${report.os.arch} (${report.os.release})`)
  lines.push("")
  lines.push("## binaries")
  for (const b of report.binaries) {
    const mark = b.present ? "✓" : "·"
    const suffix = b.present ? ` — ${b.version ?? b.path ?? ""}`.trimEnd() : " — not installed"
    lines.push(`- ${mark} ${b.name}${suffix}`)
  }
  lines.push("")
  lines.push("## browser")
  lines.push(
    report.browser.present
      ? `- present · ${report.browser.executable ?? "playwright chromium"}`
      : `- unavailable · ${report.browser.reason}`,
  )
  lines.push("")
  lines.push("## play readiness")
  for (const item of report.capability.plays) lines.push(renderCapabilityLine(item))
  lines.push("")
  lines.push("## vertical readiness")
  for (const item of report.capability.verticals) lines.push(renderCapabilityLine(item))
  lines.push("")
  lines.push("## workspace")
  lines.push(`- ${report.workspace.writable ? "writable" : "NOT writable"} · ${report.workspace.path}`)
  lines.push("")
  lines.push("## vault")
  if (report.vault.present) lines.push(`- present · mode ${report.vault.mode} · ${report.vault.path}`)
  else lines.push(`- not configured (${report.vault.path})`)
  lines.push("")
  lines.push("## knowledge broker")
  lines.push(`- live no-key sources · ${report.knowledge.live_sources.join(", ")}`)
  lines.push(`- local sources · ${report.knowledge.local_sources.join(", ")}`)
  lines.push(`- cache · ${report.knowledge.cache_path}`)
  lines.push(`- api keys required · ${report.knowledge.api_keys_required ? "yes" : "no"}`)
  return lines.join("\n")
}
