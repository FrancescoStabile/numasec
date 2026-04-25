import { Effect } from "effect"
import { access, constants, stat } from "fs/promises"
import path from "path"
import os from "os"
import { BINARIES } from "./catalog"
import { evaluateCapabilitySurface, type CapabilityReadiness, type CapabilitySurface } from "./readiness"

export type BinaryReport = { name: string; present: boolean; path?: string; version?: string }
export type VaultReport = { present: boolean; path: string; mode?: string }
export type CveReport = { present: boolean; path: string }
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
  cve: CveReport
  vault: VaultReport
  workspace: WorkspaceReport
  capability: CapabilitySurface
}

const BROWSER_INSTALL_HINT = "Playwright unavailable. Run: bun add playwright && npx playwright install chromium"
let browserRuntime: Promise<BrowserReport> | undefined

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

async function probeCve(workspace: string): Promise<CveReport> {
  const p = path.join(workspace, "assets", "cve", "latest.json")
  try {
    await access(p, constants.R_OK)
    return { present: true, path: p }
  } catch {
    return { present: false, path: p }
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
  executablePath?: string,
): Promise<{ close(): Promise<void> | void }> {
  if (executablePath) {
    return driver.chromium.launch({ headless: true, executablePath } as Parameters<typeof driver.chromium.launch>[0])
  }
  return driver.chromium.launch({ headless: true })
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
    const browser = await tryLaunchWithDriver(driver)
    await browser.close()
    return { present: true, executable }
  } catch (err) {
    firstError = errorMessage(err)
  }

  // Fallback: system Chromium via env var or PATH
  try {
    const systemPath = await findSystemChromium()
    if (systemPath) {
      const browser = await tryLaunchWithDriver(driver, systemPath)
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

async function probeBrowserRuntime(): Promise<BrowserReport> {
  browserRuntime ??= (async () => {
    // Try Playwright's built-in import (works in dev mode)
    try {
      return await evaluateBrowserRuntime(await import("playwright"))
    } catch (pwErr) {
      // Playwright import failed — common in compiled binaries due to
      // Bun bundling CI paths into playwright-core's require.resolve calls.
      // Fallback: detect Chromium on the system without needing playwright.

      // Check NUMASEC_CHROMIUM_PATH env var first, then system PATH
      const systemPath = await findSystemChromium()
      if (systemPath) {
        // Verify the binary actually runs
        try {
          const proc = Bun.spawn([systemPath, "--version"], { stdout: "pipe", stderr: "pipe" })
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

      return browserUnavailable(`${BROWSER_INSTALL_HINT} — ${errorMessage(pwErr)}`)
    }
  })()

  return browserRuntime
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
    const [browser, vault, cve, ws] = await Promise.all([
      probeBrowserRuntime(),
      probeVault(),
      probeCve(workspace),
      probeWorkspace(workspace),
    ])
    const bunVersion = (globalThis as unknown as { Bun?: { version?: string } }).Bun?.version
    const present = new Set(binaries.filter((item) => item.present).map((item) => item.name))
    return {
      runtime: { bun: bunVersion, node: process.versions.node },
      os: { platform: process.platform, arch: process.arch, release: os.release() },
      binaries,
      browser,
      cve,
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
  lines.push("## cve bundle")
  if (report.cve.present) lines.push(`- present · ${report.cve.path}`)
  else lines.push(`- not configured (${report.cve.path})`)
  return lines.join("\n")
}
