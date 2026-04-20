// Disposable OWASP Juice Shop fixture for the numasec benchmark harness.
//
// Fixture-safety: we *never* touch any canonical ./juice-shop/ checkout the
// user may have at the repo root. Every run clones into a fresh
// /tmp/numasec-bench-<ts>/juice-shop and tears it down on teardown().

import { spawn } from "node:child_process"
import { mkdirSync, rmSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

export type Fixture = {
  port: number
  pid: number | null
  dir: string | null
  reused: boolean
}

const JUICE_SHOP_URL = "https://github.com/juice-shop/juice-shop.git"
const DEFAULT_PORT = 3000
const BOOT_TIMEOUT_MS = 60_000

async function isReachable(port: number): Promise<boolean> {
  try {
    const r = await fetch(`http://localhost:${port}/`, { signal: AbortSignal.timeout(2000) })
    return r.ok || r.status < 500
  } catch {
    return false
  }
}

async function waitForReady(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await isReachable(port)) return true
    await new Promise((r) => setTimeout(r, 2000))
  }
  return false
}

function run(cmd: string, args: string[], cwd: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { cwd, stdio: "inherit" })
    p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}`))))
    p.on("error", reject)
  })
}

export async function provision(opts?: { port?: number }): Promise<Fixture> {
  const port = opts?.port ?? DEFAULT_PORT

  if (await isReachable(port)) {
    return { port, pid: null, dir: null, reused: true }
  }

  const base = join(tmpdir(), `numasec-bench-${Date.now()}`)
  const dir = join(base, "juice-shop")
  mkdirSync(base, { recursive: true })

  console.log(`[bench] cloning juice-shop → ${dir}`)
  await run("git", ["clone", "--depth", "1", JUICE_SHOP_URL, dir], base)

  console.log(`[bench] npm install (this takes a while)`)
  await run("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error"], dir)

  console.log(`[bench] npm start on :${port}`)
  const child = spawn("npm", ["start"], {
    cwd: dir,
    env: { ...process.env, PORT: String(port), NODE_ENV: "production" },
    detached: true,
    stdio: "ignore",
  })
  child.unref()

  const pid = child.pid ?? null
  const ok = await waitForReady(port, BOOT_TIMEOUT_MS)
  if (!ok) {
    if (pid) try { process.kill(pid, "SIGTERM") } catch {}
    rmSync(base, { recursive: true, force: true })
    throw new Error(`juice-shop did not come up on :${port} within ${BOOT_TIMEOUT_MS}ms`)
  }

  return { port, pid, dir, reused: false }
}

export function teardown(fx: Fixture): void {
  if (fx.reused) return
  if (fx.pid) {
    try { process.kill(-fx.pid, "SIGTERM") } catch {}
    try { process.kill(fx.pid, "SIGTERM") } catch {}
  }
  if (fx.dir) {
    const base = fx.dir.replace(/\/juice-shop$/, "")
    if (existsSync(base) && base.includes("numasec-bench-")) {
      rmSync(base, { recursive: true, force: true })
    }
  }
}

if (import.meta.main) {
  const fx = await provision()
  console.log(JSON.stringify(fx, null, 2))
}
