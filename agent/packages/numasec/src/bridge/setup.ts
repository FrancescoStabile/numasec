/**
 * Python environment setup for the numasec scanner bridge.
 *
 * On first run, ensures:
 *  1. uv is available (installs if missing)
 *  2. A .venv exists with all numasec Python dependencies
 *  3. Returns the correct python path for the bridge to spawn
 */
import { existsSync } from "fs"
import { execSync, spawnSync } from "child_process"
import path from "path"
import { Log } from "@/util/log"

const log = Log.create({ service: "bridge.setup" })

/** Locate the numasec Python package root (contains pyproject.toml). */
function findProjectRoot(): string {
  // Walk up from agent/packages/numasec/src/bridge/ to find pyproject.toml
  let dir = path.resolve(__dirname, "../../../../..")
  for (let i = 0; i < 5; i++) {
    if (existsSync(path.join(dir, "pyproject.toml"))) return dir
    dir = path.dirname(dir)
  }
  throw new Error("Cannot find numasec Python project root (pyproject.toml)")
}

/** Check if a command exists on PATH. */
function which(cmd: string): string | null {
  try {
    const result = spawnSync("which", [cmd], { stdio: "pipe", timeout: 5000 })
    if (result.status === 0) return result.stdout.toString().trim()
    return null
  } catch {
    return null
  }
}

/** Install uv if not present. */
async function ensureUv(): Promise<string> {
  const uvPath = which("uv")
  if (uvPath) {
    log.info("uv found", { path: uvPath })
    return uvPath
  }

  log.info("installing uv...")
  try {
    execSync("curl -LsSf https://astral.sh/uv/install.sh | sh", {
      stdio: "pipe",
      timeout: 60_000,
      env: { ...process.env, UV_INSTALL_DIR: path.join(process.env.HOME || "~", ".local/bin") },
    })
  } catch (e) {
    throw new Error(`Failed to install uv: ${e}`)
  }

  // After install, uv is in ~/.local/bin or ~/.cargo/bin
  const candidates = [
    path.join(process.env.HOME || "~", ".local/bin/uv"),
    path.join(process.env.HOME || "~", ".cargo/bin/uv"),
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }

  // Try PATH again
  const found = which("uv")
  if (found) return found

  throw new Error("uv installed but not found on PATH")
}

/** Sync the Python venv with numasec dependencies. */
async function syncVenv(uvPath: string, projectRoot: string): Promise<string> {
  const venvPath = path.join(projectRoot, ".venv")
  const pythonPath = path.join(venvPath, "bin", "python")

  if (existsSync(pythonPath)) {
    log.info("venv exists", { python: pythonPath })
    return pythonPath
  }

  log.info("creating venv and installing dependencies...")
  try {
    execSync(`${uvPath} sync --project ${projectRoot} --extra mcp`, {
      cwd: projectRoot,
      stdio: "pipe",
      timeout: 300_000, // 5 min for first install
      env: { ...process.env, UV_PROJECT_ENVIRONMENT: venvPath },
    })
  } catch (e) {
    // Fallback: try pip install -e
    log.warn("uv sync failed, falling back to pip", { error: String(e) })
    const python3 = which("python3") || which("python")
    if (!python3) throw new Error("No Python found. Install Python 3.11+ or uv.")

    execSync(`${python3} -m venv ${venvPath}`, { stdio: "pipe", timeout: 30_000 })
    execSync(`${pythonPath} -m pip install -e ".[mcp]"`, {
      cwd: projectRoot,
      stdio: "pipe",
      timeout: 300_000,
    })
  }

  if (!existsSync(pythonPath)) {
    throw new Error(`Python venv creation failed — ${pythonPath} not found`)
  }

  return pythonPath
}

/**
 * Ensure the Python environment is ready and return the python path.
 * Called lazily on first bridge call.
 *
 * In pip-install mode (NUMASEC_PYTHON_PATH set by the Python launcher),
 * the Python interpreter is already available — no project root or venv
 * setup is needed. In dev mode, walks up to find pyproject.toml and
 * creates/reuses a .venv.
 */
export async function ensurePythonEnv(): Promise<{ pythonPath: string; projectRoot: string }> {
  // pip-install mode: Python launcher provides the interpreter path directly
  if (process.env.NUMASEC_PYTHON_PATH && existsSync(process.env.NUMASEC_PYTHON_PATH)) {
    log.info("using NUMASEC_PYTHON_PATH (pip-install mode)", { python: process.env.NUMASEC_PYTHON_PATH })
    return { pythonPath: process.env.NUMASEC_PYTHON_PATH, projectRoot: "" }
  }

  // Dev mode: locate project root and manage venv
  const projectRoot = findProjectRoot()
  log.info("project root", { path: projectRoot })

  const existingVenv = path.join(projectRoot, ".venv", "bin", "python")
  if (existsSync(existingVenv)) {
    log.info("using existing venv", { python: existingVenv })
    return { pythonPath: existingVenv, projectRoot }
  }

  const uvPath = await ensureUv()
  const pythonPath = await syncVenv(uvPath, projectRoot)
  return { pythonPath, projectRoot }
}
