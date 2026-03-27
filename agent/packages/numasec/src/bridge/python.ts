import { spawn, type ChildProcess } from "child_process"
import { Log } from "../util/log"
import { ulid } from "ulid"
import readline from "readline"
import { ensurePythonEnv } from "./setup"

const log = Log.create({ service: "python-bridge" })

interface PendingCall {
  resolve: (value: any) => void
  reject: (reason: any) => void
  timer: ReturnType<typeof setTimeout>
}

interface JsonRpcRequest {
  id: string
  method: string
  params: Record<string, any>
}

interface JsonRpcResponse {
  id: string
  result?: any
  error?: { message: string; code?: number; data?: any }
}

export class PythonBridge {
  private static _instance: PythonBridge | null = null
  private process: ChildProcess | null = null
  private pending = new Map<string, PendingCall>()
  private ready = false
  private startPromise: Promise<void> | null = null
  private pythonPath: string | null = null
  private readonly defaultTimeout = 300_000 // 5 min per call

  static instance(): PythonBridge {
    if (!PythonBridge._instance) {
      PythonBridge._instance = new PythonBridge()
    }
    return PythonBridge._instance
  }

  async start(): Promise<void> {
    if (this.ready) return
    if (this.startPromise) return this.startPromise

    this.startPromise = this._start()
    return this.startPromise
  }

  private async _start(): Promise<void> {
    const env = await ensurePythonEnv()
    this.pythonPath = env.pythonPath

    log.info("starting python bridge", { python: this.pythonPath, cwd: env.projectRoot })

    this.process = spawn(this.pythonPath, ["-m", "numasec.worker"], {
      cwd: env.projectRoot,
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        PYTHONUNBUFFERED: "1",
      },
    })

    this.process.on("exit", (code, signal) => {
      log.warn("python worker exited", { code, signal })
      this.ready = false
      this.startPromise = null
      // Reject all pending calls
      for (const [id, pending] of this.pending) {
        clearTimeout(pending.timer)
        pending.reject(new Error(`Python worker exited with code ${code}`))
      }
      this.pending.clear()
    })

    this.process.on("error", (err) => {
      log.error("python worker error", { error: err.message })
      this.ready = false
      this.startPromise = null
    })

    // Read stderr for logging
    if (this.process.stderr) {
      const stderrReader = readline.createInterface({ input: this.process.stderr })
      stderrReader.on("line", (line) => {
        log.debug("python worker stderr", { line })
      })
    }

    // Read stdout for JSON-RPC responses
    if (this.process.stdout) {
      const stdoutReader = readline.createInterface({ input: this.process.stdout })
      stdoutReader.on("line", (line) => {
        try {
          const response: JsonRpcResponse = JSON.parse(line)
          const pending = this.pending.get(response.id)
          if (!pending) {
            log.warn("received response for unknown request", { id: response.id })
            return
          }
          this.pending.delete(response.id)
          clearTimeout(pending.timer)
          if (response.error) {
            pending.reject(new Error(response.error.message))
          } else {
            pending.resolve(response.result)
          }
        } catch (e) {
          log.debug("non-json output from worker", { line })
        }
      })
    }

    // Wait for the worker to signal it's ready
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Python worker failed to start within 30s"))
      }, 30_000)

      const checkReady = (line: string) => {
        try {
          const msg = JSON.parse(line)
          if (msg.ready === true) {
            clearTimeout(timeout)
            this.ready = true
            resolve()
          }
        } catch {
          // Not JSON, ignore
        }
      }

      if (this.process?.stdout) {
        const reader = readline.createInterface({ input: this.process.stdout })
        reader.on("line", (rawLine) => {
          checkReady(rawLine)
          try {
            const response: JsonRpcResponse = JSON.parse(rawLine)
            const pending = this.pending.get(response.id)
            if (pending) {
              this.pending.delete(response.id)
              clearTimeout(pending.timer)
              if (response.error) {
                pending.reject(new Error(response.error.message))
              } else {
                pending.resolve(response.result)
              }
            }
          } catch {
            // Not JSON-RPC
          }
        })
      }
    })

    log.info("python bridge ready")
  }

  async call(method: string, params: Record<string, any> = {}, timeout?: number): Promise<any> {
    await this.start()

    const id = ulid()
    const request: JsonRpcRequest = { id, method, params }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`Python bridge call timed out after ${(timeout ?? this.defaultTimeout) / 1000}s: ${method}`))
      }, timeout ?? this.defaultTimeout)

      this.pending.set(id, { resolve, reject, timer })

      const line = JSON.stringify(request) + "\n"
      this.process?.stdin?.write(line, (err) => {
        if (err) {
          this.pending.delete(id)
          clearTimeout(timer)
          reject(new Error(`Failed to write to Python bridge: ${err.message}`))
        }
      })
    })
  }

  async stop(): Promise<void> {
    if (this.process) {
      this.process.kill("SIGTERM")
      this.process = null
      this.ready = false
      this.startPromise = null
    }
  }
}
