import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./scanner.txt"
import { Guard, ScopeDeniedError } from "@/core/boundary"
import { crawl } from "../scanner/crawl"
import { dirFuzz } from "../scanner/dir-fuzzer"
import { analyzeJs } from "../scanner/js-analyzer"
import { scanPorts } from "../scanner/port-scanner"
import { probeServices } from "../scanner/service-prober"

const TIMEOUTS = {
  crawl: 60_000,
  "dir-fuzz": 60_000,
  js: 60_000,
  ports: 30_000,
  service: 15_000,
} as const

const options = z
  .object({
    maxUrls: z.number().int().positive().max(1000).optional(),
    maxDepth: z.number().int().min(0).max(10).optional(),
    maxFiles: z.number().int().positive().max(200).optional(),
    wordlist: z.array(z.string()).max(5000).optional(),
    extensions: z.array(z.string()).max(50).optional(),
    ports: z.array(z.number().int().min(1).max(65535)).max(200).optional(),
    concurrency: z.number().int().min(1).max(200).optional(),
    timeout: z.number().int().min(100).max(60_000).optional(),
    filterStatus: z.array(z.number().int().min(100).max(599)).optional(),
  })
  .optional()

const parameters = z.object({
  mode: z
    .enum(["crawl", "dir-fuzz", "js", "ports", "service"])
    .describe("Which scanner to run. See tool description for the role of each."),
  target: z
    .string()
    .min(1)
    .describe(
      "URL for crawl/dir-fuzz/js (e.g. https://app.example.com); host or IP for ports/service (e.g. 10.0.0.5).",
    ),
  options: options.describe("Per-mode knobs: maxUrls, maxDepth, wordlist, ports, concurrency, timeout, etc."),
})

type Params = z.infer<typeof parameters>

type Metadata = {
  mode: string
  target: string
  elapsed?: number
  scope?: string
  scope_reason?: string
  scope_matched?: string
  out_of_scope?: boolean
  truncated?: boolean
  outputPath?: string
}

function isUrlMode(mode: Params["mode"]): boolean {
  return mode === "crawl" || mode === "dir-fuzz" || mode === "js"
}

function extractHost(target: string): string {
  if (target.startsWith("http://") || target.startsWith("https://")) {
    return new URL(target).hostname
  }
  return target.replace(/^\/+|\/+$/g, "").split("/")[0]
}

function baseUrl(target: string): string {
  if (target.startsWith("http://") || target.startsWith("https://")) return target
  throw new Error(`target must be an absolute URL (http:// or https://) for this mode, got: ${target}`)
}

export const ScannerTool = Tool.define<typeof parameters, Metadata, never>(
  "scanner",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: Params, ctx: Tool.Context<Metadata>) =>
        Effect.gen(function* () {
          const urlMode = isUrlMode(params.mode)
          if (urlMode) baseUrl(params.target)

          const host = extractHost(params.target)
          const scopeReq = urlMode
            ? { kind: "url" as const, value: params.target }
            : { kind: "host" as const, value: host }

          const scope = yield* Effect.tryPromise({
            try: () => Guard.check(process.cwd(), scopeReq),
            catch: (e) =>
              e instanceof ScopeDeniedError
                ? new Error(`out-of-scope: ${params.target} is not allowed by the active operation's scope`)
                : new Error(String(e)),
          })

          yield* ctx.ask({
            permission: "scanner",
            patterns: [`${params.mode}:${params.target}`],
            always: [],
            metadata: {
              mode: params.mode,
              target: params.target,
              scope: scope.mode,
              scope_reason: scope.reason,
              scope_matched: scope.matched,
            },
          })

          const signal = AbortSignal.any([ctx.abort, AbortSignal.timeout(TIMEOUTS[params.mode])])
          const opts = params.options ?? {}

          const run = () => {
            if (params.mode === "crawl") {
              return crawl(baseUrl(params.target), {
                maxUrls: opts.maxUrls,
                maxDepth: opts.maxDepth,
                timeout: opts.timeout,
              })
            }
            if (params.mode === "dir-fuzz") {
              return dirFuzz(baseUrl(params.target), {
                wordlist: opts.wordlist,
                extensions: opts.extensions,
                concurrency: opts.concurrency,
                timeout: opts.timeout,
                filterStatus: opts.filterStatus,
              })
            }
            if (params.mode === "js") {
              return analyzeJs(baseUrl(params.target), {
                maxFiles: opts.maxFiles,
                timeout: opts.timeout,
              })
            }
            if (params.mode === "ports") {
              return scanPorts(host, {
                ports: opts.ports,
                concurrency: opts.concurrency,
                timeout: opts.timeout,
              })
            }
            if (!opts.ports || opts.ports.length === 0) {
              return Promise.reject(new Error("service mode requires options.ports"))
            }
            return probeServices(host, opts.ports, {
              concurrency: opts.concurrency,
              timeout: opts.timeout,
            })
          }

          const result = yield* Effect.tryPromise({
            try: () =>
              Promise.race([
                run(),
                new Promise<never>((_, reject) => {
                  signal.addEventListener(
                    "abort",
                    () => reject(new Error(`scanner ${params.mode} aborted: ${signal.reason}`)),
                    { once: true },
                  )
                  if (signal.aborted) reject(new Error(`scanner ${params.mode} aborted: ${signal.reason}`))
                }),
              ]),
            catch: (e) => new Error(`scanner ${params.mode}: ${(e as Error).message}`),
          })

          const elapsed = (result as { elapsed?: number }).elapsed
          return {
            title: summarize(params.mode, result) ?? `scanner ${params.mode} ${params.target}`,
            output: JSON.stringify({ mode: params.mode, target: params.target, ...result }, null, 2),
            metadata: {
              mode: params.mode,
              target: params.target,
              elapsed,
              scope: scope.mode,
              scope_reason: scope.reason,
              scope_matched: scope.matched,
            } satisfies Metadata,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

function summarize(mode: Params["mode"], result: unknown): string | undefined {
  const r = result as Record<string, unknown>
  if (mode === "crawl") return `crawl: ${(r.urls as string[] | undefined)?.length ?? 0} urls, ${(r.forms as unknown[] | undefined)?.length ?? 0} forms`
  if (mode === "dir-fuzz") return `dir-fuzz: ${(r.found as unknown[] | undefined)?.length ?? 0} paths / ${r.testedCount ?? 0} tested`
  if (mode === "js") return `js: ${(r.endpoints as unknown[] | undefined)?.length ?? 0} endpoints, ${(r.secrets as unknown[] | undefined)?.length ?? 0} secrets`
  if (mode === "ports") return `ports: ${(r.openPorts as unknown[] | undefined)?.length ?? 0} open / ${r.closedCount ?? 0} closed`
  if (mode === "service") return `service: ${(r.services as unknown[] | undefined)?.length ?? 0} identified`
  return undefined
}
