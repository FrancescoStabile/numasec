import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./scanner.txt"
import { Guard, ScopeDeniedError } from "@/core/boundary"
import { createHash } from "crypto"
import { crawl, type CrawlResult } from "../scanner/crawl"
import { dirFuzz } from "../scanner/dir-fuzzer"
import { analyzeJs, type JsAnalysisResult } from "../scanner/js-analyzer"
import { scanPorts, type PortScanResult } from "../scanner/port-scanner"
import { probeServices, type ServiceProbeResult } from "../scanner/service-prober"
import type { DirFuzzResult } from "../scanner/dir-fuzzer"
import { Cyber } from "@/core/cyber"
import { Evidence } from "@/core/evidence"
import { Observation } from "@/core/observation"
import { Operation } from "@/core/operation"
import { Instance } from "@/project/instance"

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

function normalizeRoute(target: string, value: string) {
  try {
    return new URL(value, target).href
  } catch {
    return undefined
  }
}

function factName(prefix: string, value: string | number) {
  return `${prefix}:${String(value).toLowerCase().replace(/[^a-z0-9._:-]+/g, "_")}`
}

function fingerprint(value: string) {
  return createHash("sha256").update(value).digest("hex").slice(0, 16)
}

function persistScanResult(input: {
  workspace: string
  slug?: string
  mode: Params["mode"]
  target: string
  result: unknown
}) {
  if (!input.slug) return Effect.succeed(undefined)
  const slug = input.slug
  return Effect.promise(() =>
    Evidence.put(input.workspace, slug, JSON.stringify(input.result, null, 2), {
      mime: "application/json",
      ext: "json",
      label: `scanner ${input.mode} ${input.target}`,
      source: "scanner",
    }),
  )
}

function scannerObservationDraft(mode: Params["mode"], target: string, result: unknown) {
  const origin = target.startsWith("http://") || target.startsWith("https://") ? new URL(target).origin : target
  const data = result as Record<string, unknown>
  if (mode === "crawl") {
    const urls = (data.urls as unknown[] | undefined)?.length ?? 0
    const forms = (data.forms as unknown[] | undefined)?.length ?? 0
    return {
      subtype: "intel-fact" as const,
      title: `Web crawl completed for ${origin}`,
      severity: "info" as const,
      confidence: 0.6,
      note: `${urls} URLs and ${forms} forms discovered.`,
      tags: ["pentest", "recon", "web", "crawl"],
    }
  }
  if (mode === "js") {
    const endpoints = (data.endpoints as unknown[] | undefined)?.length ?? 0
    const files = (data.jsFiles as unknown[] | undefined)?.length ?? 0
    const secrets = (data.secrets as unknown[] | undefined)?.length ?? 0
    const subtype: "risk" | "intel-fact" = secrets > 0 || endpoints > 0 ? "risk" : "intel-fact"
    const severity: "medium" | "info" = secrets > 0 ? "medium" : "info"
    return {
      subtype,
      title: `JavaScript surface analysis completed for ${origin}`,
      severity,
      confidence: 0.6,
      note: `${files} JavaScript files, ${endpoints} endpoints, ${secrets} secret-shaped strings observed.`,
      tags: ["pentest", "recon", "web", "js"],
    }
  }
  if (mode === "dir-fuzz") {
    const found = (data.found as unknown[] | undefined)?.length ?? 0
    const tested = Number(data.testedCount ?? 0)
    const severity: "low" | "info" = found > 0 ? "low" : "info"
    return {
      subtype: "intel-fact" as const,
      title: `Directory fuzzing completed for ${origin}`,
      severity,
      confidence: 0.6,
      note: `${found} candidate paths discovered across ${tested} requests.`,
      tags: ["pentest", "recon", "web", "dir-fuzz"],
    }
  }
}

function writeCrawlFacts(input: { target: string; result: CrawlResult; eventID?: string; evidenceRefs?: string[] }) {
  const origin = new URL(input.target).origin
  const hostKey = new URL(input.target).hostname
  const port = new URL(input.target).port || (input.target.startsWith("https://") ? "443" : "80")
  const serviceKey = `${hostKey}:${port}`
  return Effect.all([
    Cyber.upsertRelation({
      src_kind: "host",
      src_key: hostKey,
      relation: "exposes",
      dst_kind: "service",
      dst_key: serviceKey,
      writer_kind: "tool",
      status: "observed",
      confidence: 1000,
      source_event_id: input.eventID,
      evidence_refs: input.evidenceRefs,
    }).pipe(Effect.catch(() => Effect.succeed(""))),
    ...input.result.urls.map((url) =>
      Effect.all([
        Cyber.upsertFact({
          entity_kind: "http_route",
          entity_key: url,
          fact_name: "discovered_by:crawl",
          value_json: true,
          writer_kind: "tool",
          status: "observed",
          confidence: 1000,
          source_event_id: input.eventID,
          evidence_refs: input.evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed(""))),
        Cyber.upsertRelation({
          src_kind: "service",
          src_key: serviceKey,
          relation: "serves",
          dst_kind: "http_route",
          dst_key: url,
          writer_kind: "tool",
          status: "observed",
          confidence: 1000,
          source_event_id: input.eventID,
          evidence_refs: input.evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed(""))),
      ]),
    ),
    ...input.result.forms.map((form) =>
      Cyber.upsertFact({
        entity_kind: "http_form",
        entity_key: `${form.method}:${form.action}`,
        fact_name: "shape",
        value_json: { action: form.action, method: form.method, inputs: form.inputs },
        writer_kind: "tool",
        status: "observed",
        confidence: 900,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ),
    ...input.result.technologies.map((technology) =>
      Cyber.upsertFact({
        entity_kind: "host",
        entity_key: hostKey,
        fact_name: factName("technology", technology),
        value_json: technology,
        writer_kind: "parser",
        status: "observed",
        confidence: 700,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ),
    ...(input.result.openapi
      ? [
          Cyber.upsertFact({
            entity_kind: "service",
            entity_key: serviceKey,
            fact_name: "openapi_spec",
            value_json: input.result.openapi,
            writer_kind: "tool",
            status: "observed",
            confidence: 1000,
            source_event_id: input.eventID,
            evidence_refs: input.evidenceRefs,
          }).pipe(Effect.catch(() => Effect.succeed(""))),
        ]
      : []),
    ...input.result.sitemap.map((url) =>
      Cyber.upsertFact({
        entity_kind: "http_route",
        entity_key: url,
        fact_name: "listed_in:sitemap",
        value_json: origin,
        writer_kind: "parser",
        status: "observed",
        confidence: 850,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ),
    ...input.result.robotsDisallowed.map((route) =>
      Cyber.upsertFact({
        entity_kind: "http_route",
        entity_key: normalizeRoute(origin, route) ?? `${origin}${route}`,
        fact_name: "listed_in:robots_disallow",
        value_json: true,
        writer_kind: "parser",
        status: "observed",
        confidence: 850,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ),
  ])
}

function writeDirFuzzFacts(input: { target: string; result: DirFuzzResult; eventID?: string; evidenceRefs?: string[] }) {
  const origin = new URL(input.target).origin
  const hostKey = new URL(input.target).hostname
  const port = new URL(input.target).port || (input.target.startsWith("https://") ? "443" : "80")
  const serviceKey = `${hostKey}:${port}`
  return Effect.forEach(input.result.found, (item) =>
    Effect.all([
      Cyber.upsertFact({
        entity_kind: "http_route",
        entity_key: normalizeRoute(origin, item.path) ?? `${origin}${item.path}`,
        fact_name: "dir_fuzz_observation",
        value_json: item,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
      Cyber.upsertRelation({
        src_kind: "service",
        src_key: serviceKey,
        relation: "serves",
        dst_kind: "http_route",
        dst_key: normalizeRoute(origin, item.path) ?? `${origin}${item.path}`,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ]),
  )
}

function writeJsFacts(input: { target: string; result: JsAnalysisResult; eventID?: string; evidenceRefs?: string[] }) {
  const hostKey = new URL(input.target).hostname
  return Effect.all([
    ...input.result.endpoints.flatMap((endpoint) => {
      const routeKey = normalizeRoute(input.target, endpoint)
      if (!routeKey) return []
      return [
        Cyber.upsertFact({
          entity_kind: "http_route",
          entity_key: routeKey,
          fact_name: "discovered_by:js_analysis",
          value_json: endpoint,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: input.eventID,
          evidence_refs: input.evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed(""))),
      ]
    }),
    ...input.result.spaRoutes.flatMap((route) => {
      const routeKey = normalizeRoute(input.target, route)
      if (!routeKey) return []
      return [
        Cyber.upsertFact({
          entity_kind: "http_route",
          entity_key: routeKey,
          fact_name: "spa_route",
          value_json: true,
          writer_kind: "parser",
          status: "observed",
          confidence: 800,
          source_event_id: input.eventID,
          evidence_refs: input.evidenceRefs,
        }).pipe(Effect.catch(() => Effect.succeed(""))),
      ]
    }),
    ...input.result.chatbotIndicators.map((indicator) =>
      Cyber.upsertFact({
        entity_kind: "host",
        entity_key: hostKey,
        fact_name: factName("chatbot", indicator),
        value_json: indicator,
        writer_kind: "parser",
        status: "observed",
        confidence: 700,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ),
    ...input.result.jsFiles.map((file) =>
      Cyber.upsertFact({
        entity_kind: "artifact",
        entity_key: file,
        fact_name: "javascript_resource",
        value_json: true,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ),
    ...input.result.secrets.map((secret) =>
      Cyber.upsertFact({
        entity_kind: "secret_candidate",
        entity_key: fingerprint(secret.value),
        fact_name: factName("detected", secret.type),
        value_json: {
          type: secret.type,
          file: secret.file,
          context: secret.context,
          preview: secret.value.slice(0, 8),
          length: secret.value.length,
        },
        writer_kind: "parser",
        status: "candidate",
        confidence: 650,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ),
  ])
}

function writePortFacts(input: { target: string; result: PortScanResult; eventID?: string; evidenceRefs?: string[] }) {
  return Effect.forEach(input.result.openPorts, (item) =>
    Effect.all([
      Cyber.upsertFact({
        entity_kind: "service",
        entity_key: `${input.result.host}:${item.port}`,
        fact_name: "port_scan",
        value_json: item,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
      Cyber.upsertRelation({
        src_kind: "host",
        src_key: input.result.host,
        relation: "exposes",
        dst_kind: "service",
        dst_key: `${input.result.host}:${item.port}`,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ]),
  )
}

function writeServiceFacts(input: {
  target: string
  result: ServiceProbeResult
  eventID?: string
  evidenceRefs?: string[]
}) {
  return Effect.forEach(input.result.services, (item) =>
    Effect.all([
      Cyber.upsertFact({
        entity_kind: "service",
        entity_key: `${extractHost(input.target)}:${item.port}`,
        fact_name: "service_probe",
        value_json: item,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
      Cyber.upsertRelation({
        src_kind: "host",
        src_key: extractHost(input.target),
        relation: "exposes",
        dst_kind: "service",
        dst_key: `${extractHost(input.target)}:${item.port}`,
        writer_kind: "tool",
        status: "observed",
        confidence: 1000,
        source_event_id: input.eventID,
        evidence_refs: input.evidenceRefs,
      }).pipe(Effect.catch(() => Effect.succeed(""))),
    ]),
  )
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
            try: () => Guard.check(Instance.directory, scopeReq),
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
          const workspace = Instance.directory
          const slug = yield* Effect.promise(() => Operation.activeSlug(workspace).catch(() => undefined))
          const evidence = yield* persistScanResult({
            workspace,
            slug,
            mode: params.mode,
            target: params.target,
            result: { mode: params.mode, target: params.target, ...result },
          }).pipe(Effect.catch(() => Effect.succeed(undefined)))
          const evidenceRefs = evidence ? [evidence.sha256] : undefined
          const eventID = yield* Cyber.appendLedger({
            kind: "fact.observed",
            source: "scanner",
            summary: summarize(params.mode, result) ?? `scanner ${params.mode} ${params.target}`,
            evidence_refs: evidenceRefs,
            session_id: ctx.sessionID,
            message_id: ctx.messageID,
            data: {
              mode: params.mode,
              target: params.target,
              elapsed,
              host,
            },
          }).pipe(Effect.catch(() => Effect.succeed("")))

          if (params.mode === "crawl") {
            yield* writeCrawlFacts({
              target: params.target,
              result: result as CrawlResult,
              eventID: eventID || undefined,
              evidenceRefs,
            })
          }
          if (params.mode === "dir-fuzz") {
            yield* writeDirFuzzFacts({
              target: params.target,
              result: result as DirFuzzResult,
              eventID: eventID || undefined,
              evidenceRefs,
            })
          }
          if (params.mode === "js") {
            yield* writeJsFacts({
              target: params.target,
              result: result as JsAnalysisResult,
              eventID: eventID || undefined,
              evidenceRefs,
            })
          }
          if (params.mode === "ports") {
            yield* writePortFacts({
              target: params.target,
              result: result as PortScanResult,
              eventID: eventID || undefined,
              evidenceRefs,
            })
          }
          if (params.mode === "service") {
            yield* writeServiceFacts({
              target: params.target,
              result: result as ServiceProbeResult,
              eventID: eventID || undefined,
              evidenceRefs,
            })
          }

          const observation = scannerObservationDraft(params.mode, params.target, result)
          if (slug && evidence && observation) {
            const obs = yield* Effect.promise(() => Observation.add(workspace, slug, observation))
            yield* Effect.promise(() => Observation.linkEvidence(workspace, slug, obs.id, evidence.sha256))
          }

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
