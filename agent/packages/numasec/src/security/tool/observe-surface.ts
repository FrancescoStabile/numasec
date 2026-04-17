import z from "zod"
import { Effect } from "effect"
import { Tool } from "../../tool/tool"
import { analyzeJs, type JsAnalysisResult } from "../scanner/js-analyzer"
import { crawl, type CrawlResult } from "../scanner/crawl"
import { dirFuzz, type DirFuzzResult } from "../scanner/dir-fuzzer"
import { scanPorts, type PortScanResult } from "../scanner/port-scanner"
import { probeServices, type ServiceProbeResult } from "../scanner/service-prober"
import { EvidenceGraphStore } from "../evidence-store"
import type { SessionID } from "../../session/schema"
import { Scope } from "../scope"
import { persistEngagementTarget } from "../target-store"
import { makeToolResultEnvelope } from "./result-envelope"

const DESCRIPTION = `Observe target surface and produce baseline evidence.
Combines recon, crawl, directory fuzzing, and JS analysis as composable modes.`

const MODE = z.enum(["recon", "crawl", "dir_fuzz", "js"])
export type ObserveSurfaceMode = z.infer<typeof MODE>

export interface ObserveSurfaceProfileInput {
  target: string
  sessionID?: SessionID
  modes?: ObserveSurfaceMode[]
  max_urls?: number
  max_depth?: number
  ports?: number[]
  skip_js?: boolean
  wordlist?: string[]
  extensions?: string[]
}

export interface ObserveSurfaceProfileOutput {
  target: string
  host: string
  modes: ObserveSurfaceMode[]
  recon?: {
    port_scan: PortScanResult
    service_probe?: ServiceProbeResult
    js_analysis?: JsAnalysisResult
  }
  crawl?: CrawlResult
  dir_fuzz?: DirFuzzResult
  js?: JsAnalysisResult
  open_ports: number[]
  services: Array<{
    port: number
    protocol: string
    service: string
    banner?: string
  }>
  technologies: string[]
  urls: string[]
  endpoints: string[]
  forms: Array<{ method: string; action: string; inputs: string[] }>
  secrets: Array<{ type: string; value: string; file: string }>
}

export interface ObserveSurfaceProfileHooks {
  onStage?: (title: string) => void
}

function parseHost(target: string) {
  if (target.startsWith("http://") || target.startsWith("https://")) {
    const url = new URL(target)
    return url.hostname
  }
  return target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]
}

function targetUrl(target: string, host: string) {
  if (target.startsWith("http://") || target.startsWith("https://")) return target
  return `http://${host}`
}

export async function runObserveSurfaceProfile(
  params: ObserveSurfaceProfileInput,
  hooks: ObserveSurfaceProfileHooks = {},
): Promise<ObserveSurfaceProfileOutput> {
  const modes: ObserveSurfaceMode[] = params.modes && params.modes.length > 0
    ? params.modes
    : ["recon", "crawl", "dir_fuzz", "js"]
  if (params.sessionID) {
    Scope.ensure(params.sessionID, params.target)
  }
  const host = parseHost(params.target)
  const target = targetUrl(params.target, host)
  const urls = new Set<string>()
  const endpoints = new Set<string>()
  const technologies = new Set<string>()
  const openPorts = new Set<number>()
  const forms: Array<{ method: string; action: string; inputs: string[] }> = []
  const secrets: Array<{ type: string; value: string; file: string }> = []
  const services: Array<{ port: number; protocol: string; service: string; banner?: string }> = []
  let reconPortScan: PortScanResult | undefined
  let reconServiceProbe: ServiceProbeResult | undefined
  let reconJsAnalysis: JsAnalysisResult | undefined
  let crawlResult: CrawlResult | undefined
  let dirFuzzResult: DirFuzzResult | undefined
  let jsResult: JsAnalysisResult | undefined

  if (modes.includes("recon")) {
    hooks.onStage?.(`Scanning ports on ${host}...`)
    const result = await scanPorts(host, { ports: params.ports })
    reconPortScan = result
    for (const item of result.openPorts) {
      openPorts.add(item.port)
    }
    if (result.openPorts.length > 0) {
      hooks.onStage?.(`Probing ${result.openPorts.length} services...`)
      const probe = await probeServices(host, result.openPorts.map((item) => item.port))
      reconServiceProbe = probe
      for (const item of probe.services) {
        services.push({
          port: item.port,
          service: item.service,
          protocol: item.protocol,
          banner: item.banner,
        })
      }
    }

    const webPorts = result.openPorts.map((item) => item.port).filter((item) => [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090].includes(item))
    if (!params.skip_js && (webPorts.length > 0 || params.target.startsWith("http"))) {
      const webTarget = params.target.startsWith("http") ? params.target : `http://${host}:${webPorts[0] || 80}`
      hooks.onStage?.("Analyzing JavaScript...")
      const js = await analyzeJs(webTarget, {
        sessionID: params.sessionID,
      })
      reconJsAnalysis = js
      for (const item of js.endpoints) endpoints.add(item)
      for (const item of js.spaRoutes) endpoints.add(item)
      for (const item of js.secrets) {
        secrets.push({
          type: item.type,
          value: item.value,
          file: item.file,
        })
      }
    }
  }

  if (modes.includes("crawl")) {
    hooks.onStage?.(`Crawling ${target}...`)
    const result = await crawl(target, {
      maxUrls: params.max_urls,
      maxDepth: params.max_depth,
      sessionID: params.sessionID,
    })
    crawlResult = result
    for (const item of result.urls) {
      urls.add(item)
      endpoints.add(item)
    }
    for (const item of result.technologies) technologies.add(item)
    for (const item of result.forms) {
      forms.push({
        method: item.method,
        action: item.action,
        inputs: item.inputs.map((input) => `${input.name}:${input.type}`),
      })
    }
    if (result.openapi) endpoints.add(result.openapi)
  }

  if (modes.includes("dir_fuzz")) {
    hooks.onStage?.(`Fuzzing directories on ${new URL(target).hostname}...`)
    const result = await dirFuzz(target, {
      wordlist: params.wordlist,
      extensions: params.extensions,
      sessionID: params.sessionID,
    })
    dirFuzzResult = result
    for (const item of result.found) {
      endpoints.add(`${target}${item.path}`)
    }
  }

  if (modes.includes("js")) {
    hooks.onStage?.(`Analyzing JavaScript at ${target}...`)
    const result = await analyzeJs(target, {
      sessionID: params.sessionID,
    })
    jsResult = result
    for (const item of result.endpoints) endpoints.add(item)
    for (const item of result.spaRoutes) endpoints.add(item)
    for (const item of result.secrets) {
      secrets.push({
        type: item.type,
        value: item.value,
        file: item.file,
      })
    }
  }

  return {
    target: params.target,
    host,
    modes,
    recon: reconPortScan
      ? {
          port_scan: reconPortScan,
          service_probe: reconServiceProbe,
          js_analysis: reconJsAnalysis,
        }
      : undefined,
    crawl: crawlResult,
    dir_fuzz: dirFuzzResult,
    js: jsResult,
    open_ports: Array.from(openPorts),
    services,
    technologies: Array.from(technologies),
    urls: Array.from(urls),
    endpoints: Array.from(endpoints),
    forms,
    secrets,
  }
}

export const ObserveSurfaceTool = Tool.define("observe_surface", {
  description: DESCRIPTION,
  parameters: z.object({
    target: z.string().describe("Target hostname or URL"),
    modes: z.array(MODE).optional().describe("Observation modes"),
    max_urls: z.number().min(1).max(500).optional().describe("Crawl max URLs"),
    max_depth: z.number().min(1).max(6).optional().describe("Crawl depth"),
    ports: z.array(z.number()).optional().describe("Optional port set for recon mode"),
    skip_js: z.boolean().optional().describe("Skip JS analysis during recon mode"),
    wordlist: z.array(z.string()).optional().describe("Optional wordlist for dir_fuzz mode"),
    extensions: z.array(z.string()).optional().describe("Optional extension list for dir_fuzz mode"),
    persist: z.boolean().optional().describe("Persist summary and endpoint observations"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "observe_surface",
      patterns: [params.target],
      always: [] as string[],
      metadata: { target: params.target, modes: params.modes } as Record<string, any>,
    })
    persistEngagementTarget({
      sessionID: ctx.sessionID,
      url: params.target,
      source: "observe_surface",
    })

    const profile = await runObserveSurfaceProfile(
      {
        target: params.target,
        sessionID: ctx.sessionID,
        modes: params.modes,
        max_urls: params.max_urls,
        max_depth: params.max_depth,
        ports: params.ports,
        skip_js: params.skip_js,
        wordlist: params.wordlist,
        extensions: params.extensions,
      },
      {
        onStage: (title) => ctx.metadata({ title }),
      },
    )

    const persist = params.persist !== false
    let summaryNodeID = ""
    const endpointNodeIDs: string[] = []
    if (persist) {
      const summary = Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.upsertNode({
            sessionID: ctx.sessionID,
            type: "artifact",
            status: "active",
            confidence: 0.8,
            sourceTool: "observe_surface",
            payload: {
              target: params.target,
              modes: profile.modes,
              open_ports: profile.open_ports,
              technologies: profile.technologies,
              endpoint_count: profile.endpoints.length,
              form_count: profile.forms.length,
              secret_count: profile.secrets.length,
            },
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
      summaryNodeID = summary.id

      const sample = profile.endpoints.slice(0, 80)
      for (const item of sample) {
        const row = Effect.runSync(
          EvidenceGraphStore.use((store) =>
            store.upsertNode({
              sessionID: ctx.sessionID,
              type: "observation",
              status: "active",
              confidence: 0.7,
              sourceTool: "observe_surface",
              payload: {
                key: "endpoint",
                value: item,
              },
            }),
          ).pipe(Effect.provide(EvidenceGraphStore.layer)),
        )
        endpointNodeIDs.push(row.id)
        Effect.runSync(
          EvidenceGraphStore.use((store) =>
            store.upsertEdge({
              sessionID: ctx.sessionID,
              fromNodeID: summary.id,
              toNodeID: row.id,
              relation: "derived_from",
              metadata: {
                source: "observe_surface",
              },
            }),
          ).pipe(Effect.provide(EvidenceGraphStore.layer)),
        )
      }
    }

    const output = {
      target: params.target,
      modes: profile.modes,
      open_ports: profile.open_ports,
      services: profile.services,
      technologies: profile.technologies,
      urls: profile.urls,
      endpoints: profile.endpoints,
      forms: profile.forms,
      secrets: profile.secrets,
      summary_node_id: summaryNodeID,
      endpoint_node_ids: endpointNodeIDs,
    }

    return {
      title: `Surface: ${profile.endpoints.length} endpoint(s), ${profile.open_ports.length} port(s)`,
      metadata: {
        endpoints: profile.endpoints.length,
        openPorts: profile.open_ports.length,
        technologies: profile.technologies.length,
        forms: profile.forms.length,
        secrets: profile.secrets.length,
        summaryNodeID,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        artifacts: [
          {
            type: "surface_summary",
            target: params.target,
            summary_node_id: summaryNodeID,
          },
        ],
        observations: [
          {
            type: "surface",
            endpoint_count: profile.endpoints.length,
            open_port_count: profile.open_ports.length,
            technology_count: profile.technologies.length,
            form_count: profile.forms.length,
            secret_count: profile.secrets.length,
          },
        ],
        metrics: {
          endpoint_count: profile.endpoints.length,
          open_port_count: profile.open_ports.length,
          technology_count: profile.technologies.length,
          form_count: profile.forms.length,
          secret_count: profile.secrets.length,
        },
      }),
      output: JSON.stringify(output, null, 2),
    }
  },
})
