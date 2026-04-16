import z from "zod"
import { Effect } from "effect"
import * as Tool from "./tool"
import DESCRIPTION from "./observe-surface.txt"
import { crawl } from "@/scanner/crawl"
import { dirFuzz } from "@/scanner/dir-fuzzer"
import { analyzeJs } from "@/scanner/js-analyzer"
import { scanPorts } from "@/scanner/port-scanner"
import { probeServices } from "@/scanner/service-prober"

const MODE = z.enum(["recon", "crawl", "dir_fuzz", "js"])
type Mode = z.infer<typeof MODE>

const parameters = z.object({
  target: z.string().describe("Target hostname or URL"),
  modes: z.array(MODE).optional().describe("Observation modes (defaults to all)"),
  max_urls: z.number().min(1).max(500).optional().describe("Crawl max URLs"),
  max_depth: z.number().min(1).max(6).optional().describe("Crawl depth"),
  ports: z.array(z.number()).optional().describe("Port set for recon mode"),
  wordlist: z.array(z.string()).optional().describe("Wordlist for dir_fuzz mode"),
  extensions: z.array(z.string()).optional().describe("Extension list for dir_fuzz mode"),
})

function parseHost(target: string) {
  if (target.startsWith("http://") || target.startsWith("https://")) {
    return new URL(target).hostname
  }
  return target.replace(/^https?:\/\//, "").split("/")[0]!.split(":")[0]!
}

function targetUrl(target: string, host: string) {
  if (target.startsWith("http://") || target.startsWith("https://")) return target
  return `http://${host}`
}

interface SurfaceResult {
  target: string
  modes: Mode[]
  openPorts: Set<number>
  services: Array<{ port: number; protocol: string; service: string; banner?: string }>
  technologies: Set<string>
  urls: Set<string>
  endpoints: Set<string>
  forms: Array<{ method: string; action: string; inputs: string[] }>
  secrets: Array<{ type: string; value: string; file: string }>
}

async function recon(
  target: string,
  host: string,
  ports: number[] | undefined,
  result: SurfaceResult,
  stage: (title: string) => void,
) {
  stage(`Scanning ports on ${host}...`)
  const scan = await scanPorts(host, { ports })
  for (const item of scan.openPorts) result.openPorts.add(item.port)

  if (scan.openPorts.length > 0) {
    stage(`Probing ${scan.openPorts.length} services...`)
    const probe = await probeServices(
      host,
      scan.openPorts.map((item) => item.port),
    )
    for (const item of probe.services) {
      result.services.push({
        port: item.port,
        service: item.service,
        protocol: item.protocol,
        banner: item.banner,
      })
    }
  }

  const webPorts = scan.openPorts
    .map((item) => item.port)
    .filter((p) => [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090].includes(p))
  if (webPorts.length > 0 || target.startsWith("http")) {
    const webTarget = target.startsWith("http")
      ? target
      : `http://${host}:${webPorts[0] || 80}`
    stage("Analyzing JavaScript...")
    const js = await analyzeJs(webTarget)
    for (const item of js.endpoints) result.endpoints.add(item)
    for (const item of js.spaRoutes) result.endpoints.add(item)
    for (const item of js.secrets) {
      result.secrets.push({ type: item.type, value: item.value, file: item.file })
    }
  }
}

async function doCrawl(
  url: string,
  maxUrls: number | undefined,
  maxDepth: number | undefined,
  result: SurfaceResult,
  stage: (title: string) => void,
) {
  stage(`Crawling ${url}...`)
  const out = await crawl(url, { maxUrls, maxDepth })
  for (const item of out.urls) {
    result.urls.add(item)
    result.endpoints.add(item)
  }
  for (const item of out.technologies) result.technologies.add(item)
  for (const item of out.forms) {
    result.forms.push({
      method: item.method,
      action: item.action,
      inputs: item.inputs.map((input: any) => `${input.name}:${input.type}`),
    })
  }
  if (out.openapi) result.endpoints.add(out.openapi)
}

async function doFuzz(
  url: string,
  host: string,
  wordlist: string[] | undefined,
  extensions: string[] | undefined,
  result: SurfaceResult,
  stage: (title: string) => void,
) {
  stage(`Fuzzing directories on ${host}...`)
  const out = await dirFuzz(url, { wordlist, extensions })
  for (const item of out.found) {
    result.endpoints.add(`${url}${item.path}`)
  }
}

async function doJs(
  url: string,
  result: SurfaceResult,
  stage: (title: string) => void,
) {
  stage(`Analyzing JavaScript at ${url}...`)
  const out = await analyzeJs(url)
  for (const item of out.endpoints) result.endpoints.add(item)
  for (const item of out.spaRoutes) result.endpoints.add(item)
  for (const item of out.secrets) {
    result.secrets.push({ type: item.type, value: item.value, file: item.file })
  }
}

export const ObserveSurfaceTool = Tool.define(
  "observe_surface",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters,
      execute: (params: z.infer<typeof parameters>, ctx: Tool.Context) =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "observe_surface",
            patterns: [params.target],
            always: [],
            metadata: { target: params.target, modes: params.modes },
          })

          const modes: Mode[] =
            params.modes && params.modes.length > 0
              ? params.modes
              : ["recon", "crawl", "dir_fuzz", "js"]

          const host = parseHost(params.target)
          const url = targetUrl(params.target, host)

          const result: SurfaceResult = {
            target: params.target,
            modes,
            openPorts: new Set(),
            services: [],
            technologies: new Set(),
            urls: new Set(),
            endpoints: new Set(),
            forms: [],
            secrets: [],
          }

          const stage = (title: string) => {
            Effect.runSync(ctx.metadata({ title }))
          }

          yield* Effect.promise(async () => {
            if (modes.includes("recon")) await recon(params.target, host, params.ports, result, stage)
            if (modes.includes("crawl")) await doCrawl(url, params.max_urls, params.max_depth, result, stage)
            if (modes.includes("dir_fuzz")) await doFuzz(url, host, params.wordlist, params.extensions, result, stage)
            if (modes.includes("js")) await doJs(url, result, stage)
          })

          const output = JSON.stringify(
            {
              target: params.target,
              modes,
              open_ports: Array.from(result.openPorts),
              services: result.services,
              technologies: Array.from(result.technologies),
              urls: Array.from(result.urls),
              endpoints: Array.from(result.endpoints),
              forms: result.forms,
              secrets: result.secrets,
            },
            null,
            2,
          )

          return {
            title: `Surface: ${result.endpoints.size} endpoint(s), ${result.openPorts.size} port(s)`,
            metadata: {
              endpoints: result.endpoints.size,
              openPorts: result.openPorts.size,
              technologies: result.technologies.size,
              forms: result.forms.length,
              secrets: result.secrets.length,
            },
            output,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
