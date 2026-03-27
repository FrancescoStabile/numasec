/**
 * LSP stub — numasec does not use language servers.
 * This module provides no-op implementations so existing callers compile.
 */
import z from "zod"
import { Effect, Layer, ServiceMap } from "effect"
import { makeRuntime } from "@/effect/run-service"

export namespace LSP {
  export const Range = z
    .object({
      start: z.object({ line: z.number(), character: z.number() }),
      end: z.object({ line: z.number(), character: z.number() }),
    })
    .meta({ ref: "Range" })
  export type Range = z.infer<typeof Range>

  export const Symbol = z
    .object({
      name: z.string(),
      kind: z.number(),
      location: z.object({ uri: z.string(), range: Range }),
    })
    .meta({ ref: "Symbol" })
  export type Symbol = z.infer<typeof Symbol>

  export const DocumentSymbol = z
    .object({
      name: z.string(),
      detail: z.string().optional(),
      kind: z.number(),
      range: Range,
      selectionRange: Range,
      children: z.lazy((): z.ZodType<any> => DocumentSymbol.array()).optional(),
    })
    .meta({ ref: "DocumentSymbol" })
  export type DocumentSymbol = z.infer<typeof DocumentSymbol>

  export const Status = z
    .object({
      id: z.string(),
      root: z.string(),
      status: z.enum(["connected", "error"]),
    })
    .meta({ ref: "LSPStatus" })
  export type Status = z.infer<typeof Status>

  export interface Interface {
    readonly init: () => Effect.Effect<void>
    readonly status: () => Effect.Effect<Status[]>
    readonly diagnostics: () => Effect.Effect<never[]>
  }

  export class Service extends ServiceMap.Service<Service, Interface>()("@numasec/LSP") {}

  export const layer = Layer.succeed(
    Service,
    Service.of({
      init: () => Effect.void,
      status: () => Effect.succeed([]),
      diagnostics: () => Effect.succeed([]),
    }),
  )

  export const defaultLayer = layer

  const { runPromise } = makeRuntime(Service, defaultLayer)

  export const init = async () => {}
  export const status = async (): Promise<Status[]> => []
  export const hasClients = async (_file: string) => false
  export const touchFile = async (_input: string, _waitForDiagnostics?: boolean) => {}
  export const diagnostics = async () => []
  export const hover = async (_input: any) => undefined
  export const definition = async (_input: any) => []
  export const references = async (_input: any) => []
  export const implementation = async (_input: any) => []
  export const documentSymbol = async (_uri: string): Promise<DocumentSymbol[]> => []
  export const workspaceSymbol = async (_query: string): Promise<Symbol[]> => []
  export const prepareCallHierarchy = async (_input: any) => []
  export const incomingCalls = async (_input: any) => []
  export const outgoingCalls = async (_input: any) => []

  export namespace Diagnostic {
    export function pretty(_diagnostic: any): string {
      return ""
    }
  }
}
