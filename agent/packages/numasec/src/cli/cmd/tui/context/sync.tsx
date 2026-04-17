import type {
  Message,
  Agent,
  Provider,
  Session,
  Part,
  Config,
  Todo,
  Command,
  PermissionRequest,
  QuestionRequest,
  McpStatus,
  McpResource,
  FormatterStatus,
  SessionStatus,
  ProviderListResponse,
  ProviderAuthMethod,
  VcsInfo,
} from "@numasec/sdk/v2"
import { createStore, produce, reconcile } from "solid-js/store"
import { useSDK } from "@tui/context/sdk"
import { Binary } from "@numasec/util/binary"
import { createSimpleContext } from "./helper"
import type { Snapshot } from "@/snapshot"
import { useExit } from "./exit"
import { useArgs } from "./args"
import { batch, onCleanup, onMount } from "solid-js"
import { Log } from "@/util/log"
import type { Path } from "@numasec/sdk"
import type { Workspace } from "@numasec/sdk/v2"
import {
  disposeSyncMessage,
  disposeSyncSession,
  resetSyncRuntime,
  resetSyncStore,
} from "./sync-lifecycle"
import {
  emptySecurityState,
  mergeChains,
  mergeFindings,
  mergeMessages,
  readNextCursor,
  type SecurityChain,
  type SecurityCoverage,
  type SecurityEngagement,
  type SecurityFinding,
  type SecurityState,
  type SecuritySyncPage,
} from "./sync-pagination"

export const { use: useSync, provider: SyncProvider } = createSimpleContext({
  name: "Sync",
  init: () => {
    const [store, setStore] = createStore<{
      status: "loading" | "partial" | "complete"
      provider: Provider[]
      provider_default: Record<string, string>
      provider_next: ProviderListResponse
      provider_auth: Record<string, ProviderAuthMethod[]>
      agent: Agent[]
      command: Command[]
      permission: {
        [sessionID: string]: PermissionRequest[]
      }
      question: {
        [sessionID: string]: QuestionRequest[]
      }
      config: Config
      session: Session[]
      session_status: {
        [sessionID: string]: SessionStatus
      }
      session_diff: {
        [sessionID: string]: Snapshot.FileDiff[]
      }
      todo: {
        [sessionID: string]: Todo[]
      }
      message: {
        [sessionID: string]: Message[]
      }
      message_cursor: {
        [sessionID: string]: string | null
      }
      message_loading: {
        [sessionID: string]: boolean
      }
      message_history: {
        [sessionID: string]: boolean
      }
      part: {
        [messageID: string]: Part[]
      }
      security: {
        [sessionID: string]: SecurityState
      }
      mcp: {
        [key: string]: McpStatus
      }
      mcp_resource: {
        [key: string]: McpResource
      }
      formatter: FormatterStatus[]
      vcs: VcsInfo | undefined
      path: Path
      workspaceList: Workspace[]
    }>({
      provider_next: {
        all: [],
        default: {},
        connected: [],
      },
      provider_auth: {},
      config: {},
      status: "loading",
      agent: [],
      permission: {},
      question: {},
      command: [],
      provider: [],
      provider_default: {},
      session: [],
      session_status: {},
      session_diff: {},
      todo: {},
      message: {},
      message_cursor: {},
      message_loading: {},
      message_history: {},
      part: {},
      security: {},
      mcp: {},
      mcp_resource: {},
      formatter: [],
      vcs: undefined,
      path: { state: "", config: "", worktree: "", directory: "", home: "" },
      workspaceList: [],
    })

    const sdk = useSDK()

    async function syncWorkspaces() {
      const result = await sdk.client.experimental.workspace.list().catch(() => undefined)
      if (!result?.data) return
      setStore("workspaceList", reconcile(result.data))
    }

    type SecuritySummary = {
      generated_at: number
      checkpoints: {
        findings: { count: number; changed: boolean }
        chains: { count: number; changed: boolean }
        coverage: { count: number; changed: boolean }
        engagement: { count: number; changed: boolean }
      }
    }

    type SecurityRead = {
      coverage: SecurityCoverage[]
      engagement?: SecurityEngagement
    }

    type SecurityClient = {
      client?: {
        get: (input: { url: string }) => Promise<{ data?: unknown }>
      }
    }

    function patchSecurity(sessionID: string, value: Partial<SecurityState>) {
      const existing = store.security[sessionID]
      if (!existing) {
        setStore("security", sessionID, {
          ...emptySecurityState(),
          ...value,
        })
        return
      }
      setStore(
        "security",
        sessionID,
        produce((draft) => {
          if (value.status !== undefined) draft.status = value.status
          if (value.findings !== undefined) draft.findings = value.findings
          if (value.chains !== undefined) draft.chains = value.chains
          if (value.coverage !== undefined) draft.coverage = value.coverage
          if ("engagement" in value) draft.engagement = value.engagement
          if (value.updated !== undefined) draft.updated = value.updated
          if ("error" in value) draft.error = value.error
        }),
      )
    }

    function workspace(sessionID: string) {
      const result = Binary.search(store.session, sessionID, (item) => item.id)
      if (!result.found) return undefined
      return store.session[result.index]?.workspaceID
    }

    function path(input: string, workspaceID?: string) {
      const url = new URL(input, "http://numasec.local")
      if (workspaceID) url.searchParams.set("workspace", workspaceID)
      return url.pathname + url.search
    }

    async function get<T>(input: string, workspaceID?: string) {
      const client = sdk.client as unknown as SecurityClient
      if (!client.client) throw new Error("security client unavailable")
      const response = await client.client.get({ url: path(input, workspaceID) })
      if (!response.data) throw new Error("security request failed")
      return response.data as T
    }

    async function pages<T>(input: string, workspaceID?: string, since?: number) {
      const rows: T[] = []
      let cursor: string | undefined = undefined
      while (true) {
        const query = new URLSearchParams()
        query.set("limit", "200")
        if (since !== undefined) query.set("since", String(since))
        if (cursor) query.set("cursor", cursor)
        const body = await get<SecuritySyncPage<T>>(`${input}?${query.toString()}`, workspaceID)
        rows.push(...body.items)
        if (!body.sync.has_more) break
        if (!body.sync.next_cursor) break
        cursor = body.sync.next_cursor
      }
      return rows
    }

    async function syncSecurity(sessionID: string, workspaceID?: string, force = false) {
      const current = store.security[sessionID] ?? emptySecurityState()
      if (current.status === "loading") return
      patchSecurity(sessionID, {
        status: "loading",
        error: undefined,
      })
      try {
        const since = !force && current.updated > 0 ? current.updated : undefined
        const query = since === undefined ? "" : `?since=${since}`
        const summary = await get<SecuritySummary>(`/security/${sessionID}/read/summary${query}`, workspaceID)
        const findingLimit = summary.checkpoints.findings.count < current.findings.length
        const chainLimit = summary.checkpoints.chains.count < current.chains.length
        const coverageLimit = summary.checkpoints.coverage.count < current.coverage.length
        const findingDelta = summary.checkpoints.findings.changed
        const chainDelta = summary.checkpoints.chains.changed
        const coverageDelta = summary.checkpoints.coverage.changed
        const engagementDelta = summary.checkpoints.engagement.changed
        const initial = force || current.updated === 0

        let findings = current.findings
        const fullFindings = initial || findingLimit
        if (fullFindings) findings = await pages<SecurityFinding>(`/security/${sessionID}/findings/sync`, workspaceID)
        const deltaFindings = !fullFindings && findingDelta
        if (deltaFindings) {
          const rows = await pages<SecurityFinding>(`/security/${sessionID}/findings/sync`, workspaceID, since)
          findings = mergeFindings(findings, rows)
        }

        let chains = current.chains
        const fullChains = initial || chainLimit
        if (fullChains) chains = await pages<SecurityChain>(`/security/${sessionID}/chains/sync`, workspaceID)
        const deltaChains = !fullChains && chainDelta
        if (deltaChains) {
          const rows = await pages<SecurityChain>(`/security/${sessionID}/chains/sync`, workspaceID, since)
          chains = mergeChains(chains, rows)
        }

        let coverage = current.coverage
        const fullCoverage = initial || coverageLimit
        let engagement = current.engagement
        if (fullCoverage || coverageDelta || initial || engagementDelta) {
          const read = await get<SecurityRead>(`/security/${sessionID}/read`, workspaceID)
          coverage = read.coverage ?? []
          engagement = read.engagement
        }

        patchSecurity(sessionID, {
          status: "ready",
          findings,
          chains,
          coverage,
          engagement,
          updated: summary.generated_at,
          error: undefined,
        })
      } catch (error) {
        Log.Default.debug("security sync failed", {
          sessionID,
          error: error instanceof Error ? error.message : String(error),
        })
        const stale = store.security[sessionID] ?? current
        const ready =
          stale.findings.length > 0 ||
          stale.chains.length > 0 ||
          stale.coverage.length > 0 ||
          stale.engagement !== undefined
        patchSecurity(sessionID, {
          status: ready ? "ready" : "error",
          error: error instanceof Error ? error.message : String(error),
        })
      }
    }

    const securityQueue = new Map<string, ReturnType<typeof setTimeout>>()
    const fullSyncedSessions = new Set<string>()

    function queueSecurity(sessionID: string) {
      if (securityQueue.has(sessionID)) return
      const timer = setTimeout(() => {
        securityQueue.delete(sessionID)
        syncSecurity(sessionID, workspace(sessionID)).catch(() => {})
      }, 250)
      securityQueue.set(sessionID, timer)
    }

    sdk.event.listen((e) => {
      const event = e.details
      switch (event.type) {
        case "server.instance.disposed":
          resetSyncRuntime({
            securityQueue,
            fullSyncedSessions,
          })
          setStore(
            produce((draft) => {
              resetSyncStore(draft)
            }),
          )
          bootstrap()
          break
        case "permission.replied": {
          const requests = store.permission[event.properties.sessionID]
          if (!requests) break
          const match = Binary.search(requests, event.properties.requestID, (r) => r.id)
          if (!match.found) break
          setStore(
            "permission",
            event.properties.sessionID,
            produce((draft) => {
              draft.splice(match.index, 1)
            }),
          )
          break
        }

        case "permission.asked": {
          const request = event.properties
          const requests = store.permission[request.sessionID]
          if (!requests) {
            setStore("permission", request.sessionID, [request])
            break
          }
          const match = Binary.search(requests, request.id, (r) => r.id)
          if (match.found) {
            setStore("permission", request.sessionID, match.index, reconcile(request))
            break
          }
          setStore(
            "permission",
            request.sessionID,
            produce((draft) => {
              draft.splice(match.index, 0, request)
            }),
          )
          break
        }

        case "question.replied":
        case "question.rejected": {
          const requests = store.question[event.properties.sessionID]
          if (!requests) break
          const match = Binary.search(requests, event.properties.requestID, (r) => r.id)
          if (!match.found) break
          setStore(
            "question",
            event.properties.sessionID,
            produce((draft) => {
              draft.splice(match.index, 1)
            }),
          )
          break
        }

        case "question.asked": {
          const request = event.properties
          const requests = store.question[request.sessionID]
          if (!requests) {
            setStore("question", request.sessionID, [request])
            break
          }
          const match = Binary.search(requests, request.id, (r) => r.id)
          if (match.found) {
            setStore("question", request.sessionID, match.index, reconcile(request))
            break
          }
          setStore(
            "question",
            request.sessionID,
            produce((draft) => {
              draft.splice(match.index, 0, request)
            }),
          )
          break
        }

        case "todo.updated":
          setStore("todo", event.properties.sessionID, event.properties.todos)
          break

        case "session.diff":
          setStore("session_diff", event.properties.sessionID, event.properties.diff)
          break

        case "session.deleted": {
          setStore(
            produce((draft) => {
              disposeSyncSession({
                state: draft,
                sessionID: event.properties.info.id,
                securityQueue,
                fullSyncedSessions,
              })
            }),
          )
          break
        }
        case "session.updated": {
          const result = Binary.search(store.session, event.properties.info.id, (s) => s.id)
          if (result.found) {
            setStore("session", result.index, reconcile(event.properties.info))
            break
          }
          setStore(
            "session",
            produce((draft) => {
              draft.splice(result.index, 0, event.properties.info)
            }),
          )
          break
        }

        case "session.status": {
          setStore("session_status", event.properties.sessionID, event.properties.status)
          break
        }

        case "message.updated": {
          const messages = store.message[event.properties.info.sessionID]
          if (!messages) {
            setStore("message", event.properties.info.sessionID, [event.properties.info])
            break
          }
          const result = Binary.search(messages, event.properties.info.id, (m) => m.id)
          if (result.found) {
            setStore("message", event.properties.info.sessionID, result.index, reconcile(event.properties.info))
            break
          }
          setStore(
            "message",
            event.properties.info.sessionID,
            produce((draft) => {
              draft.splice(result.index, 0, event.properties.info)
            }),
          )
          const updated = store.message[event.properties.info.sessionID]
          const history = store.message_history[event.properties.info.sessionID]
          const cursor = store.message_cursor[event.properties.info.sessionID]
          if (!history && !cursor && updated.length > 100) {
            const oldest = updated[0]
            batch(() => {
              setStore(
                "message",
                event.properties.info.sessionID,
                produce((draft) => {
                  draft.shift()
                }),
              )
              setStore(
                "part",
                produce((draft) => {
                  delete draft[oldest.id]
                }),
              )
            })
          }
          break
        }
        case "message.removed": {
          setStore(
            produce((draft) => {
              disposeSyncMessage({
                state: draft,
                sessionID: event.properties.sessionID,
                messageID: event.properties.messageID,
              })
            }),
          )
          break
        }
        case "message.part.updated": {
          const parts = store.part[event.properties.part.messageID]
          if (!parts) {
            setStore("part", event.properties.part.messageID, [event.properties.part])
            if (event.properties.part.type === "tool" && event.properties.part.state.status === "completed")
              queueSecurity(event.properties.part.sessionID)
            break
          }
          const result = Binary.search(parts, event.properties.part.id, (p) => p.id)
          if (result.found) {
            setStore("part", event.properties.part.messageID, result.index, reconcile(event.properties.part))
            if (event.properties.part.type === "tool" && event.properties.part.state.status === "completed")
              queueSecurity(event.properties.part.sessionID)
            break
          }
          setStore(
            "part",
            event.properties.part.messageID,
            produce((draft) => {
              draft.splice(result.index, 0, event.properties.part)
            }),
          )
          if (event.properties.part.type === "tool" && event.properties.part.state.status === "completed")
            queueSecurity(event.properties.part.sessionID)
          break
        }

        case "message.part.delta": {
          const parts = store.part[event.properties.messageID]
          if (!parts) break
          const result = Binary.search(parts, event.properties.partID, (p) => p.id)
          if (!result.found) break
          setStore(
            "part",
            event.properties.messageID,
            produce((draft) => {
              const part = draft[result.index]
              const field = event.properties.field as keyof typeof part
              const existing = part[field] as string | undefined
              ;(part[field] as string) = (existing ?? "") + event.properties.delta
            }),
          )
          break
        }

        case "message.part.removed": {
          const parts = store.part[event.properties.messageID]
          const result = Binary.search(parts, event.properties.partID, (p) => p.id)
          if (result.found)
            setStore(
              "part",
              event.properties.messageID,
              produce((draft) => {
                draft.splice(result.index, 1)
              }),
            )
          break
        }

        case "vcs.branch.updated": {
          setStore("vcs", { branch: event.properties.branch })
          break
        }
      }
    })

    const exit = useExit()
    const args = useArgs()

    async function bootstrap() {
      console.log("bootstrapping")
      const start = Date.now() - 30 * 24 * 60 * 60 * 1000
      const sessionListPromise = sdk.client.session
        .list({ start: start })
        .then((x) => (x.data ?? []).toSorted((a, b) => a.id.localeCompare(b.id)))

      // blocking - include session.list when continuing a session
      const providersPromise = sdk.client.config.providers({}, { throwOnError: true })
      const providerListPromise = sdk.client.provider.list({}, { throwOnError: true })
      const agentsPromise = sdk.client.app.agents({}, { throwOnError: true })
      const configPromise = sdk.client.config.get({}, { throwOnError: true })
      const blockingRequests: Promise<unknown>[] = [
        providersPromise,
        providerListPromise,
        agentsPromise,
        configPromise,
        ...(args.continue ? [sessionListPromise] : []),
      ]

      await Promise.all(blockingRequests)
        .then(() => {
          const providersResponse = providersPromise.then((x) => x.data!)
          const providerListResponse = providerListPromise.then((x) => x.data!)
          const agentsResponse = agentsPromise.then((x) => x.data ?? [])
          const configResponse = configPromise.then((x) => x.data!)
          const sessionListResponse = args.continue ? sessionListPromise : undefined

          return Promise.all([
            providersResponse,
            providerListResponse,
            agentsResponse,
            configResponse,
            ...(sessionListResponse ? [sessionListResponse] : []),
          ]).then((responses) => {
            const providers = responses[0]
            const providerList = responses[1]
            const agents = responses[2]
            const config = responses[3]
            const sessions = responses[4]

            batch(() => {
              setStore("provider", reconcile(providers.providers))
              setStore("provider_default", reconcile(providers.default))
              setStore("provider_next", reconcile(providerList))
              setStore("agent", reconcile(agents))
              setStore("config", reconcile(config))
              if (sessions !== undefined) setStore("session", reconcile(sessions))
            })
          })
        })
        .then(() => {
          if (store.status !== "complete") setStore("status", "partial")
          // non-blocking
          Promise.all([
            ...(args.continue ? [] : [sessionListPromise.then((sessions) => setStore("session", reconcile(sessions)))]),
            sdk.client.command.list().then((x) => setStore("command", reconcile(x.data ?? []))),
            sdk.client.mcp.status().then((x) => setStore("mcp", reconcile(x.data!))),
            sdk.client.experimental.resource.list().then((x) => setStore("mcp_resource", reconcile(x.data ?? {}))),
            sdk.client.formatter.status().then((x) => setStore("formatter", reconcile(x.data!))),
            sdk.client.session.status().then((x) => {
              setStore("session_status", reconcile(x.data!))
            }),
            sdk.client.provider.auth().then((x) => setStore("provider_auth", reconcile(x.data ?? {}))),
            sdk.client.vcs.get().then((x) => setStore("vcs", reconcile(x.data))),
            sdk.client.path.get().then((x) => setStore("path", reconcile(x.data!))),
            syncWorkspaces(),
          ]).then(() => {
            setStore("status", "complete")
          })
        })
        .catch(async (e) => {
          Log.Default.error("tui bootstrap failed", {
            error: e instanceof Error ? e.message : String(e),
            name: e instanceof Error ? e.name : undefined,
            stack: e instanceof Error ? e.stack : undefined,
          })
          await exit(e)
        })
    }

    onMount(() => {
      bootstrap()
    })
    onCleanup(() => {
      resetSyncRuntime({
        securityQueue,
        fullSyncedSessions,
      })
    })
    const result = {
      data: store,
      set: setStore,
      get status() {
        return store.status
      },
      get ready() {
        return store.status !== "loading"
      },
      session: {
        get(sessionID: string) {
          const match = Binary.search(store.session, sessionID, (s) => s.id)
          if (match.found) return store.session[match.index]
          return undefined
        },
        status(sessionID: string) {
          const session = result.session.get(sessionID)
          if (!session) return "idle"
          if (session.time.compacting) return "compacting"
          const messages = store.message[sessionID] ?? []
          const last = messages.at(-1)
          if (!last) return "idle"
          if (last.role === "user") return "working"
          return last.time.completed ? "idle" : "working"
        },
        hasOlder(sessionID: string) {
          return store.message_cursor[sessionID] !== null && store.message_cursor[sessionID] !== undefined
        },
        loadingOlder(sessionID: string) {
          return store.message_loading[sessionID] ?? false
        },
        security(sessionID: string) {
          return store.security[sessionID]
        },
        async refreshSecurity(sessionID: string) {
          await syncSecurity(sessionID, workspace(sessionID), true)
        },
        async sync(sessionID: string) {
          if (fullSyncedSessions.has(sessionID)) return
          const [session, messages, todo, diff] = await Promise.all([
            sdk.client.session.get({ sessionID }, { throwOnError: true }),
            sdk.client.session.messages({ sessionID, limit: 100 }, { throwOnError: true }),
            sdk.client.session.todo({ sessionID }),
            sdk.client.session.diff({ sessionID }),
          ])
          const cursor = readNextCursor(messages.response?.headers)
          setStore(
            produce((draft) => {
              const match = Binary.search(draft.session, sessionID, (s) => s.id)
              if (match.found) draft.session[match.index] = session.data!
              if (!match.found) draft.session.splice(match.index, 0, session.data!)
              draft.todo[sessionID] = todo.data ?? []
              draft.message[sessionID] = messages.data!.map((x) => x.info)
              draft.message_cursor[sessionID] = cursor
              draft.message_loading[sessionID] = false
              draft.message_history[sessionID] = false
              for (const message of messages.data!) {
                draft.part[message.info.id] = message.parts
              }
              draft.session_diff[sessionID] = diff.data ?? []
            }),
          )
          syncSecurity(sessionID, session.data?.workspaceID, true).catch(() => {})
          fullSyncedSessions.add(sessionID)
        },
        async loadOlder(sessionID: string, limit = 100) {
          const cursor = store.message_cursor[sessionID]
          if (!cursor) return false
          if (store.message_loading[sessionID]) return false
          setStore("message_loading", sessionID, true)
          const result = await sdk.client.session
            .messages(
              {
                sessionID,
                limit,
                before: cursor,
              },
              { throwOnError: true },
            )
            .finally(() => {
              setStore("message_loading", sessionID, false)
            })
          const next = readNextCursor(result.response?.headers)
          setStore(
            produce((draft) => {
              const page = result.data?.map((item) => item.info) ?? []
              const existing = draft.message[sessionID] ?? []
              draft.message[sessionID] = mergeMessages(existing, page)
              for (const item of result.data ?? []) {
                draft.part[item.info.id] = item.parts
              }
              draft.message_cursor[sessionID] = next
              if (page.length > 0) draft.message_history[sessionID] = true
            }),
          )
          return (result.data?.length ?? 0) > 0
        },
      },
      workspace: {
        get(workspaceID: string) {
          return store.workspaceList.find((workspace) => workspace.id === workspaceID)
        },
        sync: syncWorkspaces,
      },
      bootstrap,
    }
    return result
  },
})
