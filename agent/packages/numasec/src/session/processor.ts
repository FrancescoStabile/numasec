import { MessageV2 } from "./message-v2"
import { Log } from "@/util/log"
import { Session } from "."
import { Agent } from "@/agent/agent"
import { Snapshot } from "@/snapshot"
import { SessionSummary } from "./summary"
import { Bus } from "@/bus"
import { SessionRetry } from "./retry"
import { SessionStatus } from "./status"
import { Plugin } from "@/plugin"
import type { Provider } from "@/provider/provider"
import { LLM } from "./llm"
import { Config } from "@/config/config"
import { SessionCompaction } from "./compaction"
import { Permission } from "@/permission"
import { Question } from "@/question"
import { PartID } from "./schema"
import type { SessionID, MessageID } from "./schema"
import { ingestToolEnvelope } from "@/security/envelope-ingestor"
import type { IngestedToolEnvelope } from "@/security/envelope-ingestor"
import { manualCommandEnvelope } from "@/security/manual-http-proof"
import { reportGuardSummary, reportGuardTurnParts } from "./report-closure-guard"

export namespace SessionProcessor {
  const DOOM_LOOP_THRESHOLD = 3
  const log = Log.create({ service: "session.processor" })
  export type RunSummary = {
    toolCalls: number
    toolResults: number
    text: string
    finishReason: string
  }

  function canonicalNodeSummary(input: IngestedToolEnvelope) {
    const summary: Record<string, unknown> = {}
    if (input.artifactNodeIDs.length === 1) summary.artifact_node_id = input.artifactNodeIDs[0]
    if (input.artifactNodeIDs.length > 0) summary.artifact_node_ids = input.artifactNodeIDs
    if (input.observationNodeIDs.length === 1) summary.observation_node_id = input.observationNodeIDs[0]
    if (input.observationNodeIDs.length > 0) summary.observation_node_ids = input.observationNodeIDs
    if (input.verificationNodeIDs.length === 1) summary.verification_node_id = input.verificationNodeIDs[0]
    if (input.verificationNodeIDs.length > 0) summary.verification_node_ids = input.verificationNodeIDs
    if (Object.keys(input.nodeIDsByKey).length > 0) summary.node_ids_by_key = input.nodeIDsByKey
    return summary
  }

  function manualCommand(input: {
    tool: string
    payload: unknown
  }) {
    if (!input.payload || typeof input.payload !== "object" || Array.isArray(input.payload)) return ""
    const value = input.payload as Record<string, unknown>
    if ((input.tool === "bash" || input.tool === "security_shell") && typeof value.command === "string") {
      return value.command
    }
    return ""
  }

  export function applyIngestedToolEvidence(input: {
    output: string
    metadata?: Record<string, unknown>
    ingested: IngestedToolEnvelope
  }) {
    const summary = canonicalNodeSummary(input.ingested)
    const metadata = {
      ...(input.metadata ?? {}),
      artifactNodeIDs: input.ingested.artifactNodeIDs,
      observationNodeIDs: input.ingested.observationNodeIDs,
      verificationNodeIDs: input.ingested.verificationNodeIDs,
      nodeIDsByKey: input.ingested.nodeIDsByKey,
      ingestedEvidence: {
        artifacts: input.ingested.artifacts,
        observations: input.ingested.observations,
        verifications: input.ingested.verifications,
        external: input.ingested.external,
      },
    } as Record<string, unknown>
    if (!("artifactNodeID" in metadata) && input.ingested.artifactNodeIDs.length === 1) metadata.artifactNodeID = input.ingested.artifactNodeIDs[0]
    if (!("observationNodeID" in metadata) && input.ingested.observationNodeIDs.length === 1) metadata.observationNodeID = input.ingested.observationNodeIDs[0]
    if (!("verificationNodeID" in metadata) && input.ingested.verificationNodeIDs.length === 1) metadata.verificationNodeID = input.ingested.verificationNodeIDs[0]
    if (Object.keys(summary).length === 0) {
      return {
        output: input.output,
        metadata,
      }
    }
    try {
      const parsed = JSON.parse(input.output)
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return {
          output: JSON.stringify(
            {
              ...parsed,
              canonical_node_ids: summary,
            },
            null,
            2,
          ),
          metadata,
        }
      }
    } catch {}
    return {
      output: `${input.output}\n\nCanonical node ids:\n${JSON.stringify(summary, null, 2)}`,
      metadata,
    }
  }

  export type Info = Awaited<ReturnType<typeof create>>
  export type Result = Awaited<ReturnType<Info["process"]>>

  export function create(input: {
    assistantMessage: MessageV2.Assistant
    sessionID: SessionID
    model: Provider.Model
    abort: AbortSignal
  }) {
    const toolcalls: Record<string, MessageV2.ToolPart> = {}
    let snapshot: string | undefined
    let blocked = false
    let attempt = 0
    let needsCompaction = false
    let runSummary: RunSummary = {
      toolCalls: 0,
      toolResults: 0,
      text: "",
      finishReason: "",
    }

    const result = {
      get message() {
        return input.assistantMessage
      },
      get runSummary() {
        return runSummary
      },
      partFromToolCall(toolCallID: string) {
        return toolcalls[toolCallID]
      },
      async process(streamInput: LLM.StreamInput) {
        log.info("process")
        needsCompaction = false
        runSummary = {
          toolCalls: 0,
          toolResults: 0,
          text: "",
          finishReason: "",
        }
        const shouldBreak = (await Config.get()).experimental?.continue_loop_on_deny !== true
        while (true) {
          try {
            let currentText: MessageV2.TextPart | undefined
            let reasoningMap: Record<string, MessageV2.ReasoningPart> = {}
            const stream = await LLM.stream(streamInput)

            for await (const value of stream.fullStream) {
              input.abort.throwIfAborted()
              switch (value.type) {
                case "start":
                  await SessionStatus.set(input.sessionID, { type: "busy" })
                  break

                case "reasoning-start":
                  if (value.id in reasoningMap) {
                    continue
                  }
                  const reasoningPart = {
                    id: PartID.ascending(),
                    messageID: input.assistantMessage.id,
                    sessionID: input.assistantMessage.sessionID,
                    type: "reasoning" as const,
                    text: "",
                    time: {
                      start: Date.now(),
                    },
                    metadata: value.providerMetadata,
                  }
                  reasoningMap[value.id] = reasoningPart
                  await Session.updatePart(reasoningPart)
                  break

                case "reasoning-delta":
                  if (value.id in reasoningMap) {
                    const part = reasoningMap[value.id]
                    part.text += value.text
                    if (value.providerMetadata) part.metadata = value.providerMetadata
                    await Session.updatePartDelta({
                      sessionID: part.sessionID,
                      messageID: part.messageID,
                      partID: part.id,
                      field: "text",
                      delta: value.text,
                    })
                  }
                  break

                case "reasoning-end":
                  if (value.id in reasoningMap) {
                    const part = reasoningMap[value.id]
                    part.text = part.text.trimEnd()

                    part.time = {
                      ...part.time,
                      end: Date.now(),
                    }
                    if (value.providerMetadata) part.metadata = value.providerMetadata
                    await Session.updatePart(part)
                    delete reasoningMap[value.id]
                  }
                  break

                case "tool-input-start":
                  runSummary.toolCalls += 1
                  const part = await Session.updatePart({
                    id: toolcalls[value.id]?.id ?? PartID.ascending(),
                    messageID: input.assistantMessage.id,
                    sessionID: input.assistantMessage.sessionID,
                    type: "tool",
                    tool: value.toolName,
                    callID: value.id,
                    state: {
                      status: "pending",
                      input: {},
                      raw: "",
                    },
                  })
                  toolcalls[value.id] = part as MessageV2.ToolPart
                  break

                case "tool-input-delta":
                  break

                case "tool-input-end":
                  break

                case "tool-call": {
                  const match = toolcalls[value.toolCallId]
                  if (match) {
                    const part = await Session.updatePart({
                      ...match,
                      tool: value.toolName,
                      state: {
                        status: "running",
                        input: value.input,
                        time: {
                          start: Date.now(),
                        },
                      },
                      metadata: value.providerMetadata,
                    })
                    toolcalls[value.toolCallId] = part as MessageV2.ToolPart

                    const parts = await MessageV2.parts(input.assistantMessage.id)
                    const lastThree = parts.slice(-DOOM_LOOP_THRESHOLD)

                    if (
                      lastThree.length === DOOM_LOOP_THRESHOLD &&
                      lastThree.every(
                        (p) =>
                          p.type === "tool" &&
                          p.tool === value.toolName &&
                          p.state.status !== "pending" &&
                          JSON.stringify(p.state.input) === JSON.stringify(value.input),
                      )
                    ) {
                      const agent = await Agent.get(input.assistantMessage.agent)
                      await Permission.ask({
                        permission: "doom_loop",
                        patterns: [value.toolName],
                        sessionID: input.assistantMessage.sessionID,
                        metadata: {
                          tool: value.toolName,
                          input: value.input,
                        },
                        always: [value.toolName],
                        ruleset: agent.permission,
                      })
                    }
                  }
                  break
                }
                case "tool-result": {
                  const match = toolcalls[value.toolCallId]
                  if (match && match.state.status === "running") {
                    runSummary.toolResults += 1
                    const tool = match.tool
                    const manualEnvelope = manualCommandEnvelope({
                      tool: tool ?? "",
                      command: manualCommand({
                        tool: tool ?? "",
                        payload: value.input ?? match.state.input,
                      }),
                      output: value.output.output,
                      exitCode:
                        typeof value.output.metadata?.exit === "number"
                          ? value.output.metadata.exit
                          : typeof value.output.metadata?.exitCode === "number"
                            ? value.output.metadata.exitCode
                            : undefined,
                    })
                    const envelope = value.output.envelope ?? manualEnvelope
                    let output = value.output.output
                    let metadata = value.output.metadata
                    const alreadyIngested =
                      typeof metadata === "object" &&
                      metadata !== null &&
                      !Array.isArray(metadata) &&
                      "ingestedEvidence" in metadata
                    if (envelope && tool && !alreadyIngested) {
                      const ingested = await ingestToolEnvelope({
                        sessionID: input.assistantMessage.sessionID,
                        tool,
                        title: value.output.title,
                        metadata: value.output.metadata,
                        envelope,
                      }).catch((error) => {
                        log.warn("failed to ingest tool envelope", {
                          tool,
                          error,
                        })
                        return undefined
                      })
                      if (ingested) {
                        const merged = applyIngestedToolEvidence({
                          output,
                          metadata,
                          ingested,
                        })
                        output = merged.output
                        metadata = merged.metadata
                      }
                    }
                    await Session.updatePart({
                      ...match,
                      state: {
                        status: "completed",
                        input: value.input ?? match.state.input,
                        output,
                        output_v2: value.output.envelope,
                        metadata,
                        title: value.output.title,
                        time: {
                          start: match.state.time.start,
                          end: Date.now(),
                        },
                        attachments: value.output.attachments,
                      },
                    })

                    delete toolcalls[value.toolCallId]
                  }
                  break
                }

                case "tool-error": {
                  const match = toolcalls[value.toolCallId]
                  if (match && match.state.status === "running") {
                    await Session.updatePart({
                      ...match,
                      state: {
                        status: "error",
                        input: value.input ?? match.state.input,
                        error: value.error instanceof Error ? value.error.message : String(value.error),
                        time: {
                          start: match.state.time.start,
                          end: Date.now(),
                        },
                      },
                    })

                    if (
                      value.error instanceof Permission.RejectedError ||
                      value.error instanceof Question.RejectedError
                    ) {
                      blocked = shouldBreak
                    }
                    delete toolcalls[value.toolCallId]
                  }
                  break
                }
                case "error":
                  throw value.error

                case "start-step":
                  snapshot = await Snapshot.track()
                  await Session.updatePart({
                    id: PartID.ascending(),
                    messageID: input.assistantMessage.id,
                    sessionID: input.sessionID,
                    snapshot,
                    type: "step-start",
                  })
                  break

                case "finish-step":
                  const usage = Session.getUsage({
                    model: input.model,
                    usage: value.usage,
                    metadata: value.providerMetadata,
                  })
                  const finish = value.finishReason ?? "unknown"
                  runSummary.finishReason = finish
                  input.assistantMessage.finish = finish
                  input.assistantMessage.cost += usage.cost
                  input.assistantMessage.tokens = usage.tokens
                  await Session.updatePart({
                    id: PartID.ascending(),
                    reason: finish,
                    snapshot: await Snapshot.track(),
                    messageID: input.assistantMessage.id,
                    sessionID: input.assistantMessage.sessionID,
                    type: "step-finish",
                    tokens: usage.tokens,
                    cost: usage.cost,
                  })
                  await Session.updateMessage(input.assistantMessage)
                  if (snapshot) {
                    const patch = await Snapshot.patch(snapshot)
                    if (patch.files.length) {
                      await Session.updatePart({
                        id: PartID.ascending(),
                        messageID: input.assistantMessage.id,
                        sessionID: input.sessionID,
                        type: "patch",
                        hash: patch.hash,
                        files: patch.files,
                      })
                    }
                    snapshot = undefined
                  }
                  SessionSummary.summarize({
                    sessionID: input.sessionID,
                    messageID: input.assistantMessage.parentID,
                  })
                  if (
                    !input.assistantMessage.summary &&
                    (await SessionCompaction.isOverflow({ tokens: usage.tokens, model: input.model }))
                  ) {
                    needsCompaction = true
                  }
                  break

                case "text-start":
                  currentText = {
                    id: PartID.ascending(),
                    messageID: input.assistantMessage.id,
                    sessionID: input.assistantMessage.sessionID,
                    type: "text",
                    text: "",
                    time: {
                      start: Date.now(),
                    },
                    metadata: value.providerMetadata,
                  }
                  await Session.updatePart(currentText)
                  break

                case "text-delta":
                  if (currentText) {
                    currentText.text += value.text
                    if (value.providerMetadata) currentText.metadata = value.providerMetadata
                    await Session.updatePartDelta({
                      sessionID: currentText.sessionID,
                      messageID: currentText.messageID,
                      partID: currentText.id,
                      field: "text",
                      delta: value.text,
                    })
                  }
                  break

                case "text-end":
                  if (currentText) {
                    currentText.text = currentText.text.trimEnd()
                    const textOutput = await Plugin.trigger(
                      "experimental.text.complete",
                      {
                        sessionID: input.sessionID,
                        messageID: input.assistantMessage.id,
                        partID: currentText.id,
                      },
                      { text: currentText.text },
                    )
                    currentText.text = textOutput.text
                    const messages = await MessageV2.filterCompacted(MessageV2.stream(input.sessionID))
                    const parts = reportGuardTurnParts({
                      messages,
                      parentID: input.assistantMessage.parentID,
                      messageID: input.assistantMessage.id,
                    })
                    const reportGuard = reportGuardSummary(
                      parts,
                      currentText.text,
                      input.assistantMessage.agent,
                      input.sessionID,
                    )
                    if (reportGuard) {
                      currentText.text = reportGuard
                    }
                    runSummary.text = currentText.text
                    currentText.time = {
                      start: Date.now(),
                      end: Date.now(),
                    }
                    if (value.providerMetadata) currentText.metadata = value.providerMetadata
                    await Session.updatePart(currentText)
                  }
                  currentText = undefined
                  break

                case "finish":
                  break

                default:
                  log.info("unhandled", {
                    ...value,
                  })
                  continue
              }
              if (needsCompaction) break
            }
          } catch (e: any) {
            log.error("process", {
              error: e,
              stack: JSON.stringify(e.stack),
            })
            const error = MessageV2.fromError(e, { providerID: input.model.providerID, aborted: input.abort.aborted })
            if (MessageV2.ContextOverflowError.isInstance(error)) {
              needsCompaction = true
              Bus.publish(Session.Event.Error, {
                sessionID: input.sessionID,
                error,
              })
            } else {
              const retry = SessionRetry.retryable(error)
              if (retry !== undefined) {
                attempt++
                const delay = SessionRetry.delay(attempt, error.name === "APIError" ? error : undefined)
                await SessionStatus.set(input.sessionID, {
                  type: "retry",
                  attempt,
                  message: retry,
                  next: Date.now() + delay,
                })
                await SessionRetry.sleep(delay, input.abort).catch(() => {})
                continue
              }
              input.assistantMessage.error = error
              Bus.publish(Session.Event.Error, {
                sessionID: input.assistantMessage.sessionID,
                error: input.assistantMessage.error,
              })
              await SessionStatus.set(input.sessionID, { type: "idle" })
            }
          }
          if (snapshot) {
            const patch = await Snapshot.patch(snapshot)
            if (patch.files.length) {
              await Session.updatePart({
                id: PartID.ascending(),
                messageID: input.assistantMessage.id,
                sessionID: input.sessionID,
                type: "patch",
                hash: patch.hash,
                files: patch.files,
              })
            }
            snapshot = undefined
          }
          const p = await MessageV2.parts(input.assistantMessage.id)
          for (const part of p) {
            if (part.type === "tool" && part.state.status !== "completed" && part.state.status !== "error") {
              await Session.updatePart({
                ...part,
                state: {
                  ...part.state,
                  status: "error",
                  error: "Tool execution aborted",
                  time: {
                    start: Date.now(),
                    end: Date.now(),
                  },
                },
              })
            }
          }
          input.assistantMessage.time.completed = Date.now()
          await Session.updateMessage(input.assistantMessage)
          if (needsCompaction) return "compact"
          if (blocked) return "stop"
          if (input.assistantMessage.error) return "stop"
          return "continue"
        }
      },
    }
    return result
  }
}
