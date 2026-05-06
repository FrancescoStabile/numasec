import z from "zod"
import path from "path"
import { Effect } from "effect"
import * as Tool from "./tool"
import { Question } from "../question"
import { Session } from "../session"
import { MessageV2 } from "../session/message-v2"
import { Provider } from "../provider"
import { Instance } from "../project/instance"
import { type SessionID, MessageID, PartID } from "../session/schema"
import EXIT_DESCRIPTION from "./plan-exit.txt"

function getLastModel(sessionID: SessionID) {
  for (const item of MessageV2.stream(sessionID)) {
    if (item.info.role === "user" && item.info.model) return item.info.model
  }
  return undefined
}

function getPreviousAgent(sessionID: SessionID, messages: MessageV2.WithParts[]) {
  const ignored = new Set(["plan", "title", "summary", "compaction"])
  const fromMessages = messages.toReversed().find((item) => item.info.agent && !ignored.has(item.info.agent))
  if (fromMessages?.info.agent) return fromMessages.info.agent
  for (const item of MessageV2.stream(sessionID)) {
    if (item.info.agent && !ignored.has(item.info.agent)) return item.info.agent
  }
  return "security"
}

export const PlanExitTool = Tool.define(
  "plan_exit",
  Effect.gen(function* () {
    const session = yield* Session.Service
    const question = yield* Question.Service
    const provider = yield* Provider.Service

    return {
      description: EXIT_DESCRIPTION,
      parameters: z.object({}),
      execute: (_params: {}, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const info = yield* session.get(ctx.sessionID)
          const plan = path.relative(Instance.worktree, Session.plan(info))
          const answers = yield* question.ask({
            sessionID: ctx.sessionID,
            questions: [
              {
                question: `Plan at ${plan} is complete. Would you like to switch back to the operator agent and start executing?`,
                header: "Operator",
                custom: false,
                options: [
                  { label: "Yes", description: "Switch back to the operator agent and execute the plan" },
                  { label: "No", description: "Stay with plan agent to continue refining the plan" },
                ],
              },
            ],
            tool: ctx.callID ? { messageID: ctx.messageID, callID: ctx.callID } : undefined,
          })

          if (answers[0]?.[0] === "No") yield* new Question.RejectedError()

          const model = getLastModel(ctx.sessionID) ?? (yield* provider.defaultModel())
          const previousAgent = getPreviousAgent(ctx.sessionID, ctx.messages)

          const msg: MessageV2.User = {
            id: MessageID.ascending(),
            sessionID: ctx.sessionID,
            role: "user",
            time: { created: Date.now() },
            agent: previousAgent,
            model,
          }
          yield* session.updateMessage(msg)
          yield* session.updatePart({
            id: PartID.ascending(),
            messageID: msg.id,
            sessionID: ctx.sessionID,
            type: "text",
            text: `The plan at ${plan} has been approved. Switch back to the operator context and execute the plan.`,
            synthetic: true,
          } satisfies MessageV2.TextPart)

          return {
            title: `Switching to ${previousAgent}`,
            output: `User approved leaving plan agent. Continue with ${previousAgent}.`,
            metadata: { agent: previousAgent },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
