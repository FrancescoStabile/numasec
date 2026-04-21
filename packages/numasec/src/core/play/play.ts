export type PlayArgSpec = {
  name: string
  required: boolean
  type: "string" | "number" | "boolean"
  description?: string
}

export type ToolStep = {
  tool: string
  args: Record<string, unknown>
}

export type SkillStep = {
  skill: string
  brief: string
}

export type Step = ToolStep | SkillStep

export type ConditionalStep = {
  if: string
  then: Step
}

export type PlayStep = Step | ConditionalStep

export type Play = {
  id: string
  name: string
  description: string
  args: PlayArgSpec[]
  steps: PlayStep[]
}

export function isToolStep(step: Step): step is ToolStep {
  return "tool" in step
}

export function isSkillStep(step: Step): step is SkillStep {
  return "skill" in step
}

export function isConditional(step: PlayStep): step is ConditionalStep {
  return "if" in step && "then" in step
}
