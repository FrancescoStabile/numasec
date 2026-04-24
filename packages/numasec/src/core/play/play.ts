export type PlayArgSpec = {
  name: string
  required: boolean
  type: "string" | "number" | "boolean"
  description?: string
}

export type PlayRequirement = {
  kind: "runtime" | "binary"
  id: string
  label: string
  missingAs: "required" | "optional"
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

export type NormalizedToolStep = {
  kind: "tool"
  label: string
  tool: string
  args: Record<string, unknown>
  requires?: PlayRequirement[]
}

export type NormalizedSkillStep = {
  kind: "skill"
  label: string
  skill: string
  brief: string
  requires?: PlayRequirement[]
}

export type NormalizedStep = NormalizedToolStep | NormalizedSkillStep

export type PlayStep = Step | ConditionalStep | NormalizedStep

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

// Distinguishes NormalizedStep (has `kind`) from Step and ConditionalStep
export function isNormalizedStep(step: PlayStep): step is NormalizedStep {
  return "kind" in step
}
