export type Technique = {
  id: string
  name: string
  description: string
  references?: string[]
}

export type Phase = {
  id: string
  name: string
  description: string
  techniques: Technique[]
}

export type Framework = {
  id: string
  name: string
  version: string
  phases: Phase[]
}

export type FrameworkID = "mitre" | "ptes" | "wstg"
