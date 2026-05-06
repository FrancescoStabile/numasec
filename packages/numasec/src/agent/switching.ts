export type SwitchableAgentInfo = {
  name: string
  mode: "subagent" | "primary" | "all"
  hidden?: boolean
}

export function isSelectableAgent(agent: Pick<SwitchableAgentInfo, "mode" | "hidden">) {
  return agent.mode !== "subagent" && agent.hidden !== true
}

export function isSwitchableAgent(agent: SwitchableAgentInfo) {
  return isSelectableAgent(agent) && agent.name !== "plan"
}
