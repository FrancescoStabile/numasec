import { Context } from "effect"
import type { InstanceContext } from "@/project/instance"

export const InstanceRef = Context.Reference<InstanceContext | undefined>("~numasec/InstanceRef", {
  defaultValue: () => undefined,
})

export const WorkspaceRef = Context.Reference<string | undefined>("~numasec/WorkspaceRef", {
  defaultValue: () => undefined,
})
