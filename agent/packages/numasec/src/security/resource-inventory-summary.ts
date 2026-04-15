import { EvidenceNodeTable } from "./evidence.sql"

type EvidenceNode = typeof EvidenceNodeTable.$inferSelect

export type ResourceInventoryActor = {
  actor_label: string
  actor_id: string
  actor_email: string
  actor_role: string
  privileged: boolean
  source: string
}

export type ResourceInventoryAction = {
  url: string
  method: string
  action_kind: string
  target_state: string
  resource_url: string
  source_kind: string
  submit_label: string
  action_label: string
  request_content_type: string
  request_body: string
  parameter_names: string[]
}

export type ResourceInventoryResource = {
  node_id: string
  actor_label: string
  actor_id: string
  actor_email: string
  actor_role: string
  url: string
  method: string
  source_kind: string
  exposure: string
  resource_id: string
  resource_email: string
  owner_id: string
  tenant_id: string
  creator_id: string
  resource_role: string
  resource_state: string
  action_kind: string
  action_target_state: string
  resource_url: string
  request_content_type: string
  request_body: string
  parameter_names: string[]
  action_label: string
  form_enctype: string
  form_body: string
  submit_label: string
}

export type ResourceInventoryActorGroup = {
  actor_label: string
  actor_id: string
  actor_email: string
  actor_role: string
  own_values: string[]
  foreign_values: string[]
  unknown_values: string[]
  endpoints: string[]
  actions: ResourceInventoryAction[]
}

export type ResourceInventorySummary = {
  actors: ResourceInventoryActor[]
  by_actor: ResourceInventoryActorGroup[]
  resources: ResourceInventoryResource[]
  metrics: {
    actor_count: number
    resource_count: number
    actor_groups: number
    action_count: number
  }
}

function payload(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null && !Array.isArray(input)) return input as Record<string, unknown>
  return {}
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : "false"
  return ""
}

function actorKey(input: Record<string, unknown>) {
  return text(input.actor_id) || text(input.actor_email) || text(input.actor_label) || "unknown"
}

export function summarizeResourceInventory(
  rows: EvidenceNode[],
  params?: {
    actor?: string
    exposure?: "all" | "self" | "foreign" | "unknown"
    limit?: number
  },
): ResourceInventorySummary {
  const observations = rows.filter((item) => item.type === "observation")
  const actors = observations
    .map((item) => payload(item.payload))
    .filter((item) => {
      const family = text(item.family)
      return family === "actor_inventory" || family === "actor_identity"
    })
  const resources = observations
    .map((item) => ({
      node_id: item.id,
      payload: payload(item.payload),
    }))
    .filter((item) => text(item.payload.family) === "resource_inventory")

  const actorFilter = (params?.actor ?? "").toLowerCase()
  const exposureFilter = params?.exposure ?? "all"

  const actorMap = new Map<string, Record<string, unknown>>()
  for (const item of actors) {
    if (actorFilter) {
      const haystack = [
        text(item.actor_label),
        text(item.actor_id),
        text(item.actor_email),
        text(item.actor_role),
      ].join(" ").toLowerCase()
      if (!haystack.includes(actorFilter)) continue
    }
    actorMap.set(actorKey(item), item)
  }

  const filtered = resources
    .filter((item) => {
      if (actorFilter) {
        const haystack = [
          text(item.payload.actor_label),
          text(item.payload.actor_id),
          text(item.payload.actor_email),
          text(item.payload.actor_role),
        ].join(" ").toLowerCase()
        if (!haystack.includes(actorFilter)) return false
      }
      if (exposureFilter !== "all" && text(item.payload.exposure) !== exposureFilter) return false
      return true
    })
    .slice(0, params?.limit ?? 200)

  const byActor = new Map<
    string,
    {
      actor_label: string
      actor_id: string
      actor_email: string
      actor_role: string
      own_values: Set<string>
      foreign_values: Set<string>
      unknown_values: Set<string>
      endpoints: Set<string>
      actions: Map<string, ResourceInventoryAction>
    }
  >()
  let actions = 0

  for (const item of filtered) {
    const key = actorKey(item.payload)
    const current = byActor.get(key) ?? {
      actor_label: text(item.payload.actor_label),
      actor_id: text(item.payload.actor_id),
      actor_email: text(item.payload.actor_email),
      actor_role: text(item.payload.actor_role),
      own_values: new Set<string>(),
      foreign_values: new Set<string>(),
      unknown_values: new Set<string>(),
      endpoints: new Set<string>(),
      actions: new Map(),
    }
    current.endpoints.add(text(item.payload.url))
    const value = text(item.payload.resource_id) || text(item.payload.resource_email) || text(item.payload.owner_id)
    if (value) {
      if (text(item.payload.exposure) === "self") current.own_values.add(value)
      if (text(item.payload.exposure) === "foreign") current.foreign_values.add(value)
      if (text(item.payload.exposure) === "unknown") current.unknown_values.add(value)
    }
    const action = text(item.payload.action_kind)
    if (action) {
      const id = `${text(item.payload.method)} ${text(item.payload.url)}`
      if (!current.actions.has(id)) {
        current.actions.set(id, {
          url: text(item.payload.url),
          method: text(item.payload.method),
          action_kind: action,
          target_state: text(item.payload.action_target_state),
          resource_url: text(item.payload.resource_url),
          source_kind: text(item.payload.source_kind),
          submit_label: text(item.payload.submit_label),
          action_label: text(item.payload.action_label),
          request_content_type: text(item.payload.request_content_type),
          request_body: text(item.payload.request_body),
          parameter_names: Array.isArray(item.payload.parameter_names)
            ? item.payload.parameter_names.map((entry) => text(entry)).filter(Boolean)
            : [],
        })
        actions += 1
      }
    }
    byActor.set(key, current)
  }

  const actorsOut = Array.from(actorMap.values()).map((item) => ({
    actor_label: text(item.actor_label),
    actor_id: text(item.actor_id),
    actor_email: text(item.actor_email),
    actor_role: text(item.actor_role),
    privileged: item.privileged === true,
    source: text(item.source),
  }))

  const resourcesOut = filtered.map((item) => ({
    node_id: item.node_id,
    actor_label: text(item.payload.actor_label),
    actor_id: text(item.payload.actor_id),
    actor_email: text(item.payload.actor_email),
    actor_role: text(item.payload.actor_role),
    url: text(item.payload.url),
    method: text(item.payload.method),
    source_kind: text(item.payload.source_kind),
    exposure: text(item.payload.exposure),
    resource_id: text(item.payload.resource_id),
    resource_email: text(item.payload.resource_email),
    owner_id: text(item.payload.owner_id),
    tenant_id: text(item.payload.tenant_id),
    creator_id: text(item.payload.creator_id),
    resource_role: text(item.payload.resource_role),
    resource_state: text(item.payload.resource_state),
    action_kind: text(item.payload.action_kind),
    action_target_state: text(item.payload.action_target_state),
    resource_url: text(item.payload.resource_url),
    request_content_type: text(item.payload.request_content_type),
    request_body: text(item.payload.request_body),
    parameter_names: Array.isArray(item.payload.parameter_names)
      ? item.payload.parameter_names.map((entry) => text(entry)).filter(Boolean)
      : [],
    action_label: text(item.payload.action_label),
    form_enctype: text(item.payload.form_enctype),
    form_body: text(item.payload.form_body),
    submit_label: text(item.payload.submit_label),
  }))

  const actorGroups = Array.from(byActor.values()).map((item) => ({
    actor_label: item.actor_label,
    actor_id: item.actor_id,
    actor_email: item.actor_email,
    actor_role: item.actor_role,
    own_values: Array.from(item.own_values),
    foreign_values: Array.from(item.foreign_values),
    unknown_values: Array.from(item.unknown_values),
    endpoints: Array.from(item.endpoints),
    actions: Array.from(item.actions.values()),
  }))

  return {
    actors: actorsOut,
    by_actor: actorGroups,
    resources: resourcesOut,
    metrics: {
      actor_count: actorsOut.length,
      resource_count: resourcesOut.length,
      actor_groups: actorGroups.length,
      action_count: actions,
    },
  }
}
