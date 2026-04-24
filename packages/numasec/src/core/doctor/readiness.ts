import { PLAY_CAPABILITIES, VERTICAL_CAPABILITIES, type CapabilitySpec } from "./catalog"

export type CapabilityStatus = "ready" | "degraded" | "unavailable"

export type CapabilityReadiness = {
  id: string
  label: string
  status: CapabilityStatus
  missing_required: string[]
  missing_optional: string[]
}

export type CapabilitySurface = {
  plays: CapabilityReadiness[]
  verticals: CapabilityReadiness[]
}

function evaluateSpec(
  spec: CapabilitySpec,
  input: { binaries: Set<string>; browser_present: boolean },
): CapabilityReadiness {
  const missing_required: string[] = []
  const missing_optional: string[] = []

  for (const requirement of spec.requirements) {
    const present =
      requirement.kind === "binary"
        ? input.binaries.has(requirement.id)
        : requirement.id === "browser" && input.browser_present

    if (present) continue
    if (requirement.required) missing_required.push(requirement.label)
    else missing_optional.push(requirement.label)
  }

  if (missing_required.length > 0) {
    return {
      id: spec.id,
      label: spec.label,
      status: "unavailable",
      missing_required,
      missing_optional,
    }
  }

  if (missing_optional.length > 0) {
    return {
      id: spec.id,
      label: spec.label,
      status: "degraded",
      missing_required,
      missing_optional,
    }
  }

  return {
    id: spec.id,
    label: spec.label,
    status: "ready",
    missing_required,
    missing_optional,
  }
}

export function evaluateCapabilitySurface(input: {
  binaries: Set<string>
  browser_present: boolean
}): CapabilitySurface {
  return {
    plays: PLAY_CAPABILITIES.map((spec) => evaluateSpec(spec, input)),
    verticals: VERTICAL_CAPABILITIES.map((spec) => evaluateSpec(spec, input)),
  }
}
