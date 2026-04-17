// Kind pack extension point — placeholder for kind-specific boundary/plan/deliverable
// specializations that arrive in Sprint 3+. Today it only re-exports the registry entry
// so callers can do `import { pack } from "@/kind/security/pack"` once packs grow.
import { Kind } from "@/core/kind"

export const info = Kind.byId("security")!

// Future hooks (no-op today):
export const boundary = undefined
export const deliverable = undefined
export const plan = undefined
