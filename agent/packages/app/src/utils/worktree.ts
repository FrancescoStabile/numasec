// Stub — worktree backend has been removed. This no-op shim prevents
// UI crashes for the experimental workspace feature.
type State =
  | { status: "pending" }
  | { status: "ready" }
  | { status: "failed"; message: string }

export const Worktree = {
  get(_directory: string): State | undefined {
    return { status: "ready" }
  },
  pending(_directory: string) {},
  ready(_directory: string) {},
  failed(_directory: string, _message: string) {},
  wait(_directory: string): Promise<State> {
    return Promise.resolve({ status: "ready" })
  },
}
