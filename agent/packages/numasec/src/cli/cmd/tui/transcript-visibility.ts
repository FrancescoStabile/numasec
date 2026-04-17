export const TRANSCRIPT_VISIBILITY_KEYS = {
  thinking: "thinking_visibility_v2",
  tool_details: "tool_details_visibility_v2",
  assistant_metadata: "assistant_metadata_visibility_v2",
} as const

export const TRANSCRIPT_VISIBILITY_DEFAULTS = {
  thinking: true,
  tool_details: true,
  assistant_metadata: true,
} as const

export function showDetailedToolView(status: string, visible: boolean) {
  if (status !== "completed") return true
  return visible
}
