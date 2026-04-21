// Shared glyph vocabulary for the numasec TUI.
//
// These are monochromatic terminal-safe glyphs deliberately chosen to give
// numasec a coherent "operator console" identity across every kind pack.
// Use SEMANTIC aliases (not raw chars) in components so that themes or future
// accessibility modes can swap them centrally.

// ── Severity / observation weight ──────────────────────────────────────────
export const SEV = {
  critical: "◆",
  high: "◈",
  medium: "◇",
  low: "◌",
  info: "·",
} as const

// Severity bars (low → high density). Useful for distribution visualizations.
export const SEV_BAR = ["░", "▒", "▓", "█"] as const

// ── Flow / chain / pivot ───────────────────────────────────────────────────
export const FLOW = {
  step: "⟶",
  pivot: "⤳",
  replay: "⇄",
  branch: "⎇",
  join: "⋈",
} as const

// ── Subject glyphs (kind-agnostic asset types) ─────────────────────────────
export const SUBJECT = {
  target: "⌬", // remote endpoint / URL / box
  cloud: "⎈",
  credential: "⚷",
  proxy: "⟜",
  file: "▤",
  repo: "❮❯",
  entity: "◉", // person / organization / domain (osint)
  binary: "▙",
  flag: "⚑",
} as const

// ── Scope / boundary state ─────────────────────────────────────────────────
export const SCOPE = {
  in: "◉",
  ambiguous: "◎",
  out: "○",
  blocked: "⊘",
} as const

// ── Status / liveness ──────────────────────────────────────────────────────
export const STATUS = {
  ok: "✓",
  fail: "✗",
  warn: "△",
  pending: "◌",
  running: "◐",
  done: "●",
  skipped: "⊖",
} as const

// ── Tool-call header frame (box drawing) ───────────────────────────────────
export const FRAME = {
  topLeft: "┌",
  topRight: "┐",
  bottomLeft: "└",
  bottomRight: "┘",
  horizontal: "─",
  vertical: "│",
  teeRight: "├",
  teeLeft: "┤",
} as const

// ── Brandmark corners (used on panels that want a "tactical" feel) ─────────
export const BRAND = {
  cornerTL: "◢",
  cornerTR: "◤",
  cornerBL: "◣",
  cornerBR: "◥",
  wordmark: "◢◤ numasec",
} as const

// ── Kind badges (fallback; kind packs can override) ────────────────────────
export const KIND_GLYPH = {
  security: "◈",
  pentest: "◆",
  appsec: "❮❯",
  osint: "⌬",
  hacking: "⚑",
} as const

export type KindId = keyof typeof KIND_GLYPH
