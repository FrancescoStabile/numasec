# Prompt B2 — Slab Accent Design

**Date:** 2025-05-25  
**Branch:** tui-upgrade  
**Status:** Approved by user

---

## Problem

The numasec prompt bar is visually identical to OpenCode's. It uses a left-border box with `SplitBorder` chars (`╹` at bottom), a `▐`-less left accent, and a background fill on the focused textarea. The goal is a "hacker slab" look that is unmistakably different from OpenCode.

---

## Design: B2 — Slab Accent + Separator

```
 ──────────────────────────────────────────────────────
 ▐ [sec]▸  ask anything...
   pentest  deepseek-v3  openrouter          tab  ctrl+p
```

### Visual anatomy

| Element | Description |
|---------|-------------|
| `──────` separator | Full-width `─` line, always visible, `theme.borderSubtle` color (dim). Separates chat area from prompt. |
| `▐` slab | Half-block character, accent-colored (same `highlight()` memo as today). Sole vertical visual element — no border box. |
| `[sec]▸` label | Existing agent label + glyph, accent-colored. |
| Footer | Agent name · model · provider (left); keybind hints (right). Same content as today, no change to logic. |

### What changes

1. **Remove outer `border={["left"]}` box** (lines ~944–950 in `prompt/index.tsx`).  
   The left visual is no longer a box border — it becomes the inline `▐` character prepended to the agent label text.

2. **Add separator `<text>` row above the input area.**  
   Renders `─`.repeat(width) at full terminal width, colored `theme.borderSubtle`.

3. **Remove decorative lower-border box** (lines ~1198–1223).  
   The "╹" ornament that closes the box bottom is no longer needed.

4. **Keep inner `<box>` for textarea** — remove `backgroundColor` from the textarea's `focusedBackgroundColor` prop (or set to transparent / `theme.background`).

5. **Prefix text update:** `▐ [sec]▸ ` (half-block + space + existing label + glyph + space).

### What does NOT change

- `highlight()` memo and all agent-color logic — unchanged.
- Footer content (agent name, model, provider, keybinds, spinner) — unchanged.
- Status bar (thinking spinner, retry) — unchanged.
- Keybindings — unchanged.
- Autocomplete — unchanged.

---

## Implementation

### File: `packages/numasec/src/cli/cmd/tui/component/prompt/index.tsx`

#### Change 1 — Remove outer border box, add separator row

Current JSX structure (simplified):
```tsx
<box ref={anchor}>
  <box border={["left"]} borderColor={highlight()} customBorderChars={{...SplitBorder, bottomLeft: "╹"}}>
    <box paddingLeft={2} paddingRight={2} paddingTop={1} ...>
      <text>{`[${pack.short}]${pack.glyph} `}</text>
      <textarea .../>
      <box>  {/* footer: agent + model + hints */}</box>
    </box>
  </box>
  <box height={1} border={["left"]} customBorderChars={{...EmptyBorder, vertical: "╹"/"space"}}>
    <box border={["bottom"]} .../>
  </box>
  <box ...>  {/* status bar */}</box>
</box>
```

Target JSX structure:
```tsx
<box ref={anchor}>
  {/* separator line */}
  <text fg={theme.borderSubtle}>{"─".repeat(terminalWidth)}</text>

  {/* input area — no border box */}
  <box paddingLeft={1} paddingRight={2} paddingTop={1} paddingBottom={1} ...>
    <text flexShrink={0} fg={highlight()}>▐ {agentLabel}</text>
    <textarea .../>
    <box>  {/* footer: agent + model + hints — unchanged */}</box>
  </box>

  {/* status bar — unchanged */}
  <box ...>...</box>
</box>
```

**Separator width:** use `useRenderer()` hook (already imported) to get terminal width via `renderer.screen.width`, or pass `width="100%"` and rely on opentui filling it. The simpler approach: render the `<text>` with `width="100%"` and use CSS `overflow: hidden` to clip. Alternatively, repeat `─` for a large fixed number (e.g. 300) and let the box clip it naturally.

**paddingLeft change:** outer box was `paddingLeft={2}` and the border consumed col 0. With the border removed, add `▐ ` (2 chars) as part of the prefix text and keep `paddingLeft={1}` so the slab sits 1 column from the left edge.

#### Change 2 — Textarea focusedBackgroundColor

Line ~1160:
```tsx
focusedBackgroundColor={theme.backgroundElement}
```

Change to:
```tsx
focusedBackgroundColor={theme.background}
```

This removes the filled highlight when the textarea is focused.

---

## Theme impact

No theme JSON changes required for this feature. The separator uses `theme.borderSubtle` which already exists in all numasec theme files.

---

## Edge cases

| Case | Handling |
|------|---------|
| Prompt not visible (`props.visible === false`) | The anchor `<box>` already handles this via `visible={props.visible !== false}` — no change needed. |
| Shell mode | Prefix becomes `▐ [shell]$ ` — same pattern, `theme.primary` via `highlight()`. |
| No active agent | Prefix falls back to `▐ > ` — same fallback as today. |
| Leader key active | `highlight()` returns `theme.border` — slab dims to border color, same as today. |
| Multiline input | The slab `▐` is only on the first line (it's part of the prefix text, which is `flexShrink={0}`). This matches the current behavior of the border — it runs full height, but the slab is a single character in the first line of the row. |

---

## Acceptance criteria

- [ ] `────` separator is always visible between chat and prompt, full terminal width, dim color
- [ ] `▐` appears at the left of the prompt, colored by current agent
- [ ] No filled background box in the prompt area
- [ ] No `╹` lower ornament
- [ ] Footer row (agent · model · hints) remains, always visible
- [ ] `bun typecheck` passes
