# Prompt B2 Slab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the OpenCode-style left-border prompt box with a "slab accent" design: a `────` full-width separator above the prompt and a `▐` half-block character as the sole visual accent.

**Architecture:** Single file change in `packages/numasec/src/cli/cmd/tui/component/prompt/index.tsx`. Remove the `border={["left"]}` outer box and the decorative lower-border box; add a separator row via a `<box>` with a bottom border using `─` chars; update the prefix text to prepend `▐ `.

**Tech Stack:** SolidJS (opentui/solid), opentui box layout

---

## File Map

| File | Change |
|------|--------|
| `packages/numasec/src/cli/cmd/tui/component/prompt/index.tsx` | Modify JSX return — 3 targeted edits |

No new files. No test files (UI rendering — verify visually with `bun dev`).

---

## Task 1: Add separator row, remove outer border box

**File:** `packages/numasec/src/cli/cmd/tui/component/prompt/index.tsx` lines ~943–951

- [ ] **Step 1: Replace the outer `border={["left"]}` box opening with a separator box + plain box**

Find this block (lines ~943–951):
```tsx
      <box ref={(r) => (anchor = r)} visible={props.visible !== false}>
        <box
          border={["left"]}
          borderColor={highlight()}
          customBorderChars={{
            ...SplitBorder.customBorderChars,
            bottomLeft: "╹",
          }}
        >
```

Replace with:
```tsx
      <box ref={(r) => (anchor = r)} visible={props.visible !== false}>
        <box
          height={1}
          border={["bottom"]}
          borderColor={theme.borderSubtle}
          customBorderChars={{
            ...EmptyBorder,
            horizontal: "─",
          }}
        />
        <box>
```

**Explanation:** The `border={["left"]}` box is gone. In its place: a 1-row `<box>` whose bottom border renders as `────` full-width (opentui fills it to the box's natural width, which is 100%). Then a plain `<box>` wraps the inner content with no visual chrome.

- [ ] **Step 2: Verify the closing tag is still correct**

The closing `</box>` for the old `border={["left"]}` box was at line ~951's companion close, right before line ~1198. That close tag is now the closing `</box>` for the new plain `<box>`. No change needed to the closing tag.

---

## Task 2: Update prefix text — prepend `▐ `

**File:** `packages/numasec/src/cli/cmd/tui/component/prompt/index.tsx` lines ~952–968

- [ ] **Step 1: Change `paddingLeft={2}` to `paddingLeft={1}` on the inner padding box**

Find (line ~952):
```tsx
          <box
            paddingLeft={2}
            paddingRight={2}
            paddingTop={1}
```

Replace with:
```tsx
          <box
            paddingLeft={1}
            paddingRight={2}
            paddingTop={1}
```

**Explanation:** The old border consumed the leftmost column; without it, `paddingLeft={2}` would indent too far. `paddingLeft={1}` keeps the slab 1 col from the terminal edge.

- [ ] **Step 2: Prepend `▐ ` to all prefix text variants**

Find (lines ~961–968):
```tsx
            <text flexShrink={0} fg={highlight()}>
              {(() => {
                if (store.mode === "shell") return "[shell]$ "
                const agent = local.agent.current()
                const pack = Kind.byAgent(agent?.name)
                if (!pack) return "> "
                return `[${pack.short}]${pack.glyph} `
              })()}
            </text>
```

Replace with:
```tsx
            <text flexShrink={0} fg={highlight()}>
              {(() => {
                if (store.mode === "shell") return "▐ [shell]$ "
                const agent = local.agent.current()
                const pack = Kind.byAgent(agent?.name)
                if (!pack) return "▐ > "
                return `▐ [${pack.short}]${pack.glyph} `
              })()}
            </text>
```

---

## Task 3: Remove decorative lower-border box, fix textarea background

**File:** `packages/numasec/src/cli/cmd/tui/component/prompt/index.tsx` lines ~1160 and ~1198–1223

- [ ] **Step 1: Change textarea `focusedBackgroundColor` to transparent**

Find (line ~1160):
```tsx
              focusedBackgroundColor={theme.backgroundElement}
```

Replace with:
```tsx
              focusedBackgroundColor={theme.background}
```

**Explanation:** Removes the filled box highlight when the textarea is focused. The `▐` slab is the only focus indicator now.

- [ ] **Step 2: Remove the decorative lower-border box entirely**

Find and delete this entire block (lines ~1198–1223):
```tsx
        <box
          height={1}
          border={["left"]}
          borderColor={highlight()}
          customBorderChars={{
            ...EmptyBorder,
            vertical: theme.backgroundElement.a !== 0 ? "╹" : " ",
          }}
        >
          <box
            height={1}
            border={["bottom"]}
            borderColor={theme.backgroundElement}
            customBorderChars={
              theme.backgroundElement.a !== 0
                ? {
                    ...EmptyBorder,
                    horizontal: "▀",
                  }
                : {
                    ...EmptyBorder,
                    horizontal: " ",
                  }
            }
          />
        </box>
```

This block rendered the `╹▀` ornament that closed the old box — it's no longer needed.

---

## Task 4: Typecheck and commit

- [ ] **Step 1: Run typecheck**

```bash
cd /home/francesco/Projects/numasec && bun typecheck 2>&1 | tail -20
```

Expected: no errors in `prompt/index.tsx`.

- [ ] **Step 2: Verify visually**

```bash
cd /home/francesco/Projects/numasec && bun dev
```

Expected output in terminal:
```
 ──────────────────────────────────────────────────
 ▐ [sec]▸  ask anything...
   pentest  deepseek-v3  openrouter       tab  ctrl+p
```

- [ ] **Step 3: Commit**

```bash
cd /home/francesco/Projects/numasec && git add packages/numasec/src/cli/cmd/tui/component/prompt/index.tsx && git commit -m "feat(tui): B2 slab accent prompt — separator + ▐ marker, no border box

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```
