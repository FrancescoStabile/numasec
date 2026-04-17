# numasec Glyph Set

The numasec terminal vocabulary. Monochromatic, terminal‑safe glyphs that give the TUI a
coherent "operator console" identity across every kind, theme and accessibility mode.

> The canonical source is [`packages/numasec/src/cli/cmd/tui/component/glyph.ts`][src].
> Always reference glyphs from that module by **semantic alias**, never by the raw
> character — this keeps themes and future a11y modes able to swap them centrally.

[src]: ../packages/numasec/src/cli/cmd/tui/component/glyph.ts

## Severity (`SEV`)

Used for findings, observations, alerts and any "weight" indicator.

| Token      | Glyph | Use                                          |
| ---------- | ----- | -------------------------------------------- |
| `critical` | `◆`   | Confirmed exploit / business‑impacting       |
| `high`     | `◈`   | Confirmed weakness with realistic impact     |
| `medium`   | `◇`   | Plausible weakness, partial proof            |
| `low`      | `◌`   | Hardening opportunity                        |
| `info`     | `·`   | Informational, factual note                  |

## Severity bar (`SEV_BAR`)

`░ ▒ ▓ █` — low → high density. Use for distribution charts in the HUD.

## Flow / chain (`FLOW`)

| Token    | Glyph | Use                                  |
| -------- | ----- | ------------------------------------ |
| `step`   | `⟶`   | Linear next action in a chain        |
| `pivot`  | `⤳`   | Pivot from one asset to another      |
| `replay` | `⇄`   | Replayable evidence / `.numasec` ref |
| `branch` | `⎇`   | Alternative branch in attack tree    |
| `join`   | `⋈`   | Confluence of two chains             |

## Subjects (`SUBJECT`)

Asset‑type glyphs reused across kinds.

| Token        | Glyph | Use                                        |
| ------------ | ----- | ------------------------------------------ |
| `target`     | `⌬`   | Remote endpoint / URL / box                |
| `cloud`      | `⎈`   | Cloud provider artifact                    |
| `credential` | `⚷`   | Credential / token / secret reference      |
| `proxy`      | `⟜`   | Proxy chain (Burp / Caido / mitmproxy/Tor) |
| `file`       | `▤`   | Local file artifact                        |
| `repo`       | `❮❯`  | Source repository                          |
| `entity`     | `◉`   | Person / org / domain (osint)              |
| `binary`     | `▙`   | Compiled binary                            |
| `flag`       | `⚑`   | CTF flag / objective                       |

## Scope (`SCOPE`)

Used by the boundary guard and HUD.

| Token       | Glyph | Use                            |
| ----------- | ----- | ------------------------------ |
| `in`        | `◉`   | In scope                       |
| `ambiguous` | `◎`   | Needs operator confirmation    |
| `out`       | `○`   | Out of scope (informational)   |
| `blocked`   | `⊘`   | Out of scope, action denied    |

## Status (`STATUS`)

Tool‑call results, plan node states, generic liveness.

| Token     | Glyph | Use                          |
| --------- | ----- | ---------------------------- |
| `ok`      | `✓`   | Success                      |
| `fail`    | `✗`   | Failure                      |
| `warn`    | `△`   | Warning / partial            |
| `pending` | `◌`   | Queued / not started         |
| `running` | `◐`   | In progress                  |
| `done`    | `●`   | Completed                    |
| `skipped` | `⊖`   | Skipped intentionally        |

## Tool‑call frame (`FRAME`)

Box‑drawing primitives for the tool‑call header restyle:

```
┌─ RUN bash ───── 0.3s ────┐
│  $ nmap -sV target.local │
└──────────────────────────┘
```

## Brand corners (`BRAND`)

`◢◤ numasec` is the wordmark. The four corner glyphs (`◢ ◤ ◣ ◥`) frame "tactical"
panels (boot splash, top‑level dialogs, error screens).

## Kind badges (`KIND_GLYPH`)

| Kind     | Glyph |
| -------- | ----- |
| security | `◈`   |
| pentest  | `◆`   |
| appsec   | `❮❯`  |
| osint    | `⌬`   |
| hacking  | `⚑`   |

These badges appear:

- next to the **input prompt prefix** (`[osint]⌬ >`)
- in the **mission strip** kind slot
- in the **kind selector dialog**

## Accessibility & fallbacks

- Every glyph has a single‑char or 2‑char form. We avoid emoji because emoji rendering
  varies wildly across terminals, fonts and screen readers.
- When `NO_COLOR=1` is set, glyph + color fall back to glyph + monochrome bracket
  notation (e.g. `[CRIT]`, `[HIGH]` instead of colored `◆/◈`).
- A future `NUMASEC_GLYPHS=ascii` env will swap the unicode set for ASCII‑only
  equivalents (`*`, `!`, `+`, `-`, `~`).

## Stability

The semantic aliases are stable. The underlying characters may change in a major release
if a token reads ambiguously in a popular terminal — open an issue with a screenshot.

— numasec maintainers
