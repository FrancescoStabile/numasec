# numasec Public Prompts

> **Principle 2 (Manifesto)** — *Public brain.* Every kind prompt that drives the agent
> lives in this repository, in plain text, under MIT. You can read it, diff it, fork it,
> and patch it before you trust it.

This page is the contract. It tells you exactly what numasec tells the model, for each
of the five kinds. The files below are the source of truth — when in doubt, read the
file, not this page.

## Kind prompts

| Kind     | Glyph | File                                                   | Tagline                                          |
| -------- | ----- | ------------------------------------------------------ | ------------------------------------------------ |
| security | `◈`   | [`packages/numasec/src/agent/prompt/security.txt`][p1] | Security Jarvis on your terminal                  |
| pentest  | `◆`   | [`packages/numasec/src/agent/prompt/pentest.txt`][p2]  | Authorized engagement, scope → findings → report |
| appsec   | `❮❯`  | [`packages/numasec/src/agent/prompt/appsec.txt`][p3]   | Read the code like a reviewer                    |
| osint    | `⌬`   | [`packages/numasec/src/agent/prompt/osint.txt`][p4]    | Find what is already public                      |
| hacking  | `⚑`   | [`packages/numasec/src/agent/prompt/hacking.txt`][p5]  | Just hack, no ceremony                           |

[p1]: ../packages/numasec/src/agent/prompt/security.txt
[p2]: ../packages/numasec/src/agent/prompt/pentest.txt
[p3]: ../packages/numasec/src/agent/prompt/appsec.txt
[p4]: ../packages/numasec/src/agent/prompt/osint.txt
[p5]: ../packages/numasec/src/agent/prompt/hacking.txt

## Helper prompts

These are not user‑facing kinds; they drive specific subsystems.

| Purpose      | File                                                       |
| ------------ | ---------------------------------------------------------- |
| Title        | `packages/numasec/src/agent/prompt/title.txt`              |
| Summary      | `packages/numasec/src/agent/prompt/summary.txt`            |
| Compaction   | `packages/numasec/src/agent/prompt/compaction.txt`         |
| Explore mode | `packages/numasec/src/agent/prompt/explore.txt`            |
| Provider     | `packages/numasec/src/session/prompt/anthropic.txt`        |

## Reading guide

1. **Start with `security.txt`** to understand the baseline persona numasec gives the
   model when no specific kind is selected.
2. **Compare it with `pentest.txt`** to see how the structured offensive workflow
   diverges from the conversational baseline.
3. **`hacking.txt` is intentionally raw** — minimal commentary, low ceremony. Do not
   confuse "raw" with "unbounded": the boundary guard still applies.
4. **`appsec.txt` is reviewer‑oriented** (read‑first, verify with code paths) and
   **`osint.txt` is intel‑oriented** (passive, source‑provenance aware).

## How prompts are loaded

Prompts are bundled at build time and resolved per session via the agent layer:

- Kind packs (`packages/numasec/src/core/kind/index.ts`) declare which **agent name**
  drives a kind.
- The agent layer reads the matching `agent/prompt/<name>.txt` file and prepends it as
  the system prompt for that session.
- Anything you read in those `.txt` files is what the model sees first.

## Stability

Prompts are not API. They will change. When they change, the change is in the git log,
under a commit message that explains why. We do not silently rotate prompts.

## Contributing

Prompt edits land in normal pull requests. We expect:

1. A short rationale in the PR description (what behavior the prompt is fixing).
2. A before/after side‑by‑side for any deletion of guidance.
3. A test session transcript on at least one canonical scenario (we will add a
   `docs/PROMPT_FIXTURES.md` directory as the catalogue grows).

— numasec maintainers
