# numasec Agent (TypeScript TUI)

The interactive terminal UI for numasec. Forked from [OpenCode](https://github.com/opencode-ai/opencode) (MIT) and specialized for penetration testing.

## Architecture

TypeScript TUI → TypeScript security runtime (v2 primitives + compatibility wrappers)

## Agents

5 primary agents (cycle with Tab):
- **pentest** — Full PTES methodology (default)
- **recon** — Reconnaissance only, no exploitation
- **hunt** — Systematic OWASP Top 10 vulnerability hunting
- **review** — Secure code review (AppSec)
- **report** — Report generation and finding management

3 subagents (delegated automatically):
- **scanner** — Automated scan execution
- **analyst** — False positive elimination, attack chain correlation
- **explore** — Target reconnaissance and source analysis

## Development

```bash
bun install
bun typecheck
bun test
```

## Slash Commands (v2)

Canonical workflow commands:
- `/scope set <target>` — Set engagement scope and start recon
- `/scope show` — Show current scope and observed surface
- `/hypothesis list` — List graph hypotheses
- `/verify next` — Plan next verification step
- `/evidence list` / `/evidence show <id-or-title>` — Evidence views
- `/chains list` — Show derived attack chains
- `/finding list` — List findings
- `/remediation plan` — Prioritized remediation guidance
- `/retest run [filter]` — Deterministic retest replay
- `/report status` — Report readiness and remaining closure debt
- `/report generate [markdown|html|sarif] [--out <path>] [--final] [--note <text>]` — Working report by default, or closure-gated final export with `--final`

Additional commands:
- `/coverage` — OWASP Top 10 coverage status
- `/creds` — Discovered credentials (masked)
- `/review` — Security review of code changes
- `/init` — Generate security profile for target app

Legacy aliases (soft-deprecated, still supported in v1.x):
- `/target <url>` → `/scope set <url>`
- `/findings` → `/finding list`
- `/report <format>` → `/report generate <format>`
- `/evidence` → `/evidence list`
- `/evidence <id-or-title>` → `/evidence show <id-or-title>`

Migration policy:
- v2 names are the default UX from v1.0.5 onward.
- No legacy alias removals in v1.x.
- Earliest alias removal target is v2.0+ with release-note notice.

## v1 → v2 cutover note (release 1.0.5)

- Operational rollout/rollback runbook is documented in the repository root `README.md` (`v1 to v2 cutover runbook` section).
- Active migration flags for this release:
  - `NUMASEC_SECURITY_GRAPH_WRITE`
  - `NUMASEC_SECURITY_GRAPH_READ`
- `NUMASEC_SECURITY_V2_PLANNER` and `NUMASEC_SECURITY_V2_TUI` are declared but not active rollout gates in v1.0.5.
