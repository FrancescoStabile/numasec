# numasec Agent (TypeScript TUI)

The interactive terminal UI for numasec. Forked from [OpenCode](https://github.com/opencode-ai/opencode) (MIT) and specialized for penetration testing.

## Architecture

TypeScript TUI → JSON-RPC bridge → Python MCP scanners (21 tools)

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

## Slash Commands

- `/target <url>` — Set assessment target
- `/findings` — View discovered vulnerabilities
- `/report` — Generate security report
- `/coverage` — OWASP Top 10 coverage status
- `/creds` — Manage discovered credentials
- `/evidence` — Attach evidence to findings
