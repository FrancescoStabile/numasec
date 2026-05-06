# numasec Tool Reference

This page describes the built-in tool palette exposed by numasec.
These are the runtime tool ids the agents actually see.

## File and code tools

- `read`, `write`, `edit`, `apply_patch`
- `glob`, `grep`, `code`
- `bash`

These are the base filesystem and search primitives. `bash` remains the escape hatch when you need to drive installed local binaries directly.

## Session and orchestration tools

- `task`
- `todo`
- `skill`
- `fetch`
- `search`
- `question` when the current client allows operator prompts
- `plan` when experimental plan mode is enabled in the CLI

These tools keep long sessions usable: background work, planning, web fetch, web search, code search, and skill loading.

## Security primitives

- `httprequest`
- `browser`
- `scanner`
- `crypto`
- `net`
- `vault`
- `interact`
- `methodology`
- `cve`
- `cloud_posture`
- `container_surface`
- `iac_triage`
- `binary_triage`

In practice, this is the cyber operator core.

`httprequest` handles raw HTTP with auth, cookies, redirects, and replay.
`browser` is the Playwright-driven browser for navigation, interaction, and state inspection.
`scanner` covers surface mapping primitives such as crawl, dir fuzz, JavaScript analysis, port scan, service probe, and banner grabs.
`vault` provides one place for local credentials and profiles.

The adapter tools expose deeper vertical workflows without bundling every
security binary into numasec:

- `cloud_posture` runs cloud posture checks through local adapters such as `prowler`
- `container_surface` triages container images through local adapters such as `trivy`
- `iac_triage` checks infrastructure-as-code through the local `checkov` adapter
- `binary_triage` gathers binary metadata and quick reverse-engineering signals from local utilities

If an adapter is missing, the tool reports an unavailable or degraded state instead of pretending work was performed.

## Cyber workflow tools

- `doctor`
- `runbook`
- `play`
- `pwn_bootstrap`
- `workspace`
- `scope`
- `opsec`
- `identity`
- `evidence`
- `observation`
- `knowledge`
- `finding`
- `report`
- `autonomy`
- `share`
- `remediate`
- `appsec_probe`
- `analyze`

These tools turn the primitive palette into an operator workflow.

- `doctor` checks runtime, workspace, CVE bundle, vault mode, and missing local tools
- `runbook` is the primary semantic capsule surface for operator workflows
- `play` is the lower-level primitive behind `runbook`
- `pwn_bootstrap` classifies a target and initializes a pentest operation
- `workspace` manages operation state, operation metadata, and current posture
- `scope` records and evaluates operation boundaries
- `opsec` inspects or changes the operation guard level
- `identity` tracks active personas, credentials, and test identities without exposing secrets
- `evidence` stores or references proof artifacts
- `observation` records evidence-backed signals that are not yet findings
- `knowledge` pulls supporting knowledge with provenance
- `finding` manages candidate, verified, rejected, and stale finding state
- `report` builds deliverables and report output
- `autonomy` switches between permissioned and auto execution posture
- `share` builds a redacted handoff archive for the active operation
- `remediate` turns an observation into reviewable advice or patch scaffolding
- `appsec_probe` runs bounded, observed-surface AppSec probes without hardcoded lab paths
- `analyze` summarizes operation state and projected cyber signals

## A note on external binaries

numasec does not bundle tools like `nmap`, `sqlmap`, `ffuf`, `nuclei`, `prowler`, `trivy`, `checkov`, `checksec`, or Burp.
It can still use them through `bash`, and `/doctor` will tell you what is present or missing on the current machine.
