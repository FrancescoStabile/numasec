# numasec Tool Reference

This page describes the built in tool palette that ships with numasec 1.1.7.
These are the tool ids the agents actually see at runtime.

## File and code tools

- `read`, `write`, `edit`, `patch`
- `glob`, `grep`, `code`
- `bash`

These are the basic filesystem and search primitives. `bash` is still the escape
hatch when you want to drive binaries already installed on the machine.

## Session and orchestration tools

- `task`
- `todo`
- `skill`
- `fetch`
- `search`
- `question` when the current client allows operator prompts
- `plan` when experimental plan mode is enabled in the CLI

These tools keep long sessions usable: background work, planning, web fetch,
web search, code search, and skill loading.

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

In practice, this is the core of numasec.

`httprequest` handles raw HTTP with auth, cookies, redirects, and replay.
`browser` is a Playwright driven browser for navigation, interaction, and state
inspection. `scanner` covers built in surface mapping primitives such as crawl,
dir fuzz, JavaScript analysis, port scan, service probe, and banner grabs.
`vault` replaces the old split between auth and secrets storage with one place
for local credentials and profiles.

The adapter tools expose deeper vertical workflows without bundling every
security binary into numasec:

- `cloud_posture` runs cloud posture checks through local adapters such as `prowler`
- `container_surface` triages container images through local adapters such as `trivy`
- `iac_triage` checks infrastructure-as-code through the local `checkov` adapter
- `binary_triage` gathers binary metadata and quick reverse-engineering signals from local utilities

If an adapter is missing, the tool reports an unavailable/degraded state instead
of pretending work was performed.

## Engagement workflow tools

- `doctor`
- `play`
- `pwn_bootstrap`
- `opsec`
- `share`
- `remediate`

These are the tools that turn the primitive palette into an operator workflow.

- `doctor` checks runtime, workspace, CVE bundle, vault mode, and missing local tools
- `play` expands a reusable workflow into an ordered step trace
- `pwn_bootstrap` creates and activates an operation, then selects the right play and default agent
- `opsec` inspects or changes the operation guard level
- `share` builds a redacted handoff archive for the active operation
- `remediate` turns an observation into reviewable advice or patch scaffolding

## A note on external binaries

numasec does not bundle tools like `nmap`, `sqlmap`, `ffuf`, `nuclei`, `prowler`,
`trivy`, `checkov`, `checksec`, or Burp.
It can still use them through `bash`, and `/doctor` will tell you what is present
or missing on your machine.
