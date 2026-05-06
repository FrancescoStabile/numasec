# Changelog

## 1.2.0

numasec 1.2.0 is the release where the project becomes a real cyber operator console.

It gives the agent an operation, a scope, local tools, evidence, replay material, findings with lifecycle, cyber knowledge, and reports that come from proof instead of vibes. The point is simple: if AI agents are becoming normal for coding, security deserves one built for the way hackers, pentesters, AppSec engineers, and bug bounty hunters actually work.

### Highlights

- Operations now have real state: ledger events, projected facts, relations, evidence, replay, workflow, and deliverables.
- The TUI now behaves like an operation console, with lenses for findings, evidence, replay, workflow, and report state.
- AppSec and Pentest are the hard-gated 1.2 domains. Other cyber domains exist, but they are maturity-labeled instead of overclaimed.
- Findings now move through candidate, observed, verified, rejected, stale, and reportable states.
- A finding is not reportable just because the model sounds confident. It needs evidence and replay material, or an explicit structured replay exemption.
- The `knowledge` tool now acts as a Cyber Knowledge Broker for vulnerability intelligence, KEV/EPSS enrichment, applicability states, and safe next actions.
- Reports are built from operation state, not from a polished chat transcript.
- Runtime readiness now matters: numasec tracks installed tools, degraded capabilities, and what the local environment can actually do.

### Operator workflow

- Start with `/pwn <target>` to create a scoped pentest operation and kick off the right starter capsule.
- Use `/runbook run web-surface <target>` to map a web target through the runbook surface.
- Use `/runbook run appsec-web-triage <target>` for AppSec triage with evidence and candidate findings.
- Use `/doctor` to see which local tools are ready, degraded, or missing.
- Build reports only after the operation has enough state to support them.

### Release gates

The CI/CD release gate for 1.2.0 is:

- `bun typecheck`
- `cd packages/numasec && bun test --timeout 30000`
- `cd packages/numasec && bun run build`

AppSec and Pentest benchmarks remain local/manual validation tools for release confidence and product claims. They are not run inside GitHub Actions.

### Community

Thanks to the bug bounty hunters, security researchers, and early users who tested numasec in real workflows and shared candid feedback.

Special thanks to Deafen, a bug bounty hunter who tested numasec in real bounty work, shared useful feedback, and told me about successful results using it. That is the kind of signal that matters: numasec has to work outside demos.

Special thanks to @wendellmeset for putting real time into the project and opening detailed public issues. Those reports caught rough edges in the terminal UX and helped make this release harder to break.

### Compatibility

- `numasec.md` remains available as a derived context pack, but it is not canonical operation state.
- `cve` remains as a compatibility alias for CVE-style lookup. New cyber research should use `knowledge`.
- numasec uses installed tools. It does not bundle Kali, Burp, nuclei, nmap, ffuf, sqlmap, trivy, or similar binaries.

### Known limitations

- AppSec and Pentest are the only maturity-gated domains in this release.
- OSINT, CTF/hacking, cloud/container/IaC, forensics, and binary workflows are present with maturity labels and should not be marketed as equally benchmarked yet.
- The oracle layer verifies proof shape and lifecycle constraints; it is not an automatic exploitability oracle.
- Live benchmark runs require a configured model provider credential when executed manually.
