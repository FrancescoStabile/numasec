# Changelog

## 1.2.0

numasec 1.2.0 turns the project into a terminal-native AI cyber operator harness: scoped operations, runbooks, real local tools, evidence, replay, finding lifecycle, knowledge, and report generation in one workflow.

### Highlights

- Repositioned numasec around cyber operations instead of generic coding assistance.
- Added kernel-first operation state for ledger events, facts, relations, evidence, replay, workflow, and deliverables.
- Promoted AppSec and Pentest to evidence-backed release domains with local benchmark coverage.
- Added operation lenses in the terminal UI for findings, evidence, replay, workflow, and report state.
- Tightened finding semantics across candidate, observed, verified, rejected, stale, and reportable states.
- Made reportability require evidence plus replay material, or an explicit structured replay exemption.
- Added Cyber Knowledge Broker support through the `knowledge` tool for vulnerability intelligence, KEV/EPSS enrichment, applicability states, and safe next actions.
- Added operation sharing, report building, AppSec/Pentest runbooks, and runtime readiness/capability state.

### Operator workflow

- `/pwn <target>` creates a scoped pentest operation and selects the appropriate starter capsule.
- `/runbook run web-surface <target>` maps web attack surface through the runbook surface.
- `/runbook run appsec-web-triage <target>` performs AppSec triage with evidence and candidate findings.
- `/doctor` reports local tool readiness and degraded capabilities.
- report tooling builds deliverables from operation state rather than chat transcript confidence.

### Release gates

The CI/CD release gate for 1.2.0 is:

- `bun typecheck`
- `cd packages/numasec && bun test --timeout 30000`
- `cd packages/numasec && bun run build`

AppSec and Pentest benchmarks remain local/manual validation tools for release confidence and product claims. They are not run inside GitHub Actions.

### Community

Thanks to the bug bounty hunters, security researchers, and early users who tested numasec in real workflows and shared candid feedback.

Special thanks to @wendellmeset for putting real time into the project and opening detailed issues. Those reports caught rough edges in the terminal UX and helped make this release harder to break.

### Compatibility

- `numasec.md` remains available as a derived context pack, but it is not canonical operation state.
- `cve` remains as a compatibility alias for CVE-style lookup. New cyber research should use `knowledge`.
- numasec uses installed tools. It does not bundle Kali, Burp, nuclei, nmap, ffuf, sqlmap, trivy, or similar binaries.

### Known limitations

- AppSec and Pentest are the only maturity-gated domains in this release.
- OSINT, CTF/hacking, cloud/container/IaC, forensics, and binary workflows are present with maturity labels and should not be marketed as equally benchmarked yet.
- The oracle layer verifies proof shape and lifecycle constraints; it is not an automatic exploitability oracle.
- Live benchmark runs require a configured model provider credential when executed manually.
