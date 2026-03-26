"""MCP prompt templates -- structured workflows for threat modeling and code review."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("security_mcp.mcp.prompts")


def register_prompts(mcp: Any) -> None:
    """Register MCP prompt templates with the server."""

    @mcp.prompt()
    def threat_model(
        target: str,
        architecture: str = "",
        data_flows: str = "",
        trust_boundaries: str = "",
    ) -> str:
        """Generate a threat model using STRIDE methodology.

        Analyzes target architecture to identify threats, attack vectors,
        and recommended mitigations. Based on OWASP Threat Modeling guidelines.

        Args:
            target: Application name or URL to model.
            architecture: Description of the system architecture (components, APIs, DBs).
            data_flows: Description of data flows between components.
            trust_boundaries: Where trust levels change (e.g., internet->DMZ->internal).
        """
        sections = [
            "# Threat Model Analysis",
            "",
            f"## Target: {target}",
            "",
            "Perform a STRIDE-based threat model for the target application.",
            "",
            "## STRIDE Categories to Analyze",
            "",
            "For each category, identify specific threats, affected components, "
            "likelihood (High/Medium/Low), impact (High/Medium/Low), and mitigations.",
            "",
            "### 1. Spoofing (Authentication)",
            "- Can an attacker impersonate a legitimate user or service?",
            "- Check: authentication mechanisms, token validation, certificate pinning",
            "",
            "### 2. Tampering (Integrity)",
            "- Can data be modified in transit or at rest?",
            "- Check: input validation, HMAC/signatures, database integrity constraints",
            "",
            "### 3. Repudiation (Non-repudiation)",
            "- Can actions be denied by the actor?",
            "- Check: audit logging, timestamps, digital signatures",
            "",
            "### 4. Information Disclosure (Confidentiality)",
            "- Can sensitive data be exposed?",
            "- Check: encryption at rest/transit, error messages, debug endpoints",
            "",
            "### 5. Denial of Service (Availability)",
            "- Can the service be disrupted?",
            "- Check: rate limiting, resource limits, input size validation",
            "",
            "### 6. Elevation of Privilege (Authorization)",
            "- Can an attacker gain higher privileges?",
            "- Check: RBAC, least privilege, vertical/horizontal escalation paths",
            "",
        ]

        if architecture:
            sections.extend(["## Architecture Context", "", architecture, ""])

        if data_flows:
            sections.extend(["## Data Flows", "", data_flows, ""])

        if trust_boundaries:
            sections.extend(["## Trust Boundaries", "", trust_boundaries, ""])

        sections.extend(
            [
                "## Expected Output Format",
                "",
                "For each identified threat, provide:",
                "",
                "| # | STRIDE Category | Threat | Component | Likelihood | Impact | Mitigation |",
                "|---|----------------|--------|-----------|-----------|--------|------------|",
                "| 1 | Spoofing | ... | ... | High/Med/Low | High/Med/Low | ... |",
                "",
                "Then provide:",
                "1. **Risk Matrix**: Summary of High/Critical risks",
                "2. **Attack Tree**: Top 3 most likely attack paths",
                "3. **Recommended Security Controls**: Prioritized list of mitigations",
                "4. **OWASP Top 10 Mapping**: Which OWASP categories apply",
            ]
        )

        return "\n".join(sections)

    @mcp.prompt()
    def code_review(
        code: str,
        language: str = "auto",
        context: str = "",
        focus: str = "security",
    ) -> str:
        """Security-focused code review using OWASP and CWE guidelines.

        Analyzes code for vulnerabilities, misconfigurations, and security
        anti-patterns. Returns findings with severity, CWE IDs, and fix suggestions.

        Args:
            code: The source code to review.
            language: Programming language (auto-detected if not specified).
            context: Additional context (e.g., "this handles user authentication").
            focus: Review focus -- security, all, or specific CWE category.
        """
        sections = [
            "# Security Code Review",
            "",
            f"**Language**: {language}",
            f"**Focus**: {focus}",
            "",
        ]

        if context:
            sections.extend(["## Context", "", context, ""])

        sections.extend(
            [
                "## Code Under Review",
                "",
                "```",
                code,
                "```",
                "",
                "## Review Checklist",
                "",
                "Analyze the code above for the following vulnerability classes:",
                "",
                "### Injection (CWE-89, CWE-78, CWE-79, CWE-94, CWE-1336)",
                "- SQL/NoSQL injection via string concatenation",
                "- OS command injection via shell=True or exec()",
                "- XSS via innerHTML, dangerouslySetInnerHTML, or template |safe",
                "- SSTI via user input in template rendering",
                "",
                "### Broken Authentication (CWE-287, CWE-307, CWE-384)",
                "- Hardcoded credentials or API keys",
                "- Weak password validation",
                "- Missing rate limiting on auth endpoints",
                "- Insecure session management",
                "",
                "### Broken Access Control (CWE-639, CWE-862, CWE-863)",
                "- Missing authorization checks",
                "- IDOR via user-controlled IDs",
                "- Privilege escalation paths",
                "",
                "### Cryptographic Failures (CWE-327, CWE-328, CWE-311)",
                "- Weak hashing (MD5, SHA1 for passwords)",
                "- Missing encryption for sensitive data",
                "- Hardcoded secrets or keys",
                "",
                "### Security Misconfiguration (CWE-16, CWE-200, CWE-532)",
                "- Debug mode enabled in production",
                "- Verbose error messages exposing internals",
                "- Sensitive data in logs",
                "- Missing security headers",
                "",
                "### Data Exposure (CWE-200, CWE-209)",
                "- Sensitive data in responses or URLs",
                "- Stack traces in error responses",
                "- PII not properly handled",
                "",
                "## Expected Output Format",
                "",
                "For each finding:",
                "",
                "### Finding [N]: [Title]",
                "- **Severity**: Critical / High / Medium / Low / Info",
                "- **CWE**: CWE-XXX",
                "- **OWASP**: A0X:2021",
                "- **Line(s)**: [line numbers]",
                "- **Description**: What the vulnerability is and why it's dangerous",
                "- **Impact**: What an attacker could do",
                "- **Fix**: Concrete code fix (before/after)",
                "",
                "End with a summary table and overall risk rating.",
            ]
        )

        return "\n".join(sections)

    @mcp.prompt()
    def security_assessment(
        target: str,
        scope: str = "standard",
        notes: str = "",
    ) -> str:
        """Guide a PTES-based security assessment using security-mcp tools.

        Args:
            target: Target URL or IP address to assess.
            scope: Assessment scope -- quick, standard, or deep.
            notes: Optional context about the target.
        """
        phase_map: dict[str, list[str]] = {
            "quick": ["RECON", "MAPPING", "VULNERABILITY", "REPORTING"],
            "standard": ["RECON", "MAPPING", "VULNERABILITY", "EXPLOITATION", "REPORTING"],
            "deep": ["RECON", "MAPPING", "VULNERABILITY", "EXPLOITATION", "POST_EXPLOITATION", "REPORTING"],
        }
        phases = phase_map.get(scope, phase_map["standard"])

        sections = [
            "# Security Assessment",
            "",
            f"**Target**: {target}",
            f"**Scope**: {scope} ({len(phases)} phases)",
            "",
            "## Workflow",
            "",
            "1. `create_session(target)` -- get session_id",
            "2. `recon(target, checks='ports,tech')` -- discover services/technologies",
            "3. `crawl(url)` -- discover endpoints (auto-detects SPA)",
            "4. `plan(action='mandatory_tests', target=..., endpoints=...)` -- get test tasks",
            "5. Execute tasks using vulnerability tools below",
            "6. On auth success: `plan(action='post_auth', token=...)` -- 8-tier post-auth plan",
            "7. `plan(action='coverage_gaps', session_id=...)` -- verify OWASP Top 10 coverage",
            "8. `generate_report(session_id, format='sarif')`",
            "",
            "## Tool Guide",
            "",
            "| Intent | Tool | Key Parameters |",
            "|--------|------|----------------|",
            "| Reconnaissance | `recon` | checks: ports,tech,subdomains,dns |",
            "| Endpoint discovery | `crawl` | url, force_browser |",
            "| Injection (SQLi/NoSQLi/SSTI/CMDi) | `injection_test` | types, headers, waf_evasion |",
            "| XSS | `xss_test` | url, params, headers |",
            "| Access control (IDOR/CSRF/CORS) | `access_control_test` | checks, headers |",
            "| Auth / JWT | `auth_test` | url |",
            "| SSRF | `ssrf_test` | url, headers |",
            "| Path (LFI/XXE/redirect) | `path_test` | checks, headers |",
            "| Directory fuzzing | `dir_fuzz` | url, extensions |",
            "| JS analysis | `js_analyze` | url |",
            "| Manual HTTP | `http_request` | url, method, headers, body |",
            "| Browser | `browser` | action: navigate/click/fill/screenshot |",
            "| Blind detection | `oob` | action: setup/poll |",
            "| Planning & coverage | `plan` | action: initial/mandatory_tests/coverage_gaps/post_auth/chain |",
            "| Knowledge base | `kb_search` | query, type: search/cwe/attack_patterns |",
            "| Parallel scans | `run_scanner_batch` | session_id, tasks |",
            "",
        ]

        phase_details: dict[str, str] = {
            "RECON": "`recon(target, checks='ports,tech')`. Probe /metrics, /actuator, /robots.txt, /.env. Run `js_analyze`.",
            "MAPPING": "`crawl(url)`. Classify: auth endpoints, numeric IDs (IDOR), JSON (NoSQL), state-changing (CSRF). Then `plan(action='mandatory_tests')`.",
            "VULNERABILITY": "Execute ALL mandatory_tests. On auth success -> `plan(action='post_auth')`. Ensure OWASP Top 10 coverage.",
            "EXPLOITATION": "Chain findings via `plan(action='chain')`. UNION extraction, token forging, privilege escalation via `http_request`.",
            "POST_EXPLOITATION": "Assess impact: privilege escalation, data exposure, lateral movement. Validate severity ratings.",
            "REPORTING": "`plan(action='coverage_gaps')` -> execute gaps -> `generate_report(session_id, format)`.",
        }

        for i, phase in enumerate(phases, 1):
            sections.append(f"**Phase {i} -- {phase}**: {phase_details.get(phase, '')}")

        sections.extend([
            "",
            "## Principles",
            "",
            "- All tools accept `headers` for authenticated testing -- pass auth tokens to every scanner",
            "- OWASP Top 10 coverage mandatory -- `plan(action='coverage_gaps')` before reporting",
            "- Adapt to target -- skip irrelevant tests, add relevant ones based on tech stack",
            "- Findings auto-enrich with CWE, CVSS v3.1, OWASP category, ATT&CK technique",
            "- Chain findings: SQLi->RCE, SSRF->cloud metadata, XXE->file read, LFI->log poisoning, SSTI->RCE",
            "- Business logic: `kb_search(query='business logic')` for methodology -> `http_request` on discovered endpoints",
        ])

        if notes:
            sections.extend(["", "## Notes", "", notes])

        return "\n".join(sections)
