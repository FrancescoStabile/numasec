"""
NumaSec — Hierarchical Attack Planner

Decomposes objectives into structured attack phases.
Tracks progress and guides the LLM by injecting plan status into context.

The planner does NOT execute — it GUIDES the LLM.

v3.2: Added PLAN_TEMPLATES for target-type-aware plans and
      generate_plan_with_llm() for LLM-customised attack plans.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, TYPE_CHECKING

from numasec.target_profile import TargetProfile

if TYPE_CHECKING:
    from numasec.router import LLMRouter

logger = logging.getLogger(__name__)


class PhaseStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETE = "complete"
    SKIPPED = "skipped"


@dataclass
class AttackStep:
    """A single step within an attack phase."""
    description: str
    tool_hint: str = ""
    status: PhaseStatus = PhaseStatus.PENDING
    result_summary: str = ""


@dataclass
class AttackPhase:
    """A phase of the pentest methodology."""
    name: str
    objective: str
    steps: list[AttackStep] = field(default_factory=list)
    status: PhaseStatus = PhaseStatus.PENDING
    skip_condition: str = ""

    def progress(self) -> str:
        total = len(self.steps)
        done = sum(1 for s in self.steps if s.status in (PhaseStatus.COMPLETE, PhaseStatus.SKIPPED))
        return f"{done}/{total}"


@dataclass
class AttackPlan:
    """Full attack plan with phases."""
    objective: str
    phases: list[AttackPhase] = field(default_factory=list)
    created_at: str = ""

    def current_phase(self) -> AttackPhase | None:
        """Get the currently active phase."""
        for phase in self.phases:
            if phase.status == PhaseStatus.ACTIVE:
                return phase
        # If no phase is active, activate the first pending
        for phase in self.phases:
            if phase.status == PhaseStatus.PENDING:
                phase.status = PhaseStatus.ACTIVE
                return phase
        return None

    def advance_phase(self):
        """Mark current phase complete and activate next."""
        for i, phase in enumerate(self.phases):
            if phase.status == PhaseStatus.ACTIVE:
                phase.status = PhaseStatus.COMPLETE
                for j in range(i + 1, len(self.phases)):
                    if self.phases[j].status == PhaseStatus.PENDING:
                        self.phases[j].status = PhaseStatus.ACTIVE
                        return
                return

    def skip_phase(self, phase_name: str, reason: str = ""):
        """Skip a phase."""
        for phase in self.phases:
            if phase.name == phase_name:
                phase.status = PhaseStatus.SKIPPED
                for step in phase.steps:
                    step.status = PhaseStatus.SKIPPED
                    step.result_summary = reason or "Skipped"

    def mark_step_complete(self, tool_name: str, result_summary: str = "", *, is_failure: bool = False):
        """Mark a step complete by matching tool hint.
        
        Only matches steps whose tool_hint is an exact match for the tool name.
        Steps without a tool_hint are left for the LLM to advance manually.
        Failed tool calls do not mark steps complete.
        """
        if is_failure:
            return  # failed tool = step NOT done
        current = self.current_phase()
        if not current:
            return
        for step in current.steps:
            if step.status == PhaseStatus.PENDING and step.tool_hint:
                # Exact match — "http" must not match "httpx"
                if step.tool_hint == tool_name:
                    step.status = PhaseStatus.COMPLETE
                    step.result_summary = result_summary[:200]
                    return

    def is_complete(self) -> bool:
        return all(p.status in (PhaseStatus.COMPLETE, PhaseStatus.SKIPPED) for p in self.phases)

    def to_prompt_summary(self) -> str:
        """Generate plan summary for LLM context injection."""
        lines = [f"## Testing Plan: {self.objective}\n"]

        for i, phase in enumerate(self.phases, 1):
            status_icon = {
                PhaseStatus.PENDING: "[ ]",
                PhaseStatus.ACTIVE: "[>]",
                PhaseStatus.COMPLETE: "[x]",
                PhaseStatus.SKIPPED: "[-]",
            }.get(phase.status, "?")

            lines.append(f"{status_icon} **Phase {i}: {phase.name}** [{phase.progress()}]")
            lines.append(f"  Objective: {phase.objective}")

            if phase.status == PhaseStatus.ACTIVE:
                for j, step in enumerate(phase.steps, 1):
                    step_icon = {
                        PhaseStatus.PENDING: "  [ ]",
                        PhaseStatus.ACTIVE: "  [>]",
                        PhaseStatus.COMPLETE: "  [x]",
                        PhaseStatus.SKIPPED: "  [-]",
                    }.get(step.status, "  ?")
                    lines.append(f"{step_icon} {j}. {step.description}")
                    if step.tool_hint:
                        lines.append(f"       hint: {step.tool_hint}")
                    if step.result_summary:
                        lines.append(f"       result: {step.result_summary}")

        lines.append("")
        lines.append("**INSTRUCTION**: Follow the active phase ([>]). Complete each step, then move to the next.")
        lines.append("If a phase doesn't apply to this target, skip it and explain why.")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> AttackPlan:
        if not data:
            return cls(objective="")
        plan = cls(objective=data.get("objective", ""))
        plan.created_at = data.get("created_at", "")
        for phase_data in data.get("phases", []):
            steps = []
            for s in phase_data.get("steps", []):
                step = AttackStep(
                    description=s.get("description", ""),
                    tool_hint=s.get("tool_hint", ""),
                    status=PhaseStatus(s.get("status", "pending")),
                    result_summary=s.get("result_summary", ""),
                )
                steps.append(step)
            phase = AttackPhase(
                name=phase_data.get("name", ""),
                objective=phase_data.get("objective", ""),
                steps=steps,
                status=PhaseStatus(phase_data.get("status", "pending")),
                skip_condition=phase_data.get("skip_condition", ""),
            )
            plan.phases.append(phase)
        return plan


def generate_plan(objective: str, profile: TargetProfile) -> AttackPlan:
    """
    Generate an attack plan based on the objective and current knowledge.
    This is a heuristic plan — the LLM can adapt it during execution.

    Used as the **synchronous fallback** when no LLM router is available.
    Prefer ``generate_plan_with_llm`` when a router is at hand.
    """
    plan = AttackPlan(objective=objective)

    # ── Phase 1: Reconnaissance ──
    recon_steps = []

    if not profile.ports:
        recon_steps.append(AttackStep(
            description="Port scan target to find open services",
            tool_hint="nmap",
        ))
    else:
        recon_steps.append(AttackStep(
            description=f"Port scan already done ({len(profile.get_open_ports())} open ports)",
            status=PhaseStatus.COMPLETE,
        ))

    if profile.get_web_ports() or not profile.ports:
        recon_steps.append(AttackStep(
            description="HTTP probe to identify web technologies",
            tool_hint="httpx",
        ))

    recon_steps.append(AttackStep(
        description="Check for common exposed files (/robots.txt, /.git, /.env, /admin)",
        tool_hint="http",
    ))

    plan.phases.append(AttackPhase(
        name="Discovery",
        objective="Find what's running: ports, services, technologies, endpoints",
        steps=recon_steps,
    ))

    # ── Phase 2: Enumeration ──
    enum_steps = [
        AttackStep(
            description="Directory and file fuzzing on web ports",
            tool_hint="ffuf",
        ),
        AttackStep(
            description="Identify all input parameters (forms, query params, headers)",
            tool_hint="browser_navigate",
        ),
        AttackStep(
            description="Technology fingerprinting and version detection",
            tool_hint="httpx",
        ),
    ]

    plan.phases.append(AttackPhase(
        name="Mapping",
        objective="Map all pages, forms, and inputs that need testing",
        steps=enum_steps,
        skip_condition="No web service found",
    ))

    # ── Phase 3: Vulnerability Testing ──
    vuln_steps = [
        AttackStep(
            description="Test parameters for SQL injection (manual first, then sqlmap)",
            tool_hint="http",
        ),
        AttackStep(
            description="Test inputs for XSS (reflected, stored, DOM)",
            tool_hint="browser_fill",
        ),
        AttackStep(
            description="Test for file inclusion (LFI/RFI)",
            tool_hint="http",
        ),
        AttackStep(
            description="Test for SSTI (Server-Side Template Injection)",
            tool_hint="http",
        ),
        AttackStep(
            description="Test for authentication bypass and IDOR",
            tool_hint="http",
        ),
        AttackStep(
            description="Run nuclei for known CVEs",
            tool_hint="nuclei",
        ),
    ]

    plan.phases.append(AttackPhase(
        name="Security Testing",
        objective="Test all discovered pages and inputs for security issues",
        steps=vuln_steps,
    ))

    # ── Phase 4: Exploitation ──
    plan.phases.append(AttackPhase(
        name="Deep Analysis",
        objective="Verify and demonstrate confirmed vulnerabilities with proof",
        steps=[
            AttackStep(
                description="Exploit confirmed vulnerabilities for proof-of-concept",
            ),
            AttackStep(
                description="Attempt privilege escalation if initial access obtained",
            ),
            AttackStep(
                description="Extract sensitive data as evidence (credentials, configs)",
            ),
        ],
    ))

    # ── Phase 5: Reporting ──
    plan.phases.append(AttackPhase(
        name="Results",
        objective="Summarize what was found, how to fix it, and what to do first",
        steps=[
            AttackStep(
                description="Report each vulnerability with [FINDING: SEVERITY] format",
            ),
            AttackStep(
                description="Provide remediation recommendations",
            ),
        ],
    ))

    return plan


# ────────────────────────────────────────────────────────────────────
# §4.3 — Plan Templates & LLM-Powered Planner
# ────────────────────────────────────────────────────────────────────

# Target-type → specialised phases.  Each entry is a list of (name, objective, steps[]).
# The heuristic ``detect_target_type`` maps a TargetProfile to a key.

PLAN_TEMPLATES: dict[str, list[dict]] = {
    # ── Standard web application ──
    "web_standard": [
        {
            "name": "Discovery",
            "objective": "Enumerate services, technologies, and entry points",
            "steps": [
                ("Port scan / service fingerprint", "nmap"),
                ("HTTP probe – tech fingerprint", "httpx"),
                ("Exposed files: /robots.txt, /.git, /.env, /admin", "http"),
            ],
        },
        {
            "name": "Mapping",
            "objective": "Map pages, forms, parameters, and auth surfaces",
            "steps": [
                ("Directory/file fuzzing", "ffuf"),
                ("Identify inputs — forms, query params, headers", "browser_navigate"),
                ("Technology version detection", "httpx"),
            ],
        },
        {
            "name": "Vulnerability Testing",
            "objective": "Test discovered inputs for common web vulnerabilities",
            "steps": [
                ("SQL injection — manual then sqlmap", "http"),
                ("XSS — reflected, stored, DOM", "browser_fill"),
                ("File inclusion — LFI / RFI", "http"),
                ("SSTI — Server-Side Template Injection", "http"),
                ("Auth bypass & IDOR", "http"),
                ("Known CVEs via nuclei", "nuclei"),
            ],
        },
        {
            "name": "Exploitation",
            "objective": "Prove impact with PoC exploits",
            "steps": [
                ("PoC exploitation of confirmed vulns", ""),
                ("Privilege escalation", ""),
                ("Sensitive data extraction", ""),
            ],
        },
        {
            "name": "Reporting",
            "objective": "Structured findings with remediation",
            "steps": [
                ("Report each vuln with [FINDING: SEVERITY]", ""),
                ("Remediation recommendations", ""),
            ],
        },
    ],

    # ── WordPress / CMS ──
    "wordpress": [
        {
            "name": "Discovery",
            "objective": "Enumerate WordPress version, plugins, themes, users",
            "steps": [
                ("Port scan / service fingerprint", "nmap"),
                ("WP version detection (/readme.html, meta generator)", "http"),
                ("Enumerate plugins via /wp-content/plugins/", "ffuf"),
                ("Enumerate users via /wp-json/wp/v2/users", "http"),
            ],
        },
        {
            "name": "Plugin & Theme Audit",
            "objective": "Identify outdated or vulnerable WP components",
            "steps": [
                ("Scan with nuclei wordpress templates", "nuclei"),
                ("Check plugin versions against WPVulnDB", "http"),
                ("Enumerate theme files for info disclosure", "ffuf"),
            ],
        },
        {
            "name": "Authentication Attacks",
            "objective": "Test login, xmlrpc, and rest-api auth surfaces",
            "steps": [
                ("Test /xmlrpc.php for brute-force amplification", "http"),
                ("Default credentials on /wp-login.php", "browser_fill"),
                ("JWT / application-password bypass if REST API open", "http"),
            ],
        },
        {
            "name": "Vulnerability Testing",
            "objective": "Exploit known plugin / core vulnerabilities",
            "steps": [
                ("SQL injection via plugin parameters", "http"),
                ("File upload abuse (media library or plugin)", "http"),
                ("Theme editor RCE (/wp-admin/theme-editor.php)", "browser_navigate"),
                ("SSRF via oEmbed or plugins", "http"),
            ],
        },
        {
            "name": "Post-Exploitation & Reporting",
            "objective": "Prove impact and document findings",
            "steps": [
                ("Backdoor persistence check", ""),
                ("Data exfiltration from wp_users / wp_options", ""),
                ("Report with [FINDING: SEVERITY]", ""),
            ],
        },
    ],

    # ── REST API ──
    "api_rest": [
        {
            "name": "Discovery",
            "objective": "Map API endpoints, auth scheme, and data model",
            "steps": [
                ("Port scan / service fingerprint", "nmap"),
                ("Fetch OpenAPI/Swagger spec", "http"),
                ("Enumerate routes via fuzzing (/api/v1/*, /graphql)", "ffuf"),
                ("Detect auth: Bearer, API-key, OAuth", "http"),
            ],
        },
        {
            "name": "Authentication & Authorisation",
            "objective": "Test for auth / authz flaws",
            "steps": [
                ("Test JWT manipulation (alg:none, key confusion)", "http"),
                ("IDOR on resource IDs (sequential, UUID prediction)", "http"),
                ("Role escalation (change role param in request)", "http"),
                ("Rate-limit / brute-force on login endpoint", "http"),
            ],
        },
        {
            "name": "Input Validation",
            "objective": "Test all params for injection, mass-assignment, over-fetching",
            "steps": [
                ("SQL / NoSQL injection on query params and body", "http"),
                ("Mass assignment — add extra fields in POST/PUT body", "http"),
                ("SSRF via URL-type params (webhooks, callbacks)", "http"),
                ("GraphQL introspection + deep query injection", "http"),
            ],
        },
        {
            "name": "Business Logic",
            "objective": "Test for logic flaws specific to the API domain",
            "steps": [
                ("Replay / reorder requests for state manipulation", "http"),
                ("Race conditions on sensitive operations", "http"),
                ("Test pagination for data leaks (over-fetching)", "http"),
            ],
        },
        {
            "name": "Reporting",
            "objective": "Structured findings with API-specific remediation",
            "steps": [
                ("Report each vuln with [FINDING: SEVERITY]", ""),
                ("API-specific remediation recommendations", ""),
            ],
        },
    ],

    # ── Single-Page Application (SPA / JavaScript-heavy) ──
    "spa_javascript": [
        {
            "name": "Discovery",
            "objective": "Map client-side routes, APIs, and JS bundles",
            "steps": [
                ("Port scan / service fingerprint", "nmap"),
                ("Browser-based crawl — wait for JS render", "browser_navigate"),
                ("Extract API endpoints from JS bundles", "http"),
                ("Identify framework (React, Vue, Angular)", "httpx"),
            ],
        },
        {
            "name": "Client-Side Analysis",
            "objective": "Analyse JavaScript for secrets and auth logic",
            "steps": [
                ("Search JS source maps for secrets / API keys", "http"),
                ("Analyse client-side routing for hidden admin routes", "browser_navigate"),
                ("Check for debug / dev mode enabled", "browser_navigate"),
            ],
        },
        {
            "name": "API & Auth Testing",
            "objective": "Test backend APIs called by the SPA",
            "steps": [
                ("JWT / token manipulation", "http"),
                ("CORS misconfiguration", "http"),
                ("WebSocket security if applicable", "http"),
                ("IDOR / auth-bypass on API calls", "http"),
            ],
        },
        {
            "name": "Injection Testing",
            "objective": "Test both client and server injection vectors",
            "steps": [
                ("DOM XSS — test hash/query params rendered by JS", "browser_fill"),
                ("PostMessage abuse (cross-origin)", "browser_navigate"),
                ("Server-side injection on API endpoints", "http"),
            ],
        },
        {
            "name": "Reporting",
            "objective": "Structured findings with SPA-specific remediation",
            "steps": [
                ("Report each vuln with [FINDING: SEVERITY]", ""),
                ("SPA-specific remediation (CSP, subresource integrity)", ""),
            ],
        },
    ],

    # ── Network / Infrastructure ──
    "network": [
        {
            "name": "Discovery",
            "objective": "Enumerate hosts, ports, services",
            "steps": [
                ("Full TCP port scan", "nmap"),
                ("UDP top-1000 scan", "nmap"),
                ("Service/version fingerprinting", "nmap"),
                ("OS detection", "nmap"),
            ],
        },
        {
            "name": "Service Enumeration",
            "objective": "Deep-dive on each open service",
            "steps": [
                ("SMB enumeration (shares, users)", "nmap"),
                ("SSH version & auth methods", "http"),
                ("FTP anonymous access", "http"),
                ("SNMP community strings", "nmap"),
                ("DNS zone transfer", "nmap"),
            ],
        },
        {
            "name": "Vulnerability Scanning",
            "objective": "Identify known CVEs on discovered services",
            "steps": [
                ("Nuclei network templates", "nuclei"),
                ("Service-specific CVE checks", "http"),
                ("SSL/TLS misconfiguration testing", "http"),
            ],
        },
        {
            "name": "Exploitation",
            "objective": "Prove impact with PoC exploits",
            "steps": [
                ("Exploit confirmed CVEs", ""),
                ("Default / weak credentials", ""),
                ("Privilege escalation on obtained shells", ""),
            ],
        },
        {
            "name": "Reporting",
            "objective": "Structured findings with infrastructure remediation",
            "steps": [
                ("Report each vuln with [FINDING: SEVERITY]", ""),
                ("Patch & hardening recommendations", ""),
            ],
        },
    ],
}


def detect_target_type(profile: TargetProfile) -> str:
    """
    Infer the best plan template key from what we already know.

    Returns one of: 'wordpress', 'api_rest', 'spa_javascript', 'network', 'web_standard'.
    """
    techs_lower = {t.name.lower() for t in profile.technologies}

    # WordPress detection
    if any("wordpress" in t or "wp" == t for t in techs_lower):
        return "wordpress"

    # SPA detection
    if profile.spa_detected:
        return "spa_javascript"
    if techs_lower & {"react", "vue", "angular", "next.js", "nuxt", "svelte", "gatsby"}:
        return "spa_javascript"

    # API detection — no HTML endpoints or explicit API frameworks
    api_techs = {"express", "fastapi", "flask", "django-rest-framework", "spring-boot", "graphql"}
    if techs_lower & api_techs:
        html_endpoints = [e for e in profile.endpoints if "html" in e.content_type.lower()]
        if len(html_endpoints) < 2:
            return "api_rest"

    # Pure network — no web ports at all
    web_ports = profile.get_web_ports() if hasattr(profile, "get_web_ports") else []
    if profile.ports and not web_ports:
        return "network"

    # Default: standard web app
    return "web_standard"


def _template_to_plan(template_key: str, objective: str) -> AttackPlan:
    """Convert a PLAN_TEMPLATES entry into a live AttackPlan."""
    template = PLAN_TEMPLATES.get(template_key, PLAN_TEMPLATES["web_standard"])
    plan = AttackPlan(objective=objective)

    for phase_def in template:
        steps = [
            AttackStep(description=desc, tool_hint=hint)
            for desc, hint in phase_def["steps"]
        ]
        plan.phases.append(AttackPhase(
            name=phase_def["name"],
            objective=phase_def["objective"],
            steps=steps,
        ))

    return plan


# ── LLM prompt for plan customisation ──

_PLANNER_SYSTEM = """\
You are an expert penetration-test planner.  Given (1) a target profile and \
(2) a base attack plan template, you MUST return a **refined** JSON attack plan \
customised for THIS specific target.

Rules:
- Keep the same phase structure (5 phases).
- You MAY reorder steps, remove irrelevant ones, or ADD new target-specific steps.
- Each step is {"description": "...", "tool_hint": "tool_name_or_empty"}.
- Valid tool_hints: nmap, httpx, ffuf, nuclei, http, browser_navigate, browser_fill, \
browser_click, sqlmap, "" (empty = manual).
- Output ONLY valid JSON — no markdown fences, no commentary.
- JSON schema: {"phases": [{"name": str, "objective": str, "steps": [{"description": str, "tool_hint": str}]}]}
"""


async def generate_plan_with_llm(
    objective: str,
    profile: TargetProfile,
    router: LLMRouter,
) -> AttackPlan:
    """
    Generate a target-aware attack plan using LLM refinement.

    1. Detect target type from profile → select template.
    2. Ask LLM to customise the template for this specific target.
    3. Parse JSON response → AttackPlan.
    4. Falls back to heuristic template plan on any failure.
    """
    target_type = detect_target_type(profile)
    base_plan = _template_to_plan(target_type, objective)

    # Serialise template + profile for the LLM
    profile_summary = profile.to_prompt_summary()
    base_plan_json = json.dumps({
        "target_type": target_type,
        "phases": [
            {
                "name": p.name,
                "objective": p.objective,
                "steps": [
                    {"description": s.description, "tool_hint": s.tool_hint}
                    for s in p.steps
                ],
            }
            for p in base_plan.phases
        ],
    }, indent=2)

    user_prompt = (
        f"## Objective\n{objective}\n\n"
        f"## Target Profile\n{profile_summary}\n\n"
        f"## Base Plan (template: {target_type})\n```json\n{base_plan_json}\n```\n\n"
        "Refine this plan for the specific target.  Return ONLY the JSON."
    )

    try:
        from numasec.router import TaskType

        text = ""
        async with asyncio.timeout(90):
            async for chunk in router.stream(
                messages=[{"role": "user", "content": user_prompt}],
                tools=None,
                system=_PLANNER_SYSTEM,
                task_type=TaskType.PLANNING,
            ):
                if chunk.content:
                    text += chunk.content
                if chunk.done:
                    break

        # Robust JSON extraction — handle LLM wrapping with commentary
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        # If still not valid JSON, extract the first JSON object via regex
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            import re as _re
            json_match = _re.search(r'\{[\s\S]*\}', text)
            if json_match:
                data = json.loads(json_match.group())
            else:
                raise ValueError(f"No JSON object found in LLM response: {text[:200]}")
        plan = AttackPlan(objective=objective)
        for phase_data in data.get("phases", []):
            steps = [
                AttackStep(
                    description=s.get("description", ""),
                    tool_hint=s.get("tool_hint", ""),
                )
                for s in phase_data.get("steps", [])
            ]
            plan.phases.append(AttackPhase(
                name=phase_data.get("name", ""),
                objective=phase_data.get("objective", ""),
                steps=steps,
            ))

        if not plan.phases:
            raise ValueError("LLM returned empty plan")

        logger.info(f"LLM planner: {target_type} template → {len(plan.phases)} phases, "
                     f"{sum(len(p.steps) for p in plan.phases)} steps")
        return plan

    except Exception as e:
        logger.warning(f"LLM planner failed ({e}), falling back to template '{target_type}'")
        return base_plan
