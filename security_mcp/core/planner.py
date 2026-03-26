"""Deterministic Planner — PTES 5-phase based, NOT LLM-driven."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from security_mcp.models.enums import PTESPhase
from security_mcp.models.plan import AttackPhase, AttackPlan, AttackStep

if TYPE_CHECKING:
    from security_mcp.models.target import TargetProfile


@dataclass
class ReplanSignal:
    """Signal from the Perceptor to the Planner (replanning triggers)."""

    type: str = "continue"
    confidence: float = 0.5
    data: dict = field(default_factory=dict)
    finding: object | None = None
    replan_reason: str | None = None

logger = logging.getLogger("security_mcp.core.planner")


@dataclass
class Task:
    """Single task within a plan."""

    id: str
    description: str
    tool: str = ""
    category: str = ""
    params: dict = None
    expected_output: str = ""

    def __post_init__(self):
        if self.params is None:
            self.params = {}


class DeterministicPlanner:
    """Deterministic planner following PTES methodology.

    The LLM does NOT decide strategy — only the Executor uses LLM for
    tactical decisions. Re-planning occurs only on Perceptor triggers.

    Based on CHECKMATE paper (arXiv:2512.11143).
    """

    SCOPE_TIMEOUTS = {
        "quick": 3,
        "standard": 10,
        "deep": 30,
    }

    def create_plan(self, target: TargetProfile, scope: str = "quick") -> AttackPlan:
        """Generate a deterministic attack plan based on target and scope."""
        plan = AttackPlan(target=target.target, scope=scope)

        # Phase 1: Reconnaissance (always)
        recon_steps = [
            AttackStep(id="recon_port_scan", description="Port scan target", tool="scan_engine"),
            AttackStep(id="recon_tech_fp", description="Technology fingerprint", tool="http_engine"),
        ]
        if scope in ("standard", "deep"):
            recon_steps.append(AttackStep(id="recon_dir_fuzz", description="Directory fuzzing", tool="http_engine"))
        plan.phases.append(
            AttackPhase(
                phase=PTESPhase.RECON,
                steps=recon_steps,
                parallelizable=True,
                timeout_minutes=self.SCOPE_TIMEOUTS.get(scope, 3),
            )
        )

        # Phase 2: Service Mapping
        plan.phases.append(
            AttackPhase(
                phase=PTESPhase.MAPPING,
                steps=[
                    AttackStep(id="map_services", description="Map detected services", tool="scan_engine"),
                    AttackStep(id="map_endpoints", description="Map web endpoints", tool="http_engine"),
                ],
                timeout_minutes=5,
            )
        )

        # Phase 3: Vulnerability Testing
        vuln_steps = self._select_vuln_tests(target)
        plan.phases.append(
            AttackPhase(
                phase=PTESPhase.VULNERABILITY,
                steps=vuln_steps,
                parallelizable=True,
                timeout_minutes=self.SCOPE_TIMEOUTS.get(scope, 10),
            )
        )

        # Phase 4: Exploitation Validation
        if scope in ("standard", "deep"):
            plan.phases.append(
                AttackPhase(
                    phase=PTESPhase.EXPLOITATION,
                    steps=[
                        AttackStep(
                            id="exploit_validate", description="Validate exploitable findings", tool="http_engine"
                        ),
                    ],
                    timeout_minutes=15,
                )
            )

        # Phase 5: Reporting (always)
        plan.phases.append(
            AttackPhase(
                phase=PTESPhase.REPORTING,
                steps=[
                    AttackStep(id="report_gen", description="Generate assessment report", tool="reporter"),
                ],
                timeout_minutes=2,
            )
        )

        logger.info(
            "Created plan: %d phases, %d total steps, scope=%s",
            len(plan.phases),
            sum(len(p.steps) for p in plan.phases),
            scope,
        )
        return plan

    def replan(
        self,
        current_plan: AttackPlan,
        signal: ReplanSignal,
        discovered_nodes: frozenset[str] = frozenset(),
    ) -> AttackPlan:
        """Re-plan on Perceptor triggers (WAF detected, escalation found, etc.).

        Args:
            current_plan: The existing plan to mutate.
            signal: The Perceptor signal that triggered replanning.
            discovered_nodes: Attack graph node IDs already discovered.
                Used to augment VULNERABILITY phase steps based on confirmed
                capabilities (RF4 — AttackGraph → Planner wiring).
        """
        logger.info("Replanning triggered by: %s", signal.type)

        if signal.type == "waf_detected":
            # Add WAF evasion steps to vulnerability phase
            for phase in current_plan.phases:
                if phase.phase == PTESPhase.VULNERABILITY:
                    phase.steps.append(
                        AttackStep(
                            id="waf_evasion",
                            description="Attempt WAF bypass techniques (encoding, case alternation, comment injection)",
                            tool="http_engine",
                        )
                    )
                    break

        elif signal.type == "escalation_found":
            chain_name = signal.data.get("chain", "")
            for phase in current_plan.phases:
                if phase.phase == PTESPhase.EXPLOITATION:
                    phase.steps.append(
                        AttackStep(
                            id=f"escalate_{chain_name}",
                            description=f"Escalation chain: {chain_name}",
                            tool="http_engine",
                        )
                    )
                    break

        elif signal.type == "auth_obtained":
            # Credentials discovered -- insert post-auth testing tiers
            token_type = signal.data.get("token_type", "bearer")
            for phase in current_plan.phases:
                if phase.phase == PTESPhase.VULNERABILITY:
                    step_id = self._step_id("auth_retest", "post_auth")
                    if not any(s.id == step_id for s in phase.steps):
                        phase.steps.append(
                            AttackStep(
                                id=step_id,
                                description=(
                                    f"Post-auth testing with {token_type} token: "
                                    "IDOR, privilege escalation, business logic, stored XSS"
                                ),
                                tool="get_auth_retest_plan",
                            )
                        )
                    break

        elif signal.type == "rate_limited":
            # Reduce scan aggressiveness
            logger.warning("Rate limiting detected -- adding throttle steps")
            for phase in current_plan.phases:
                if phase.phase == PTESPhase.VULNERABILITY:
                    if not any(s.id == "throttle_mode" for s in phase.steps):
                        phase.steps.insert(
                            0,
                            AttackStep(
                                id="throttle_mode",
                                description="Rate limiting detected: increase delay between requests to 2s, reduce concurrency to 1",
                                tool="http_engine",
                            ),
                        )
                    break

        elif signal.type == "technology_identified":
            # Tech-specific scanner prioritisation
            tech = signal.data.get("technology", "").lower()
            tech_steps: list[tuple[str, str, str]] = []

            if "node" in tech or "express" in tech:
                tech_steps.append(("nosql_deep", "Deep NoSQL injection (Node.js target)", "nosql_test"))
                tech_steps.append(("proto_poll", "Prototype pollution check (Node.js)", "command_injection_test"))
            elif "php" in tech:
                tech_steps.append(("lfi_deep", "Deep LFI with PHP wrappers (expect://, data://)", "lfi_test"))
            elif "java" in tech or "spring" in tech:
                tech_steps.append(("deser_check", "Deserialization check (Java target)", "vuln_scan"))
            elif "django" in tech or "flask" in tech or "python" in tech:
                tech_steps.append(("ssti_deep", "Deep SSTI Jinja2 check (Python target)", "ssti_test"))

            for step_id, desc, tool in tech_steps:
                for phase in current_plan.phases:
                    if phase.phase == PTESPhase.VULNERABILITY:
                        full_id = self._step_id(step_id, tech)
                        if not any(s.id == full_id for s in phase.steps):
                            phase.steps.append(AttackStep(id=full_id, description=desc, tool=tool))
                        break

        elif signal.type == "large_surface":
            # Auto-escalate scope when many endpoints discovered
            endpoint_count = signal.data.get("endpoint_count", 0)
            if endpoint_count > 100:
                logger.info("Large attack surface (%d endpoints) -- escalating scope", endpoint_count)
                current_plan.scope = "deep"

        elif signal.type == "api_app_detected":
            # Prioritise JSON/API-specific scanners
            for phase in current_plan.phases:
                if phase.phase == PTESPhase.VULNERABILITY:
                    step_id = self._step_id("api_scan", "api")
                    if not any(s.id == step_id for s in phase.steps):
                        phase.steps.append(
                            AttackStep(
                                id=step_id,
                                description="API-specific testing: IDOR/BOLA, mass assignment, auth bypass",
                                tool="idor_test",
                            )
                        )
                    break

        elif signal.type == "spa_detected":
            # Switch to browser-first scanning
            for phase in current_plan.phases:
                if phase.phase == PTESPhase.MAPPING:
                    step_id = self._step_id("spa_crawl", "browser")
                    if not any(s.id == step_id for s in phase.steps):
                        phase.steps.append(
                            AttackStep(
                                id=step_id,
                                description="SPA detected: browser crawl for fragment routes and JS bundle analysis",
                                tool="browser_crawl_site",
                            )
                        )
                    break

        # RF4: Augment VULNERABILITY phase based on discovered graph nodes.
        if discovered_nodes:
            self._augment_vuln_phase_from_graph(current_plan, discovered_nodes)

        return current_plan

    def _augment_vuln_phase_from_graph(
        self,
        plan: AttackPlan,
        discovered_nodes: frozenset[str],
    ) -> None:
        """Inject additional vulnerability tests inferred from the attack graph.

        Called during replan when the graph has new discovered nodes that the
        initial deterministic plan did not account for.
        """
        vuln_phase = next((p for p in plan.phases if p.phase == PTESPhase.VULNERABILITY), None)
        if vuln_phase is None:
            return

        existing_ids = {s.id for s in vuln_phase.steps}

        # Directory enumeration found real content → add info-disclosure check
        if "recon_dirs" in discovered_nodes and "vuln_info_disclosure_check" not in existing_ids:
            vuln_phase.steps.append(
                AttackStep(
                    id="vuln_info_disclosure_check",
                    description="Check discovered paths for sensitive information disclosure",
                    tool="http_engine",
                )
            )
            logger.debug("Graph-guided: added vuln_info_disclosure_check (recon_dirs discovered)")

        # SQLi confirmed → add deep sqlmap escalation if not already present
        if "vuln_sqli" in discovered_nodes and "vuln_sqli_deep" not in existing_ids:
            vuln_phase.steps.append(
                AttackStep(
                    id="vuln_sqli_deep",
                    description="Deep SQL injection escalation via sqlmap",
                    tool="sqlmap",
                )
            )
            logger.debug("Graph-guided: added vuln_sqli_deep (vuln_sqli discovered)")

        # SSRF indicators found → add internal network probe
        if "vuln_ssrf" in discovered_nodes and "vuln_ssrf_probe" not in existing_ids:
            vuln_phase.steps.append(
                AttackStep(
                    id="vuln_ssrf_probe",
                    description="Probe internal services via confirmed SSRF",
                    tool="http_engine",
                )
            )
            logger.debug("Graph-guided: added vuln_ssrf_probe (vuln_ssrf discovered)")

        # LFI confirmed → add log-poisoning / wrapper escalation
        if "vuln_lfi" in discovered_nodes and "vuln_lfi_escalate" not in existing_ids:
            vuln_phase.steps.append(
                AttackStep(
                    id="vuln_lfi_escalate",
                    description="Attempt LFI to RCE via log poisoning or PHP wrappers",
                    tool="http_engine",
                )
            )
            logger.debug("Graph-guided: added vuln_lfi_escalate (vuln_lfi discovered)")

    def _select_vuln_tests(self, target: TargetProfile) -> list[AttackStep]:
        """Select vulnerability tests based on detected technologies."""
        steps: list[AttackStep] = []

        # Always run header checks
        steps.append(
            AttackStep(
                id="vuln_headers",
                description="Security header analysis",
                tool="http_engine",
            )
        )

        # Check for web services
        has_web = any(p.service in ("http", "https", "http-proxy") for p in target.ports)

        if has_web:
            steps.extend(
                [
                    AttackStep(id="vuln_sqli", description="SQL injection testing", tool="http_engine"),
                    AttackStep(id="vuln_xss", description="XSS testing", tool="http_engine"),
                    AttackStep(id="vuln_auth", description="Authentication testing", tool="http_engine"),
                ]
            )

        # Technology-specific tests
        tech_names = [t.name.lower() for t in target.technologies]

        if any("php" in t for t in tech_names):
            steps.append(
                AttackStep(
                    id="vuln_lfi",
                    description="LFI/RFI testing (PHP)",
                    tool="http_engine",
                )
            )

        if any(t in ("mysql", "postgresql", "mssql") for t in tech_names):
            steps.append(
                AttackStep(
                    id="vuln_sqli_deep",
                    description="Deep SQLi testing",
                    tool="sqlmap",
                )
            )

        if any("wordpress" in t for t in tech_names):
            steps.append(
                AttackStep(
                    id="vuln_wp",
                    description="WordPress vulnerability scan",
                    tool="nuclei",
                )
            )

        # If no tech detected, add generic nuclei scan
        if not tech_names:
            steps.append(
                AttackStep(
                    id="vuln_nuclei",
                    description="Generic vulnerability scan",
                    tool="nuclei",
                )
            )

        return steps

    # ------------------------------------------------------------------
    # Deterministic task generation (post-MAPPING expansion)
    # ------------------------------------------------------------------

    # Maps scanner tools to endpoint matching predicates.
    # Each predicate receives an Endpoint and returns True if the tool
    # should be run against that endpoint.
    _SCANNER_RULES: dict[str, str] = {
        "sqli_test": "query_or_post",
        "xss_test": "query_or_post",
        "nosql_test": "json_body",
        "csrf_test": "post_method",
        "idor_test": "numeric_path",
        "xxe_test": "upload_or_xml",
        "ssrf_test": "url_param",
        "ssti_test": "query_or_post",
    }

    # Tools that should always run once on the base URL.
    _ALWAYS_RUN_TOOLS: list[str] = [
        "auth_test",
        "cors_test",
        "host_header_test",
        "open_redirect_test",
        "access_control_test",
    ]

    # --- Helpers ---

    @staticmethod
    def _step_id(tool: str, url: str) -> str:
        """Generate a deterministic step ID from tool + URL."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:8]
        return f"auto_{tool}_{url_hash}"

    @staticmethod
    def _endpoint_matches_rule(ep: Any, rule: str) -> bool:
        """Check if an endpoint matches a scanner selection rule."""
        url = getattr(ep, "url", "")
        method = getattr(ep, "method", "GET").upper()
        content_type = getattr(ep, "content_type", "").lower()
        parameters = getattr(ep, "parameters", [])

        if rule == "query_or_post":
            return bool(parameters) or method == "POST" or "?" in url
        elif rule == "json_body":
            return "json" in content_type or method == "POST"
        elif rule == "post_method":
            return method == "POST"
        elif rule == "numeric_path":
            return any(seg.isdigit() for seg in url.split("/"))
        elif rule == "upload_or_xml":
            return "upload" in url.lower() or "xml" in content_type or "file" in url.lower()
        elif rule == "url_param":
            lower_url = url.lower()
            return any(p in lower_url for p in ("url=", "image", "file", "upload", "img", "src"))
        return False
