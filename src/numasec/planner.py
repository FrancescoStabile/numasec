"""
NumaSec — Hierarchical Attack Planner

Decomposes objectives into structured attack phases.
Tracks progress and guides the LLM by injecting plan status into context.

The planner does NOT execute — it GUIDES the LLM.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from numasec.target_profile import TargetProfile


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
