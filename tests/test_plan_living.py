"""Tests for AttackPlan living document features (W5.1)."""

from __future__ import annotations

import pytest

from security_mcp.models.enums import PTESPhase, PhaseStatus
from security_mcp.models.plan import AttackPlan, AttackPhase, AttackStep


def _make_plan() -> AttackPlan:
    return AttackPlan(
        target="http://example.com",
        scope="quick",
        phases=[
            AttackPhase(
                phase=PTESPhase.RECON,
                steps=[
                    AttackStep(id="r1", description="Port scan", tool="port_scan"),
                    AttackStep(id="r2", description="Tech fingerprint", tool="tech_fingerprint"),
                ],
            ),
            AttackPhase(
                phase=PTESPhase.VULNERABILITY,
                steps=[
                    AttackStep(id="v1", description="SQLi test", tool="sqli_test"),
                ],
            ),
        ],
    )


class TestUpdateStepStatus:
    """Test update_step_status method."""

    def test_updates_step(self):
        plan = _make_plan()
        plan.update_step_status("r1", PhaseStatus.COMPLETED, "80, 443 open")
        step = plan.phases[0].steps[0]
        assert step.status == PhaseStatus.COMPLETED
        assert step.completed is True
        assert step.result == "80, 443 open"

    def test_cascades_to_phase(self):
        plan = _make_plan()
        plan.update_step_status("r1", PhaseStatus.COMPLETED)
        plan.update_step_status("r2", PhaseStatus.COMPLETED)
        assert plan.phases[0].status == PhaseStatus.COMPLETED

    def test_phase_running_if_any_running(self):
        plan = _make_plan()
        plan.update_step_status("r1", PhaseStatus.COMPLETED)
        plan.update_step_status("r2", PhaseStatus.RUNNING)
        assert plan.phases[0].status == PhaseStatus.RUNNING

    def test_nonexistent_step_logs_warning(self):
        plan = _make_plan()
        # Should not raise
        plan.update_step_status("nonexistent", PhaseStatus.COMPLETED)


class TestAddDynamicSteps:
    """Test add_dynamic_steps method."""

    def test_adds_steps(self):
        plan = _make_plan()
        new_steps = [AttackStep(id="r3", description="Dir fuzz", tool="dir_fuzz")]
        plan.add_dynamic_steps(PTESPhase.RECON.value, new_steps)
        assert len(plan.phases[0].steps) == 3

    def test_reopens_completed_phase(self):
        plan = _make_plan()
        plan.phases[0].status = PhaseStatus.COMPLETED
        new_steps = [AttackStep(id="r3", description="Dir fuzz", tool="dir_fuzz")]
        plan.add_dynamic_steps(PTESPhase.RECON.value, new_steps)
        assert plan.phases[0].status == PhaseStatus.RUNNING

    def test_nonexistent_phase(self):
        plan = _make_plan()
        # Should not raise
        plan.add_dynamic_steps("nonexistent_phase", [])


class TestGetPendingSteps:
    """Test get_pending_steps method."""

    def test_all_pending(self):
        plan = _make_plan()
        pending = plan.get_pending_steps()
        assert len(pending) == 3  # r1, r2, v1

    def test_some_completed(self):
        plan = _make_plan()
        plan.update_step_status("r1", PhaseStatus.COMPLETED)
        pending = plan.get_pending_steps()
        assert len(pending) == 2


class TestToPromptContext:
    """Test to_prompt_context method."""

    def test_contains_target(self):
        plan = _make_plan()
        ctx = plan.to_prompt_context()
        assert "Target: http://example.com" in ctx

    def test_contains_phases(self):
        plan = _make_plan()
        ctx = plan.to_prompt_context()
        assert "Reconnaissance" in ctx
        assert "Vulnerability Testing" in ctx

    def test_contains_status_markers(self):
        plan = _make_plan()
        plan.update_step_status("r1", PhaseStatus.COMPLETED, "80 open")
        ctx = plan.to_prompt_context()
        assert "[DONE]" in ctx
        assert "[PENDING]" in ctx

    def test_completed_step_shows_result(self):
        plan = _make_plan()
        plan.update_step_status("r1", PhaseStatus.COMPLETED, "80, 443 open")
        ctx = plan.to_prompt_context()
        assert "80, 443 open" in ctx
