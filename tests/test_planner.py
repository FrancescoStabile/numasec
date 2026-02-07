"""
Tests for Planner — hierarchical attack plan.
"""

import pytest
from numasec.planner import generate_plan, AttackPlan, AttackPhase, AttackStep, PhaseStatus
from numasec.target_profile import TargetProfile


class TestGeneratePlan:
    def test_creates_plan(self, populated_profile):
        plan = generate_plan("Pentest http://10.10.10.1:8080", populated_profile)
        assert isinstance(plan, AttackPlan)
        assert plan.objective == "Pentest http://10.10.10.1:8080"
        assert len(plan.phases) >= 3

    def test_creates_plan_without_profile(self):
        plan = generate_plan("Scan target.com", TargetProfile())
        assert plan.objective == "Scan target.com"
        assert len(plan.phases) >= 3

    def test_phase_names(self, attack_plan):
        phase_names = [p.name.lower() for p in attack_plan.phases]
        # Should have discovery phase
        assert any("discovery" in n for n in phase_names)

    def test_each_phase_has_steps(self, attack_plan):
        for phase in attack_plan.phases:
            assert len(phase.steps) >= 1


class TestAttackPlan:
    def test_current_phase(self, attack_plan):
        current = attack_plan.current_phase()
        assert current is not None
        # First phase should be active
        assert current.status == PhaseStatus.ACTIVE

    def test_advance_phase(self, attack_plan):
        first_phase = attack_plan.current_phase()
        attack_plan.advance_phase()

        second_phase = attack_plan.current_phase()
        assert second_phase is not None
        assert second_phase != first_phase
        assert first_phase.status == PhaseStatus.COMPLETE

    def test_skip_phase(self, attack_plan):
        first_phase_name = attack_plan.phases[0].name
        attack_plan.skip_phase(first_phase_name, "Not applicable")
        # The first phase should be skipped
        assert attack_plan.phases[0].status == PhaseStatus.SKIPPED

    def test_mark_step_complete(self, attack_plan):
        current = attack_plan.current_phase()
        if current and current.steps:
            # Find the first pending step
            pending = [s for s in current.steps if s.status == PhaseStatus.PENDING]
            if pending:
                step = pending[0]
                attack_plan.mark_step_complete(step.tool_hint or "test", "Success")
                assert step.status == PhaseStatus.COMPLETE
                assert step.result_summary == "Success"

    def test_is_complete(self, attack_plan):
        assert not attack_plan.is_complete()

        # Complete all phases by activating then advancing each
        for _ in range(len(attack_plan.phases)):
            attack_plan.current_phase()  # Ensure one is active
            attack_plan.advance_phase()

        assert attack_plan.is_complete()

    def test_to_prompt_summary(self, attack_plan):
        summary = attack_plan.to_prompt_summary()
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert attack_plan.objective in summary

    def test_to_dict_from_dict_roundtrip(self, attack_plan):
        data = attack_plan.to_dict()
        assert isinstance(data, dict)
        assert "objective" in data
        assert "phases" in data

        restored = AttackPlan.from_dict(data)
        assert restored.objective == attack_plan.objective
        assert len(restored.phases) == len(attack_plan.phases)

    def test_empty_plan(self):
        plan = AttackPlan(objective="")
        assert plan.current_phase() is None
        assert plan.is_complete()
        summary = plan.to_prompt_summary()
        assert isinstance(summary, str)
