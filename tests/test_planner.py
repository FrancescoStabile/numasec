"""
Tests for Planner — hierarchical attack plan + templates + LLM planner.
"""

import pytest
from numasec.planner import (
    generate_plan,
    AttackPlan,
    AttackPhase,
    AttackStep,
    PhaseStatus,
    PLAN_TEMPLATES,
    detect_target_type,
    _template_to_plan,
)
from numasec.target_profile import TargetProfile, Technology, Port


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


# ═══════════════════════════════════════════════════════════════════════════
# Plan Templates
# ═══════════════════════════════════════════════════════════════════════════


class TestPlanTemplates:
    """Template-based plan generation (§4.3)."""

    def test_all_templates_exist(self):
        expected = {"web_standard", "wordpress", "api_rest", "spa_javascript", "network"}
        assert expected <= set(PLAN_TEMPLATES.keys())

    def test_each_template_has_5_phases(self):
        for key, template in PLAN_TEMPLATES.items():
            assert len(template) >= 4, f"Template '{key}' has too few phases"

    def test_template_to_plan(self):
        plan = _template_to_plan("web_standard", "Test target.com")
        assert isinstance(plan, AttackPlan)
        assert plan.objective == "Test target.com"
        assert len(plan.phases) >= 4

    def test_template_to_plan_unknown_falls_back(self):
        plan = _template_to_plan("nonexistent", "Test")
        assert len(plan.phases) >= 4  # falls back to web_standard


class TestDetectTargetType:
    """detect_target_type() infers the right template."""

    def test_default_is_web_standard(self):
        profile = TargetProfile()
        assert detect_target_type(profile) == "web_standard"

    def test_wordpress_detection(self):
        profile = TargetProfile()
        profile.add_technology(Technology(name="WordPress", version="6.0", category="cms"))
        assert detect_target_type(profile) == "wordpress"

    def test_spa_detection_via_flag(self):
        profile = TargetProfile()
        profile.spa_detected = True
        assert detect_target_type(profile) == "spa_javascript"

    def test_spa_detection_via_tech(self):
        profile = TargetProfile()
        profile.add_technology(Technology(name="React", version="18", category="framework"))
        assert detect_target_type(profile) == "spa_javascript"

    def test_api_detection(self):
        profile = TargetProfile()
        profile.add_technology(Technology(name="FastAPI", version="0.100", category="framework"))
        assert detect_target_type(profile) == "api_rest"

    def test_network_detection(self):
        profile = TargetProfile()
        profile.add_port(Port(number=22, service="ssh"))
        profile.add_port(Port(number=445, service="smb"))
        # No web ports → network
        assert detect_target_type(profile) == "network"
