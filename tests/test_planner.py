"""Tests for security_mcp.core.planner."""

from __future__ import annotations

from security_mcp.core.planner import ReplanSignal
from security_mcp.core.planner import DeterministicPlanner
from security_mcp.models.enums import PTESPhase
from security_mcp.models.target import Port, TargetProfile, Technology


class TestCreatePlan:
    def test_quick_scope(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        plan = planner.create_plan(target, scope="quick")

        assert plan.target == "example.com"
        assert plan.scope == "quick"
        # Quick: recon + mapping + vuln + reporting (no exploitation)
        phase_names = [p.phase for p in plan.phases]
        assert PTESPhase.RECON in phase_names
        assert PTESPhase.MAPPING in phase_names
        assert PTESPhase.VULNERABILITY in phase_names
        assert PTESPhase.REPORTING in phase_names
        assert PTESPhase.EXPLOITATION not in phase_names

    def test_standard_scope_has_exploitation(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        plan = planner.create_plan(target, scope="standard")

        phase_names = [p.phase for p in plan.phases]
        assert PTESPhase.EXPLOITATION in phase_names

    def test_deep_scope_has_dir_fuzz(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        plan = planner.create_plan(target, scope="deep")

        recon = next(p for p in plan.phases if p.phase == PTESPhase.RECON)
        step_ids = [s.id for s in recon.steps]
        assert "recon_dir_fuzz" in step_ids

    def test_recon_always_has_port_scan(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        plan = planner.create_plan(target, scope="quick")

        recon = next(p for p in plan.phases if p.phase == PTESPhase.RECON)
        assert any(s.id == "recon_port_scan" for s in recon.steps)

    def test_reporting_always_present(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        for scope in ("quick", "standard", "deep"):
            plan = planner.create_plan(target, scope=scope)
            assert any(p.phase == PTESPhase.REPORTING for p in plan.phases)


class TestSelectVulnTests:
    def test_web_target_gets_sqli_xss(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        target.ports = [Port(number=80, service="http")]
        steps = planner._select_vuln_tests(target)
        step_ids = [s.id for s in steps]
        assert "vuln_sqli" in step_ids
        assert "vuln_xss" in step_ids

    def test_php_target_gets_lfi(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        target.ports = [Port(number=80, service="http")]
        target.technologies = [Technology(name="PHP", version="7.4")]
        steps = planner._select_vuln_tests(target)
        step_ids = [s.id for s in steps]
        assert "vuln_lfi" in step_ids

    def test_always_has_header_check(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        steps = planner._select_vuln_tests(target)
        assert any(s.id == "vuln_headers" for s in steps)


class TestReplan:
    def test_waf_detected_adds_evasion(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        plan = planner.create_plan(target, scope="standard")

        signal = ReplanSignal(type="waf_detected")
        new_plan = planner.replan(plan, signal)

        vuln_phase = next(p for p in new_plan.phases if p.phase == PTESPhase.VULNERABILITY)
        assert any("waf" in s.id.lower() for s in vuln_phase.steps)

    def test_escalation_adds_exploit_step(self):
        planner = DeterministicPlanner()
        target = TargetProfile(target="example.com")
        plan = planner.create_plan(target, scope="standard")

        signal = ReplanSignal(
            type="escalation_found",
            data={"chain": "sqli_to_rce"},
        )
        new_plan = planner.replan(plan, signal)

        exploit_phase = next(p for p in new_plan.phases if p.phase == PTESPhase.EXPLOITATION)
        assert any("sqli_to_rce" in s.id for s in exploit_phase.steps)
