"""Tests for security_mcp core models — Finding, TargetProfile, AttackPlan, enums."""

from datetime import datetime, timezone

import pytest

from security_mcp.models.enums import PhaseStatus, PTESPhase, Severity
from security_mcp.models.finding import Finding
from security_mcp.models.plan import AttackPhase, AttackPlan, AttackStep
from security_mcp.models.target import Endpoint, Port, TargetProfile, Technology

# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFindingCreation:
    """Creating a Finding should auto-generate an ID."""

    def test_finding_creation(self):
        f = Finding(title="SQL Injection in login", severity="high")

        assert f.title == "SQL Injection in login"
        assert f.severity == Severity.HIGH
        assert f.id.startswith("SSEC-")
        assert len(f.id) == 17  # "SSEC-" + 12 hex chars


class TestFindingSeverityNormalization:
    """Short aliases should be expanded to canonical severity values."""

    def test_finding_severity_normalization(self):
        crit = Finding(title="Critical finding test", severity="crit")
        assert crit.severity == Severity.CRITICAL

        med = Finding(title="Medium finding test", severity="med")
        assert med.severity == Severity.MEDIUM


class TestFindingFingerprint:
    """Two findings with the same url/method/parameter must share a fingerprint."""

    def test_finding_fingerprint(self):
        f1 = Finding(
            title="SQL Injection in id",
            severity="high",
            url="/api/users",
            method="GET",
            parameter="id",
        )
        f2 = Finding(
            title="Blind SQLi in id param",
            severity="critical",
            url="/api/users",
            method="GET",
            parameter="id",
        )
        assert f1.fingerprint() == f2.fingerprint()


class TestFindingFingerprintDifferent:
    """Findings with different url/method/parameter should differ in fingerprint."""

    def test_finding_fingerprint_different(self):
        f1 = Finding(
            title="SQL Injection in id",
            severity="high",
            url="/api/users",
            method="GET",
            parameter="id",
        )
        f2 = Finding(
            title="XSS in search",
            severity="medium",
            url="/search",
            method="GET",
            parameter="q",
        )
        assert f1.fingerprint() != f2.fingerprint()


# ---------------------------------------------------------------------------
# TargetProfile
# ---------------------------------------------------------------------------


class TestTargetProfileAddPort:
    """add_port should deduplicate by (number, protocol)."""

    def test_target_profile_add_port(self):
        tp = TargetProfile()
        tp.add_port(Port(number=80, protocol="tcp", service="http"))
        tp.add_port(Port(number=80, protocol="tcp", service="http-alt"))  # duplicate
        tp.add_port(Port(number=443, protocol="tcp", service="https"))
        tp.add_port(Port(number=80, protocol="udp", service="http"))  # different proto

        assert len(tp.ports) == 3
        port_nums = [(p.number, p.protocol) for p in tp.ports]
        assert (80, "tcp") in port_nums
        assert (443, "tcp") in port_nums
        assert (80, "udp") in port_nums


class TestTargetProfileAddEndpoint:
    """add_endpoint should deduplicate by (url, method)."""

    def test_target_profile_add_endpoint(self):
        tp = TargetProfile()
        tp.add_endpoint(Endpoint(url="/api", method="GET"))
        tp.add_endpoint(Endpoint(url="/api", method="GET"))  # duplicate
        tp.add_endpoint(Endpoint(url="/api", method="POST"))  # different method

        assert len(tp.endpoints) == 2


class TestTargetProfileAddTechnology:
    """add_technology should deduplicate case-insensitively by name."""

    def test_target_profile_add_technology(self):
        tp = TargetProfile()
        tp.add_technology(Technology(name="Apache", version="2.4"))
        tp.add_technology(Technology(name="apache", version="2.4.41"))  # same, different case
        tp.add_technology(Technology(name="PHP", version="7.4"))

        assert len(tp.technologies) == 2
        names = [t.name for t in tp.technologies]
        assert "Apache" in names
        assert "PHP" in names


class TestTargetProfileHasService:
    """has_service should report presence based on port service field."""

    def test_target_profile_has_service(self):
        tp = TargetProfile()
        tp.add_port(Port(number=22, service="ssh"))
        tp.add_port(Port(number=80, service="http"))

        assert tp.has_service("ssh") is True
        assert tp.has_service("http") is True
        assert tp.has_service("mysql") is False


# ---------------------------------------------------------------------------
# AttackPlan
# ---------------------------------------------------------------------------


class TestAttackPlanProgress:
    """progress property should reflect completed-phase ratio."""

    def test_attack_plan_progress(self):
        step_done = AttackStep(id="s1", description="done", completed=True)
        step_pending = AttackStep(id="s2", description="pending", completed=False)

        phase_complete = AttackPhase(
            phase=PTESPhase.RECON,
            status=PhaseStatus.COMPLETED,
            steps=[step_done],
        )
        phase_pending = AttackPhase(
            phase=PTESPhase.MAPPING,
            status=PhaseStatus.PENDING,
            steps=[step_pending],
        )

        plan = AttackPlan(phases=[phase_complete, phase_pending])
        assert plan.progress == pytest.approx(0.5)

        # Empty plan
        empty = AttackPlan()
        assert empty.progress == 0.0


# ---------------------------------------------------------------------------
# Enum completeness
# ---------------------------------------------------------------------------


class TestSeverityEnumValues:
    """All expected Severity values should exist."""

    def test_severity_enum_values(self):
        expected = {"critical", "high", "medium", "low", "info"}
        actual = {s.value for s in Severity}
        assert actual == expected


class TestPTESPhaseValues:
    """All PTES methodology phases should be present."""

    def test_ptes_phase_values(self):
        expected = {
            "reconnaissance",
            "service_mapping",
            "vulnerability_testing",
            "exploitation_validation",
            "reporting",
        }
        actual = {p.value for p in PTESPhase}
        assert actual == expected



class TestFindingConfidenceField:
    """Finding should support the new confidence, attack_technique, and wstg_id fields."""

    def test_finding_confidence_field(self):
        f = Finding(
            title="Reflected XSS in search",
            severity="high",
            confidence=0.9,
            attack_technique="XSS-Reflected",
            wstg_id="WSTG-INPV-01",
        )

        assert f.confidence == 0.9
        assert f.attack_technique == "XSS-Reflected"
        assert f.wstg_id == "WSTG-INPV-01"

        # Default confidence
        f_default = Finding(title="Info disclosure", severity="info")
        assert f_default.confidence == 0.5
        assert f_default.attack_technique == ""
        assert f_default.wstg_id == ""

        # Out-of-range confidence should raise
        with pytest.raises(Exception):
            Finding(title="Bad confidence", severity="low", confidence=2.0)
