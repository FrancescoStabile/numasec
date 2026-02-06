"""
Tests for TargetProfile — structured memory system.
"""

import pytest
from numasec.target_profile import (
    TargetProfile,
    Port,
    Endpoint,
    Technology,
    Credential,
    VulnHypothesis,
)


class TestPort:
    def test_port_creation(self):
        p = Port(number=80, protocol="tcp", service="http", version="Apache 2.4")
        assert p.number == 80
        assert p.protocol == "tcp"
        assert p.service == "http"

    def test_port_defaults(self):
        p = Port(number=22)
        assert p.protocol == "tcp"
        assert p.service == ""


class TestEndpoint:
    def test_endpoint_creation(self):
        ep = Endpoint(url="/api/users", method="GET", status_code=200)
        assert ep.url == "/api/users"
        assert ep.method == "GET"
        assert ep.status_code == 200

    def test_endpoint_defaults(self):
        ep = Endpoint(url="/")
        assert ep.method == "GET"
        assert ep.status_code is None


class TestTargetProfile:
    def test_empty_profile(self, target_profile):
        assert target_profile.target == ""
        assert len(target_profile.ports) == 0
        assert len(target_profile.endpoints) == 0
        assert len(target_profile.technologies) == 0

    def test_add_port(self, target_profile):
        target_profile.add_port(Port(number=80, protocol="tcp", service="http"))
        assert len(target_profile.ports) == 1
        assert target_profile.ports[0].number == 80

    def test_add_duplicate_port(self, target_profile):
        target_profile.add_port(Port(number=80, protocol="tcp", service="http"))
        target_profile.add_port(Port(number=80, protocol="tcp", service="http", version="2.0"))
        # add_port skips duplicates (same number + protocol)
        assert len(target_profile.ports) == 1
        # Original is kept (no update)
        assert target_profile.ports[0].version == ""

    def test_add_endpoint(self, target_profile):
        target_profile.add_endpoint(Endpoint(url="/admin", method="GET", status_code=403))
        assert len(target_profile.endpoints) == 1

    def test_add_duplicate_endpoint(self, target_profile):
        target_profile.add_endpoint(Endpoint(url="/admin", method="GET", status_code=403))
        target_profile.add_endpoint(Endpoint(url="/admin", method="GET", status_code=200))
        # Should update
        assert len(target_profile.endpoints) == 1
        assert target_profile.endpoints[0].status_code == 200

    def test_add_technology(self, target_profile):
        target_profile.add_technology(Technology(name="PHP", version="7.4", category="language"))
        assert len(target_profile.technologies) == 1

    def test_add_duplicate_technology(self, target_profile):
        target_profile.add_technology(Technology(name="PHP", version="7.4", category="language"))
        target_profile.add_technology(Technology(name="PHP", version="8.0", category="language"))
        # add_technology skips if name already present (case-insensitive)
        assert len(target_profile.technologies) == 1
        assert target_profile.technologies[0].version == "7.4"

    def test_add_credential(self, target_profile):
        target_profile.add_credential(Credential(username="admin", password="pass", source="bruteforce"))
        assert len(target_profile.credentials) == 1

    def test_get_confirmed_vulns(self, populated_profile):
        confirmed = populated_profile.get_confirmed_vulns()
        assert len(confirmed) == 1
        assert confirmed[0].vuln_type == "sqli"
        assert confirmed[0].confirmed is True

    def test_get_untested_hypotheses(self, populated_profile):
        untested = populated_profile.get_untested_hypotheses()
        assert len(untested) == 1
        assert untested[0].vuln_type == "xss"
        assert untested[0].tested is False

    def test_to_prompt_summary(self, populated_profile):
        summary = populated_profile.to_prompt_summary()
        assert "10.10.10.1" in summary
        assert "ssh" in summary.lower() or "22" in summary
        assert "sqli" in summary.lower()

    def test_to_dict_from_dict_roundtrip(self, populated_profile):
        data = populated_profile.to_dict()
        assert isinstance(data, dict)
        assert "ports" in data
        assert "endpoints" in data

        restored = TargetProfile.from_dict(data)
        assert restored.target == populated_profile.target
        assert len(restored.ports) == len(populated_profile.ports)
        assert len(restored.endpoints) == len(populated_profile.endpoints)
        assert len(restored.technologies) == len(populated_profile.technologies)

    def test_empty_to_prompt_summary(self, target_profile):
        summary = target_profile.to_prompt_summary()
        # Should not crash on empty profile
        assert isinstance(summary, str)
