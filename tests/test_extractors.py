"""
Tests for Extractors — parsing tool output into TargetProfile.
"""

import json
import pytest
from numasec.extractors import run_extractor
from numasec.target_profile import TargetProfile


class TestNmapExtractor:
    def test_extracts_ports(self, target_profile, nmap_output):
        run_extractor("nmap", target_profile, nmap_output, {})

        assert len(target_profile.ports) >= 3
        port_numbers = [p.number for p in target_profile.ports]
        assert 22 in port_numbers
        assert 80 in port_numbers
        assert 3306 in port_numbers

    def test_extracts_services(self, target_profile, nmap_output):
        run_extractor("nmap", target_profile, nmap_output, {})

        ssh_ports = [p for p in target_profile.ports if p.service == "ssh"]
        assert len(ssh_ports) == 1
        assert "OpenSSH" in ssh_ports[0].product

    def test_extracts_os(self, target_profile, nmap_output):
        run_extractor("nmap", target_profile, nmap_output, {})
        assert target_profile.os_guess == "Ubuntu"

    def test_handles_empty_output(self, target_profile):
        run_extractor("nmap", target_profile, "", {})
        assert len(target_profile.ports) == 0

    def test_handles_failed_scan(self, target_profile):
        run_extractor("nmap", target_profile, "Error: nmap command failed with exit code 1", {})
        assert len(target_profile.ports) == 0


class TestHttpExtractor:
    def test_extracts_technologies(self, target_profile, http_output):
        run_extractor("http", target_profile, http_output, {})

        tech_names = [t.name.lower() for t in target_profile.technologies]
        # Should detect Apache and PHP from headers
        assert any("apache" in t for t in tech_names)
        assert any("php" in t for t in tech_names)

    def test_extracts_status_code(self, target_profile, http_output):
        run_extractor("http", target_profile, http_output, {})

        assert len(target_profile.endpoints) >= 1

    def test_detects_cookies(self, target_profile, http_output):
        run_extractor("http", target_profile, http_output, {})
        # Should detect PHPSESSID cookie (technology indicator)
        tech_names = [t.name.lower() for t in target_profile.technologies]
        assert any("php" in t for t in tech_names)

    def test_handles_non_json(self, target_profile):
        run_extractor("http", target_profile, "Error: Connection refused", {})
        # Should not crash
        assert len(target_profile.technologies) == 0


class TestNucleiExtractor:
    def test_extracts_vulns(self, target_profile, nuclei_output):
        run_extractor("nuclei", target_profile, nuclei_output, {})

        # Should create VulnHypothesis for findings
        assert len(target_profile.hypotheses) >= 1

    def test_critical_vuln_detected(self, target_profile, nuclei_output):
        run_extractor("nuclei", target_profile, nuclei_output, {})

        critical = [h for h in target_profile.hypotheses if h.confidence >= 0.7]
        assert len(critical) >= 1

    def test_handles_empty(self, target_profile):
        run_extractor("nuclei", target_profile, "", {})
        assert len(target_profile.hypotheses) == 0


class TestFfufExtractor:
    def test_extracts_endpoints(self, target_profile, ffuf_output):
        run_extractor("ffuf", target_profile, ffuf_output, {})

        urls = [ep.url for ep in target_profile.endpoints]
        assert any("admin" in u for u in urls)
        assert any("api" in u for u in urls)

    def test_handles_empty(self, target_profile):
        run_extractor("ffuf", target_profile, "", {})
        assert len(target_profile.endpoints) == 0

    def test_handles_non_json(self, target_profile):
        run_extractor("ffuf", target_profile, "Error: ffuf command failed", {})
        assert len(target_profile.endpoints) == 0


class TestUnknownTool:
    def test_unknown_tool_does_not_crash(self, target_profile):
        run_extractor("unknown_tool", target_profile, "some output", {})
        # Should silently do nothing

    def test_run_command_extractor(self, target_profile):
        run_extractor("run_command", target_profile, "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:", {})
        # Should not crash
