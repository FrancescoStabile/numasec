"""
Tests for Reflection — strategic analysis after tool calls.
"""

import pytest
from numasec.reflection import reflect_on_result
from numasec.target_profile import TargetProfile


class TestReflection:
    def test_reflect_nmap(self, populated_profile, nmap_output):
        reflection = reflect_on_result("nmap", {"target": "10.10.10.1"}, nmap_output, populated_profile)
        assert isinstance(reflection, str)
        assert len(reflection) > 0

    def test_reflect_http(self, populated_profile, http_output):
        reflection = reflect_on_result("http", {"url": "http://10.10.10.1/"}, http_output, populated_profile)
        assert isinstance(reflection, str)

    def test_reflect_nuclei(self, populated_profile, nuclei_output):
        reflection = reflect_on_result("nuclei", {"target": "http://10.10.10.1/"}, nuclei_output, populated_profile)
        assert isinstance(reflection, str)

    def test_reflect_empty_result(self, target_profile):
        reflection = reflect_on_result("nmap", {"target": "10.10.10.1"}, "", target_profile)
        assert isinstance(reflection, str)

    def test_reflect_unknown_tool(self, target_profile):
        reflection = reflect_on_result("unknown_tool", {}, "some output", target_profile)
        assert isinstance(reflection, str)

    def test_reflect_failure(self, target_profile):
        reflection = reflect_on_result("nmap", {"target": "10.10.10.1"}, "Error: command failed", target_profile)
        assert isinstance(reflection, str)
