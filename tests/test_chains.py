"""
Tests for Chains — attack escalation chains.
"""

import pytest
from numasec.chains import get_escalation_chain, format_chain_for_prompt, ATTACK_CHAINS, ChainStep


class TestGetEscalationChain:
    def test_exact_match(self):
        chain = get_escalation_chain("sqli")
        assert chain is not None
        assert len(chain) >= 2

    def test_normalized_match(self):
        chain = get_escalation_chain("SQL Injection")
        assert chain is not None
        assert len(chain) >= 2

    def test_keyword_match(self):
        chain = get_escalation_chain("reflected xss in search")
        assert chain is not None

    def test_unknown_vuln(self):
        chain = get_escalation_chain("completely_unknown_vuln_type_xyz")
        assert chain is None

    def test_all_chains_have_steps(self):
        for name, steps in ATTACK_CHAINS.items():
            assert len(steps) >= 2, f"Chain '{name}' has fewer than 2 steps"
            for step in steps:
                assert isinstance(step, ChainStep)
                assert step.description


class TestFormatChainForPrompt:
    def test_formats_known_chain(self):
        text = format_chain_for_prompt("sqli")
        assert text != ""
        assert "escalation" in text.lower() or "chain" in text.lower()

    def test_empty_for_unknown(self):
        text = format_chain_for_prompt("unknown_vuln_xyz")
        assert text == ""

    def test_includes_steps(self):
        text = format_chain_for_prompt("lfi")
        assert text != ""
        # Should have numbered steps or descriptions
        assert "1." in text or "-" in text
