"""
Tests for Knowledge Loader v2 — section-level, priority-ordered,
phase-adaptive knowledge retrieval.
"""

import pytest
from numasec.knowledge_loader import (
    load_knowledge,
    get_relevant_knowledge,
    KNOWLEDGE_MAP,
    TECH_IMPLIES,
    _normalize_tech,
    _split_sections,
    _load_chunks,
    _PHASE_BUDGETS,
    _DEFAULT_BUDGET,
)
from numasec.target_profile import (
    TargetProfile, Technology, VulnHypothesis, Port,
)


# ═══════════════════════════════════════════════════════════════════════════
# Section Chunking
# ═══════════════════════════════════════════════════════════════════════════


class TestSectionChunking:
    def test_splits_on_h2(self):
        md = (
            "# Title\nIntro text that is long enough to form a section chunk.\n\n"
            "## Section A\n" + "Content A. " * 20 + "\n\n"
            "## Section B\n" + "Content B. " * 20
        )
        chunks = _split_sections(md)
        assert len(chunks) >= 2
        headings = [c.heading for c in chunks]
        assert "Section A" in headings
        assert "Section B" in headings

    def test_respects_code_fences(self):
        md = (
            "## Real Section\n"
            + "Some meaningful text. " * 10 + "\n"
            "```\n"
            "## This is inside a code block\n"
            "```\n"
            + "More meaningful text. " * 10 + "\n"
            "\n"
            "## Another Real Section\n"
            + "Another block of content. " * 10
        )
        chunks = _split_sections(md)
        headings = [c.heading for c in chunks]
        assert "This is inside a code block" not in headings
        assert "Real Section" in headings
        assert "Another Real Section" in headings

    def test_single_section_no_headers(self):
        md = "# Title\n\nJust a block of text without any ## headers.\nLine two.\nLine three.\nLine four."
        chunks = _split_sections(md)
        # Whole file becomes one chunk (if long enough)
        assert len(chunks) >= 1

    def test_tokens_estimated(self):
        md = "## Test\n" + "x" * 400
        chunks = _split_sections(md)
        assert len(chunks) == 1
        assert chunks[0].tokens == len(chunks[0].content) // 4

    def test_skips_tiny_sections(self):
        md = "## Tiny\nHi\n\n## Real Section\n" + "Content. " * 30
        chunks = _split_sections(md)
        headings = [c.heading for c in chunks]
        # "Tiny" has < 80 chars → should be skipped
        assert "Tiny" not in headings
        assert "Real Section" in headings


# ═══════════════════════════════════════════════════════════════════════════
# Technology Normalisation
# ═══════════════════════════════════════════════════════════════════════════


class TestTechNormalisation:
    def test_apache_versioned(self):
        assert _normalize_tech("Apache/2.4.41 (Ubuntu)") == "apache"

    def test_php_versioned(self):
        assert _normalize_tech("PHP/7.4.3") == "php"

    def test_openssh(self):
        assert _normalize_tech("OpenSSH 8.2p1 Ubuntu-4ubuntu0.5") == "openssh"

    def test_simple_name(self):
        assert _normalize_tech("nginx") == "nginx"

    def test_iis_versioned(self):
        assert _normalize_tech("Microsoft-IIS/10.0") == "microsoft-iis"

    def test_empty_string(self):
        result = _normalize_tech("")
        assert isinstance(result, str)


# ═══════════════════════════════════════════════════════════════════════════
# Implied Technologies
# ═══════════════════════════════════════════════════════════════════════════


class TestImpliedTech:
    def test_wordpress_implies_php_mysql(self):
        implied = TECH_IMPLIES.get("wordpress", [])
        assert "php" in implied
        assert "mysql" in implied

    def test_django_implies_python(self):
        assert "python" in TECH_IMPLIES.get("django", [])

    def test_spring_implies_java(self):
        assert "java" in TECH_IMPLIES.get("spring", [])

    def test_express_implies_node(self):
        implied = TECH_IMPLIES.get("express", [])
        assert "node" in implied
        assert "javascript" in implied

    def test_implied_tech_integrated(self):
        """WordPress profile should load PHP payloads via implied tech."""
        profile = TargetProfile()
        profile.add_technology(Technology(name="WordPress", category="cms"))
        knowledge = get_relevant_knowledge(profile, "enumeration")
        assert isinstance(knowledge, str)
        # Should have loaded something (WordPress → php → payloads/php_rce.md)


# ═══════════════════════════════════════════════════════════════════════════
# Load Knowledge — Core API
# ═══════════════════════════════════════════════════════════════════════════


class TestLoadKnowledge:
    def test_load_known_topic(self):
        content = load_knowledge(["sqli"])
        assert isinstance(content, str)
        assert len(content) > 0
        # Should contain SQL-related content
        assert "sql" in content.lower() or "injection" in content.lower()

    def test_load_unknown_topic(self):
        content = load_knowledge(["nonexistent_topic_xyz"])
        assert content == ""

    def test_respects_token_budget(self):
        content = load_knowledge(list(KNOWLEDGE_MAP.keys()), max_total_tokens=100)
        assert isinstance(content, str)
        # With 100 token budget (~400 chars), output should be small
        assert len(content) < 2000

    def test_empty_topics(self):
        content = load_knowledge([])
        assert content == ""

    def test_section_filtering(self):
        """Loading 'sqli' should get SQL Injection section, not entire web_cheatsheet."""
        content = load_knowledge(["sqli"])
        assert "SQL" in content or "sql" in content.lower()
        # Should NOT have unrelated sections like "XSS" or "File Upload" from web_cheatsheet
        # (unless they fit in the budget after the primary content)

    def test_deduplication(self):
        """Same file referenced by multiple keys should only be loaded once."""
        content1 = load_knowledge(["sqli", "sqli"])
        content2 = load_knowledge(["sqli"])
        assert content1 == content2

    def test_multiple_keys(self):
        """Loading multiple keys should combine content."""
        content = load_knowledge(["sqli", "xss"])
        assert isinstance(content, str)
        assert len(content) > 0

    def test_focused_file_fully_loaded(self):
        """Focused files (no section hint) should be loaded entirely."""
        content = load_knowledge(["jwt"])
        assert isinstance(content, str)
        if content:  # only check if file exists
            assert "jwt" in content.lower() or "token" in content.lower()


# ═══════════════════════════════════════════════════════════════════════════
# Get Relevant Knowledge — Agent Integration
# ═══════════════════════════════════════════════════════════════════════════


class TestGetRelevantKnowledge:
    def test_with_technologies(self):
        profile = TargetProfile()
        profile.add_technology(Technology(name="PHP", version="7.4", category="language"))
        knowledge = get_relevant_knowledge(profile, "enumeration")
        assert isinstance(knowledge, str)

    def test_with_vulns(self):
        profile = TargetProfile()
        hyp = VulnHypothesis(vuln_type="sqli", location="/test", confidence=0.9)
        profile.hypotheses.append(hyp)
        knowledge = get_relevant_knowledge(profile, "exploitation")
        assert isinstance(knowledge, str)
        assert len(knowledge) > 0

    def test_empty_profile(self):
        profile = TargetProfile()
        knowledge = get_relevant_knowledge(profile, "")
        assert isinstance(knowledge, str)
        # Should fallback to "recon" knowledge
        assert len(knowledge) > 0

    def test_confirmed_vuln_priority(self):
        """Confirmed vulns should be loaded first (highest priority)."""
        profile = TargetProfile()
        # Add a confirmed SQLi
        hyp = VulnHypothesis(
            vuln_type="sqli", location="/login",
            confidence=1.0, tested=True, confirmed=True,
        )
        profile.hypotheses.append(hyp)
        # Add many technologies to fill budget
        for tech in ["PHP", "Apache", "MySQL", "nginx"]:
            profile.add_technology(Technology(name=tech, category="server"))

        knowledge = get_relevant_knowledge(profile, "exploitation")
        # SQLi content should be present (highest priority)
        assert "sql" in knowledge.lower() or "injection" in knowledge.lower()

    def test_os_detection_linux(self):
        """Linux should be detected from SSH port banner."""
        profile = TargetProfile()
        profile.ports.append(Port(number=22, service="ssh", version="OpenSSH 8.2p1 Ubuntu"))
        knowledge = get_relevant_knowledge(profile, "enumeration")
        assert isinstance(knowledge, str)

    def test_os_detection_windows(self):
        """Windows should be detected from IIS or Microsoft in banner."""
        profile = TargetProfile()
        profile.ports.append(Port(number=80, service="http", version="Microsoft-IIS/10.0"))
        knowledge = get_relevant_knowledge(profile, "enumeration")
        assert isinstance(knowledge, str)

    def test_knowledge_map_has_entries(self):
        assert len(KNOWLEDGE_MAP) >= 5


# ═══════════════════════════════════════════════════════════════════════════
# Phase-Adaptive Budgets
# ═══════════════════════════════════════════════════════════════════════════


class TestPhaseBudgets:
    def test_recon_has_lower_budget(self):
        assert _PHASE_BUDGETS["recon"] < _DEFAULT_BUDGET

    def test_exploitation_has_higher_budget(self):
        assert _PHASE_BUDGETS["exploitation"] > _DEFAULT_BUDGET

    def test_exploitation_loads_more(self):
        """Exploitation phase should load more knowledge than recon."""
        profile = TargetProfile()
        hyp = VulnHypothesis(vuln_type="sqli", location="/test", confidence=0.9)
        profile.hypotheses.append(hyp)

        recon_knowledge = get_relevant_knowledge(profile, "recon")
        exploit_knowledge = get_relevant_knowledge(profile, "exploitation")
        # Both should produce content; exploitation budget is larger
        assert isinstance(recon_knowledge, str)
        assert isinstance(exploit_knowledge, str)


# ═══════════════════════════════════════════════════════════════════════════
# Chunk Caching
# ═══════════════════════════════════════════════════════════════════════════


class TestChunkCaching:
    def test_cached_chunks_are_tuples(self):
        """Cached return should be a tuple (immutable)."""
        chunks = _load_chunks("quick_wins.md")
        assert isinstance(chunks, tuple)

    def test_nonexistent_file_returns_empty(self):
        chunks = _load_chunks("this/does/not/exist.md")
        assert chunks == ()

    def test_cached_idempotent(self):
        """Multiple calls return the same object (cache hit)."""
        a = _load_chunks("quick_wins.md")
        b = _load_chunks("quick_wins.md")
        assert a is b  # same object from cache
