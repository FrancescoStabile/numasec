"""Tests for security_mcp.knowledge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from security_mcp.knowledge.loader import KnowledgeLoader
from security_mcp.knowledge.pack import KBPack
from security_mcp.knowledge.retriever import (
    Chunk,
    KnowledgeChunker,
    KnowledgeRetriever,
    estimate_tokens,
)
from security_mcp.knowledge.signer import TemplateSigner

# ---------------------------------------------------------------------------
# estimate_tokens
# ---------------------------------------------------------------------------


class TestEstimateTokens:
    def test_empty(self):
        assert estimate_tokens("") == 0

    def test_short_text(self):
        assert estimate_tokens("a" * 20) == 5

    def test_proportional(self):
        assert estimate_tokens("a" * 400) == 100


# ---------------------------------------------------------------------------
# KnowledgeLoader
# ---------------------------------------------------------------------------


class TestKnowledgeLoader:
    def test_load_from_dir(self, tmp_path: Path):
        template = {"id": "sql-injection", "title": "SQL Injection", "category": "detection"}
        (tmp_path / "sqli.yaml").write_text(yaml.dump(template))

        loader = KnowledgeLoader(template_dirs=[tmp_path])
        result = loader.load_all()
        assert "sql-injection" in result
        assert result["sql-injection"]["title"] == "SQL Injection"

    def test_get_template(self, tmp_path: Path):
        template = {"id": "xss", "title": "XSS", "category": "detection"}
        (tmp_path / "xss.yaml").write_text(yaml.dump(template))

        loader = KnowledgeLoader(template_dirs=[tmp_path])
        loader.load_all()
        assert loader.get_template("xss") is not None
        assert loader.get_template("nonexistent") is None

    def test_skip_malformed(self, tmp_path: Path):
        (tmp_path / "bad.yaml").write_text("not: valid: yaml: {{}")
        loader = KnowledgeLoader(template_dirs=[tmp_path], include_bundled=False)
        result = loader.load_all()
        assert len(result) == 0

    def test_skip_no_id(self, tmp_path: Path):
        (tmp_path / "noid.yaml").write_text(yaml.dump({"title": "No ID"}))
        loader = KnowledgeLoader(template_dirs=[tmp_path], include_bundled=False)
        result = loader.load_all()
        assert len(result) == 0


# ---------------------------------------------------------------------------
# KnowledgeChunker
# ---------------------------------------------------------------------------


SAMPLE_TEMPLATE = {
    "id": "cwe-89",
    "title": "SQL Injection Detection",
    "category": "detection",
    "description": "SQL injection occurs when user input is concatenated into SQL queries.",
    "patterns": [
        "SELECT * FROM users WHERE id = '{input}'",
        "UNION SELECT ... --",
        "' OR '1'='1",
    ],
    "remediation": {
        "primary": "Use parameterized queries",
        "secondary": ["Input validation", "WAF rules"],
    },
}


class TestKnowledgeChunker:
    def test_chunk_basic(self):
        chunker = KnowledgeChunker()
        chunks = chunker.chunk(SAMPLE_TEMPLATE)
        assert len(chunks) > 0
        assert all(isinstance(c, Chunk) for c in chunks)

    def test_chunk_has_context_header(self):
        chunker = KnowledgeChunker()
        chunks = chunker.chunk(SAMPLE_TEMPLATE)
        for chunk in chunks:
            assert "[detection]" in chunk.text
            assert "SQL Injection Detection" in chunk.text

    def test_chunk_metadata(self):
        chunker = KnowledgeChunker()
        chunks = chunker.chunk(SAMPLE_TEMPLATE)
        for chunk in chunks:
            assert chunk.template_id == "cwe-89"
            assert chunk.category == "detection"
            assert chunk.section != ""

    def test_chunk_respects_size(self):
        chunker = KnowledgeChunker(max_tokens=50)
        # Use newlines so the splitter can break across lines
        big = {
            "id": "big",
            "title": "Big",
            "category": "test",
            "content": "\n".join([f"This is line number {i} with some text" for i in range(100)]),
        }
        chunks = chunker.chunk(big)
        assert len(chunks) > 1


class TestChunkerSplitSections:
    def test_splits_string_values(self):
        chunker = KnowledgeChunker()
        sections = chunker._split_sections({"id": "x", "desc": "hello"})
        assert any(name == "desc" and text == "hello" for name, text in sections)

    def test_skips_metadata_keys(self):
        chunker = KnowledgeChunker()
        sections = chunker._split_sections(
            {"id": "x", "title": "T", "category": "C", "content": "data"}
        )
        names = [name for name, _ in sections]
        assert "id" not in names
        assert "title" not in names
        assert "content" in names

    def test_lists_joined(self):
        chunker = KnowledgeChunker()
        sections = chunker._split_sections({"id": "x", "items": ["a", "b", "c"]})
        _, text = sections[0]
        assert "a" in text
        assert "b" in text


# ---------------------------------------------------------------------------
# KnowledgeRetriever
# ---------------------------------------------------------------------------


class TestKnowledgeRetriever:
    @pytest.fixture()
    def retriever(self):
        chunks = [
            Chunk(text="SQL injection parameterized queries prevention", category="detection", template_id="cwe-89"),
            Chunk(text="Cross-site scripting XSS DOM sanitization", category="detection", template_id="cwe-79"),
            Chunk(text="Authentication bypass weak credentials brute force", category="attack", template_id="cwe-287"),
            Chunk(text="Remote code execution RCE command injection", category="attack", template_id="cwe-78"),
            Chunk(text="CSRF token validation cross-site request forgery", category="detection", template_id="cwe-352"),
        ]
        return KnowledgeRetriever(chunks=chunks)

    def test_query_returns_results(self, retriever: KnowledgeRetriever):
        results = retriever.query("SQL injection prevention")
        assert len(results) > 0
        assert results[0].score > 0

    def test_query_top_k(self, retriever: KnowledgeRetriever):
        results = retriever.query("injection", top_k=2)
        assert len(results) <= 2

    def test_query_category_filter(self, retriever: KnowledgeRetriever):
        results = retriever.query("injection", category="attack")
        for r in results:
            assert r.category == "attack"

    def test_query_cwe_filter(self, retriever: KnowledgeRetriever):
        results = retriever.query("injection", cwe="cwe-89")
        for r in results:
            assert "cwe-89" in r.text

    def test_query_empty(self):
        retriever = KnowledgeRetriever(chunks=[])
        results = retriever.query("anything")
        assert results == []

    def test_add_chunks(self):
        retriever = KnowledgeRetriever()
        assert retriever.query("test") == []

        # BM25 needs multiple docs for meaningful IDF scores
        retriever.add_chunks([
            Chunk(text="new chunk about testing security vulnerabilities"),
            Chunk(text="another chunk about database performance tuning"),
            Chunk(text="third chunk about network configuration setup"),
        ])
        results = retriever.query("testing security vulnerabilities")
        assert len(results) >= 1
        assert "testing" in results[0].text


# ---------------------------------------------------------------------------
# TemplateSigner
# ---------------------------------------------------------------------------


class TestTemplateSigner:
    def test_sign_and_verify(self, tmp_path: Path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text("id: test\ntitle: Test Template")

        signer = TemplateSigner()
        sig = signer.sign_file(template_file)
        assert isinstance(sig, str)
        assert len(sig) == 64

        assert signer.verify_file(template_file) is True

    def test_verify_modified(self, tmp_path: Path):
        template_file = tmp_path / "template.yaml"
        template_file.write_text("original content")

        signer = TemplateSigner()
        signer.sign_file(template_file)

        template_file.write_text("modified content")
        assert signer.verify_file(template_file) is False

    def test_verify_unknown(self, tmp_path: Path):
        signer = TemplateSigner()
        assert signer.verify_file(tmp_path / "nonexistent.yaml") is False

    def test_save_and_load(self, tmp_path: Path):
        sig_path = tmp_path / "signatures.json"
        template_file = tmp_path / "t.yaml"
        template_file.write_text("content")

        signer1 = TemplateSigner(signatures_path=sig_path)
        signer1.sign_file(template_file)
        signer1.save_signatures()

        assert sig_path.exists()
        data = json.loads(sig_path.read_text())
        assert str(template_file) in data

        signer2 = TemplateSigner(signatures_path=sig_path)
        assert signer2.verify_file(template_file) is True


# ---------------------------------------------------------------------------
# KBPack
# ---------------------------------------------------------------------------


class TestKBPack:
    def test_generate_key(self):
        key = KBPack.generate_key()
        assert isinstance(key, bytes)
        assert len(key) > 0

    def test_build_and_load(self, tmp_path: Path):
        payload_dir = tmp_path / "payloads"
        payload_dir.mkdir()
        (payload_dir / "sqli.yaml").write_text(
            yaml.dump({"id": "sqli", "payload": "' OR '1'='1"})
        )
        (payload_dir / "xss.yaml").write_text(
            yaml.dump({"id": "xss", "payload": "<script>alert(1)</script>"})
        )

        key = KBPack.generate_key()
        pack = KBPack(key=key)

        output = tmp_path / "test.kbpack"
        signature = pack.build(payload_dir, output)

        assert output.exists()
        assert isinstance(signature, str)
        assert len(signature) == 64

        loaded = pack.load(output)
        assert "sqli" in loaded
        assert "xss" in loaded
        assert loaded["sqli"]["payload"] == "' OR '1'='1"

    def test_verify_integrity(self, tmp_path: Path):
        payload_dir = tmp_path / "payloads"
        payload_dir.mkdir()
        (payload_dir / "test.yaml").write_text(yaml.dump({"id": "test"}))

        key = KBPack.generate_key()
        pack = KBPack(key=key)
        output = tmp_path / "test.kbpack"
        signature = pack.build(payload_dir, output)

        assert pack.verify(output, signature) is True
        assert pack.verify(output, "wrong_hash") is False

    def test_no_key_raises(self, tmp_path: Path):
        pack = KBPack()
        with pytest.raises(ValueError, match="key required"):
            pack.build(tmp_path, tmp_path / "out.kbpack")
        with pytest.raises(ValueError, match="key required"):
            pack.load(tmp_path / "out.kbpack")

    def test_wrong_key_fails(self, tmp_path: Path):
        payload_dir = tmp_path / "payloads"
        payload_dir.mkdir()
        (payload_dir / "test.yaml").write_text(yaml.dump({"id": "test"}))

        key1 = KBPack.generate_key()
        key2 = KBPack.generate_key()

        output = tmp_path / "test.kbpack"
        KBPack(key=key1).build(payload_dir, output)

        with pytest.raises(Exception):  # noqa: B017
            KBPack(key=key2).load(output)

    def test_empty_dir(self, tmp_path: Path):
        payload_dir = tmp_path / "empty"
        payload_dir.mkdir()

        key = KBPack.generate_key()
        pack = KBPack(key=key)
        output = tmp_path / "empty.kbpack"
        pack.build(payload_dir, output)

        loaded = pack.load(output)
        assert loaded == {}
