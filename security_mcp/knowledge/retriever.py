"""BM25 retriever with contextual header prepend (400-512 token chunks).

Supports optional hybrid retrieval: BM25 (0.6 weight) + semantic embeddings
(0.4 weight) via litellm.  Semantic reranking is activated when
``reranker_enabled=True`` and degrades gracefully to BM25-only on any error
(missing API key, network failure, etc.).
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("security_mcp.knowledge.retriever")

CHUNK_CONFIG = {
    "max_tokens": 450,
    "overlap_tokens": 60,
    "respect_boundaries": ["```", "patterns:", "examples:"],
}


def estimate_tokens(text: str) -> int:
    """Estimate token count (1 token ~ 4 chars)."""
    return len(text) // 4


@dataclass
class Chunk:
    """Knowledge chunk with metadata."""

    text: str
    section: str = ""
    template_id: str = ""
    category: str = ""
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class KnowledgeChunker:
    """Chunking with contextual header prepend.

    Inspired by Anthropic Contextual Chunking (-35% retrieval failures).
    Splits templates into 400-512 token chunks, preserving code blocks
    and YAML structure boundaries.
    """

    def __init__(
        self,
        max_tokens: int = 450,
        overlap_tokens: int = 60,
    ) -> None:
        self._max_tokens = max_tokens
        self._overlap_tokens = overlap_tokens

    def chunk(self, template: dict[str, Any]) -> list[Chunk]:
        """Split template into chunks with context headers."""
        template_id = template.get("id", "unknown")
        category = template.get("category", "")
        title = template.get("title", template_id)

        sections = self._split_sections(template)
        chunks: list[Chunk] = []

        for section_name, section_text in sections:
            # Context header prepended to each chunk for retrieval quality
            header = f"[{category}] {title} > {section_name}\n"

            pieces = self._split_preserving_boundaries(section_text)
            for piece in pieces:
                full_text = header + piece
                if estimate_tokens(full_text) > 0:
                    chunks.append(
                        Chunk(
                            text=full_text,
                            section=section_name,
                            template_id=template_id,
                            category=category,
                        )
                    )

        return chunks

    def _split_sections(self, template: dict[str, Any]) -> list[tuple[str, str]]:
        """Split template into named sections from its top-level keys."""
        sections: list[tuple[str, str]] = []
        skip_keys = {"id", "category", "title", "version", "tags", "cwe_ids"}

        for key, value in template.items():
            if key in skip_keys:
                continue

            if isinstance(value, str):
                sections.append((key, value))
            elif isinstance(value, list):
                text = "\n".join(str(item) for item in value)
                sections.append((key, text))
            elif isinstance(value, dict):
                # Serialize nested dicts as YAML-like text
                lines: list[str] = []
                for k, v in value.items():
                    if isinstance(v, list):
                        lines.append(f"{k}:")
                        for item in v:
                            lines.append(f"  - {item}")
                    else:
                        lines.append(f"{k}: {v}")
                sections.append((key, "\n".join(lines)))

        return sections

    def _split_preserving_boundaries(self, text: str) -> list[str]:
        """Split text respecting code blocks and YAML arrays.

        Produces chunks of approximately max_tokens size, avoiding
        splits inside fenced code blocks (```) and after YAML keys
        ending with ``:``.
        """
        max_chars = self._max_tokens * 4  # 1 token ~ 4 chars
        overlap_chars = self._overlap_tokens * 4

        if len(text) <= max_chars:
            return [text] if text.strip() else []

        pieces: list[str] = []
        lines = text.split("\n")
        current: list[str] = []
        current_len = 0
        in_code_block = False

        for line in lines:
            line_len = len(line) + 1  # +1 for newline

            # Track code block boundaries
            if line.strip().startswith("```"):
                in_code_block = not in_code_block

            # Don't split inside code blocks
            if current_len + line_len > max_chars and not in_code_block and current:
                pieces.append("\n".join(current))
                # Overlap: keep last few lines
                overlap_lines: list[str] = []
                overlap_len = 0
                for prev_line in reversed(current):
                    if overlap_len + len(prev_line) + 1 > overlap_chars:
                        break
                    overlap_lines.insert(0, prev_line)
                    overlap_len += len(prev_line) + 1
                current = overlap_lines
                current_len = overlap_len

            current.append(line)
            current_len += line_len

        if current:
            pieces.append("\n".join(current))

        return pieces


class KnowledgeRetriever:
    """BM25-based knowledge retrieval with optional hybrid semantic reranking.

    Validated by Anthropic Contextual Retrieval: -49% failures,
    -67% with reranking.

    When ``reranker_enabled=True`` and litellm is configured, retrieval uses a
    hybrid score::

        score = 0.6 * bm25_normalised + 0.4 * cosine_similarity

    Any error during embedding (missing key, network, etc.) silently falls back
    to BM25-only scoring so the retriever never raises.
    """

    HYBRID_BM25_WEIGHT: float = 0.6
    HYBRID_SEM_WEIGHT: float = 0.4

    def __init__(
        self,
        chunks: list[Chunk] | None = None,
        reranker_enabled: bool = False,
        embed_model: str = "text-embedding-3-small",
    ) -> None:
        self.chunks = chunks or []
        self.reranker_enabled = reranker_enabled
        self._embed_model = embed_model
        self._bm25: Any = None
        # Pre-computed chunk embeddings for semantic reranking.
        # ``None`` means not yet computed or computation failed.
        self._chunk_embeddings: list[list[float]] | None = None
        if self.chunks:
            self._build_index()

    def add_chunks(self, new_chunks: list[Chunk]) -> None:
        """Add chunks and rebuild the index."""
        self.chunks.extend(new_chunks)
        self._build_index()

    def _build_index(self) -> None:
        """Build BM25 index and optionally pre-compute chunk embeddings."""
        from rank_bm25 import BM25Okapi

        corpus = [self._tokenize(c.text) for c in self.chunks]
        self._bm25 = BM25Okapi(corpus)
        logger.info("BM25 index built with %d chunks", len(self.chunks))

        # Pre-compute chunk embeddings only when semantic reranking is requested.
        # This is a blocking call but happens once at startup; litellm batches
        # automatically when the list is large.
        if self.reranker_enabled:
            try:
                self._chunk_embeddings = self._compute_embeddings([c.text for c in self.chunks])
                logger.info("Chunk embeddings pre-computed (%d vectors)", len(self._chunk_embeddings))
            except Exception as exc:
                logger.warning("Embedding pre-computation failed — falling back to BM25-only: %s", exc)
                self._chunk_embeddings = None

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Simple whitespace + punctuation tokenizer."""
        return re.findall(r"\w+", text.lower())

    def query(
        self,
        question: str,
        top_k: int = 5,
        category: str | None = None,
        cwe: str | None = None,
    ) -> list[Chunk]:
        """Query knowledge base with BM25 (+ optional semantic) scoring."""
        if not self.chunks or self._bm25 is None:
            return []

        tokens = self._tokenize(question)
        if not tokens:
            return []

        scores = self._bm25.get_scores(tokens)

        # Pair chunks with scores
        scored: list[tuple[float, int]] = [(float(score), idx) for idx, score in enumerate(scores)]

        # Filter by category if specified
        if category:
            scored = [(s, i) for s, i in scored if self.chunks[i].category == category]

        # Filter by CWE if specified
        if cwe:
            scored = [(s, i) for s, i in scored if cwe in self.chunks[i].text]

        # Sort by BM25 score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        # --- Hybrid semantic reranking (R6) ---
        # Re-score top BM25 candidates using cosine similarity of embeddings.
        # Only the top ``top_k * 3`` BM25 candidates are re-ranked (efficiency).
        if self.reranker_enabled and self._chunk_embeddings is not None and scored:
            candidates = scored[: top_k * 3]
            try:
                q_emb = self._compute_embeddings([question])[0]
                sem_scores = [self._cosine(q_emb, self._chunk_embeddings[i]) for _, i in candidates]
                max_bm25 = max(s for s, _ in candidates) or 1.0
                hybrid: list[tuple[float, int]] = [
                    (
                        self.HYBRID_BM25_WEIGHT * (bm25 / max_bm25) + self.HYBRID_SEM_WEIGHT * sem,
                        idx,
                    )
                    for (bm25, idx), sem in zip(candidates, sem_scores, strict=False)
                ]
                hybrid.sort(key=lambda x: x[0], reverse=True)
                scored = hybrid
                logger.debug("Hybrid re-ranking applied to %d candidates", len(candidates))
            except Exception as exc:
                logger.warning("Hybrid scoring failed — falling back to BM25: %s", exc)
                # ``scored`` is already the BM25-sorted list; keep it

        # Take top-k
        results: list[Chunk] = []
        for score, idx in scored[:top_k]:
            if score <= 0:
                break
            chunk = self.chunks[idx]
            chunk.score = score
            results.append(chunk)

        logger.debug(
            "Query '%s' returned %d results (top score: %.2f)",
            question[:50],
            len(results),
            results[0].score if results else 0.0,
        )
        return results

    # ------------------------------------------------------------------
    # Embedding helpers
    # ------------------------------------------------------------------

    def _compute_embeddings(self, texts: list[str]) -> list[list[float]]:
        """Compute embeddings via litellm (sync).

        Uses ``self._embed_model`` (default: ``text-embedding-3-small``).
        Raises on any error so callers can fall back to BM25.

        Args:
            texts: List of strings to embed.

        Returns:
            List of embedding vectors (list of float).
        """
        import litellm  # soft dependency — only needed when reranker_enabled

        response = litellm.embedding(model=self._embed_model, input=texts)
        return [item["embedding"] for item in response.data]

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors.

        Uses ``math.fsum`` for numeric stability.  Returns 0.0 when either
        vector is the zero vector.
        """
        dot = math.fsum(x * y for x, y in zip(a, b, strict=False))
        norm_a = math.sqrt(math.fsum(x * x for x in a))
        norm_b = math.sqrt(math.fsum(x * x for x in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot / (norm_a * norm_b)
