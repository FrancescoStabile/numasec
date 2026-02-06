"""
Tests for Context — smart context window management.
"""

import pytest
from numasec.context import (
    estimate_tokens,
    should_trim_context,
    trim_context_window,
    smart_trim_context,
)


class TestEstimateTokens:
    def test_empty_string(self):
        assert estimate_tokens("") == 0

    def test_simple_string(self):
        tokens = estimate_tokens("Hello world this is a test")
        assert tokens > 0
        assert tokens < 50

    def test_dict_content(self):
        content = [{"type": "text", "text": "Hello world"}]
        tokens = estimate_tokens(content)
        assert tokens > 0

    def test_none_content(self):
        tokens = estimate_tokens(None)
        assert tokens == 0


class TestShouldTrimContext:
    def test_few_messages(self):
        messages = [{"role": "user", "content": "test"}] * 5
        needs_trim, token_count = should_trim_context(messages, threshold=25, max_tokens=100000)
        assert not needs_trim
        assert token_count >= 0

    def test_many_messages(self):
        messages = [{"role": "user", "content": "test"}] * 30
        needs_trim, _ = should_trim_context(messages, threshold=25, max_tokens=100000)
        assert needs_trim

    def test_large_tokens(self):
        # 5 messages * 100000 chars = 500000 chars / 4 = 125000 tokens > 100000
        messages = [{"role": "user", "content": "x" * 100000}] * 5
        needs_trim, token_count = should_trim_context(messages, threshold=25, max_tokens=100000)
        assert needs_trim
        assert token_count > 100000


class TestTrimContextWindow:
    def test_preserves_first_messages(self):
        messages = [
            {"role": "user", "content": f"Message {i}"}
            for i in range(30)
        ]
        trimmed = trim_context_window(messages, max_messages=10, preserve_first=2)

        assert len(trimmed) <= 10
        # First messages should be preserved
        assert trimmed[0]["content"] == "Message 0"
        assert trimmed[1]["content"] == "Message 1"
        # Last messages should be recent
        assert "Message 29" in trimmed[-1]["content"]

    def test_no_trim_needed(self):
        messages = [{"role": "user", "content": f"Msg {i}"} for i in range(5)]
        trimmed = trim_context_window(messages, max_messages=20, preserve_first=2)
        assert len(trimmed) == 5

    def test_empty_messages(self):
        trimmed = trim_context_window([], max_messages=10, preserve_first=2)
        assert trimmed == []


class TestSmartTrimContext:
    def test_preserves_recent_window(self):
        messages = [
            {"role": "user", "content": f"Old message {i}"}
            for i in range(20)
        ]
        messages.extend([
            {"role": "user", "content": f"Recent message {i}"}
            for i in range(5)
        ])

        trimmed = smart_trim_context(messages, max_tokens=5000, recent_window=5)

        # Recent messages should be intact
        recent_contents = [m["content"] for m in trimmed[-5:]]
        assert any("Recent" in c for c in recent_contents)

    def test_no_trim_if_within_budget(self):
        messages = [{"role": "user", "content": "Short msg"}] * 5
        trimmed = smart_trim_context(messages, max_tokens=100000, recent_window=3)
        assert len(trimmed) == 5

    def test_empty_messages(self):
        trimmed = smart_trim_context([], max_tokens=5000, recent_window=3)
        assert trimmed == []
