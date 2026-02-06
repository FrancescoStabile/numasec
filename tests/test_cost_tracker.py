"""
Tests for CostTracker — cost tracking with per-task-type breakdown.
"""

import pytest
from numasec.cost_tracker import CostTracker


class TestCostTracker:
    @pytest.fixture
    def tracker(self):
        return CostTracker(budget_limit=10.0)

    def test_initial_state(self, tracker):
        assert tracker.get_total_cost() == 0.0
        assert tracker.tool_calls == 0

    def test_add_tokens(self, tracker):
        tracker.add_tokens("deepseek", 1000, 500)
        total_in, total_out = tracker.get_total_tokens()
        assert total_in == 1000
        assert total_out == 500

    def test_add_tokens_with_task_type(self, tracker):
        tracker.add_tokens("deepseek", 1000, 500, task_type="tool_use")
        tracker.add_tokens("deepseek", 2000, 1000, task_type="analysis")
        
        assert "tool_use" in tracker.costs_by_task_type
        assert "analysis" in tracker.costs_by_task_type

    def test_add_tool_call(self, tracker):
        tracker.add_tool_call()
        tracker.add_tool_call()
        assert tracker.tool_calls == 2

    def test_budget_check(self, tracker):
        assert not tracker.is_over_budget()

    def test_budget_percentage(self, tracker):
        pct = tracker.get_budget_percentage()
        assert pct == 0.0

    def test_format_summary(self, tracker):
        tracker.add_tokens("deepseek", 1000, 500)
        tracker.add_tool_call()
        summary = tracker.format_summary()
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_reset(self, tracker):
        tracker.add_tokens("deepseek", 1000, 500)
        tracker.add_tool_call()
        tracker.reset()
        assert tracker.get_total_cost() == 0.0
        assert tracker.tool_calls == 0

    def test_multiple_providers(self, tracker):
        tracker.add_tokens("deepseek", 1000, 500)
        tracker.add_tokens("anthropic", 500, 200)
        total_in, total_out = tracker.get_total_tokens()
        assert total_in == 1500
        assert total_out == 700
