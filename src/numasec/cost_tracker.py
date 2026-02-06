"""
Cost Tracking System for NumaSec

Real-time token and cost tracking across LLM providers.
Display in CLI, warn on budget limits. Tracks per-task-type costs.
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class ProviderPricing:
    """Pricing per token for a provider."""
    input_per_million: float   # $ per 1M input tokens
    output_per_million: float  # $ per 1M output tokens


# Provider pricing (as of Feb 2026)
PRICING = {
    "deepseek": ProviderPricing(input_per_million=0.14, output_per_million=0.28),
    "claude": ProviderPricing(input_per_million=3.00, output_per_million=15.00),
    "openai": ProviderPricing(input_per_million=2.50, output_per_million=10.00),
    "ollama": ProviderPricing(input_per_million=0.0, output_per_million=0.0),  # Local
}


class CostTracker:
    """
    Track costs across providers in real-time.
    
    Features:
    - Per-provider token counting
    - Per-task-type cost tracking
    - Real-time cost calculation
    - Budget warnings
    - Session total
    """
    
    def __init__(self, budget_limit: float = 10.0):
        self.budget_limit = budget_limit
        self.tokens_by_provider: Dict[str, Dict[str, int]] = {}
        self.costs_by_task_type: Dict[str, float] = {}
        self.tool_calls = 0
        self.start_time = None
        
    def add_tokens(self, provider: str, input_tokens: int, output_tokens: int, task_type: str = ""):
        """Add tokens for a provider, optionally tracking task type."""
        provider = provider.lower()
        
        if provider not in self.tokens_by_provider:
            self.tokens_by_provider[provider] = {"input": 0, "output": 0}
        
        self.tokens_by_provider[provider]["input"] += input_tokens
        self.tokens_by_provider[provider]["output"] += output_tokens
        
        # Track cost by task type
        if task_type:
            cost = self._compute_cost(provider, input_tokens, output_tokens)
            self.costs_by_task_type[task_type] = self.costs_by_task_type.get(task_type, 0.0) + cost
    
    def _compute_cost(self, provider: str, input_tokens: int, output_tokens: int) -> float:
        """Compute cost for a specific token usage."""
        if provider not in PRICING:
            return 0.0
        pricing = PRICING[provider]
        input_cost = (input_tokens / 1_000_000) * pricing.input_per_million
        output_cost = (output_tokens / 1_000_000) * pricing.output_per_million
        return input_cost + output_cost
    
    def add_tool_call(self):
        """Increment tool call counter."""
        self.tool_calls += 1
    
    def get_provider_cost(self, provider: str) -> float:
        """Get cost for a specific provider."""
        provider = provider.lower()
        
        if provider not in self.tokens_by_provider:
            return 0.0
        
        if provider not in PRICING:
            return 0.0
        
        tokens = self.tokens_by_provider[provider]
        return self._compute_cost(provider, tokens["input"], tokens["output"])
    
    def get_total_cost(self) -> float:
        """Get total cost across all providers."""
        return sum(self.get_provider_cost(p) for p in self.tokens_by_provider)
    
    def get_total_tokens(self) -> tuple[int, int]:
        """Get total input and output tokens."""
        total_input = sum(t["input"] for t in self.tokens_by_provider.values())
        total_output = sum(t["output"] for t in self.tokens_by_provider.values())
        return total_input, total_output
    
    def is_over_budget(self) -> bool:
        """Check if over budget."""
        return self.get_total_cost() > self.budget_limit
    
    def get_budget_percentage(self) -> float:
        """Get percentage of budget used."""
        if self.budget_limit <= 0:
            return 0.0
        return (self.get_total_cost() / self.budget_limit) * 100
    
    def format_summary(self) -> str:
        """Get formatted summary string."""
        total_cost = self.get_total_cost()
        total_in, total_out = self.get_total_tokens()
        
        lines = ["Session Cost\n"]
        
        # Per-provider breakdown
        for provider, tokens in self.tokens_by_provider.items():
            cost = self.get_provider_cost(provider)
            if cost > 0 or provider == "ollama":
                provider_name = provider.title()
                lines.append(f"  {provider_name}: ${cost:.4f} ({tokens['input']:,} in / {tokens['output']:,} out)")
        
        # Per-task-type breakdown
        if self.costs_by_task_type:
            lines.append("")
            for task, cost in sorted(self.costs_by_task_type.items(), key=lambda x: x[1], reverse=True):
                if cost > 0.0001:
                    lines.append(f"  {task}: ${cost:.4f}")
        
        # Total
        lines.append(f"\n  Total: ${total_cost:.4f}")
        lines.append(f"  Tokens: {total_in + total_out:,}")
        lines.append(f"  Tools: {self.tool_calls} calls")
        
        # Budget warning
        if self.is_over_budget():
            lines.append(f"\n  [!] OVER BUDGET (${total_cost:.4f} / ${self.budget_limit:.2f})")
        else:
            pct = self.get_budget_percentage()
            if pct > 75:
                lines.append(f"\n  [!] {pct:.0f}% of budget used")
        
        return "\n".join(lines)
    
    def reset(self):
        """Reset all counters."""
        self.tokens_by_provider.clear()
        self.costs_by_task_type.clear()
        self.tool_calls = 0
