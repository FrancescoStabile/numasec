"""
NumaSec v3 - Smart Context Management

3-level context strategy:
1. TargetProfile summary → always in system prompt (never trimmed)
2. Middle messages → summarized heuristically (tool results compressed)
3. Recent window → kept intact (last N messages)

Preserves assistant+tool atomic groups to avoid breaking LLM validation.
"""

from __future__ import annotations

from typing import List, Dict, Any


def trim_context_window(
    messages: List[Dict[str, Any]], 
    max_messages: int = 20,
    preserve_first: int = 2,
) -> List[Dict[str, Any]]:
    """
    Trim conversation history to recent messages.
    
    CRITICAL: Preserves assistant+tools sequences to avoid breaking DeepSeek validation.
    
    Strategy:
    1. Identify all message "groups" (user, assistant, assistant+tools)
    2. Never split an assistant+tools group
    3. Keep first N groups + last M groups within budget
    """
    if len(messages) <= max_messages:
        return messages
    
    # STEP 1: Group messages into atomic units
    groups = _group_messages(messages)
    
    if len(groups) <= 2:
        return messages
    
    # STEP 2: Calculate how many groups to preserve from start
    first_groups_count = 0
    first_msgs_count = 0
    while first_groups_count < len(groups) and first_msgs_count < preserve_first:
        first_msgs_count += len(groups[first_groups_count])
        first_groups_count += 1
    
    first_msgs = _flatten_groups(groups[:first_groups_count])
    
    # Calculate remaining budget for recent messages
    remaining_budget = max_messages - len(first_msgs)
    
    if remaining_budget <= 0:
        return first_msgs[:max_messages]
    
    # STEP 3: Fill with recent groups (from end) within budget
    recent_groups = []
    recent_msgs_count = 0
    
    for g in reversed(groups[first_groups_count:]):
        if recent_msgs_count + len(g) <= remaining_budget:
            recent_groups.insert(0, g)
            recent_msgs_count += len(g)
        else:
            break
    
    recent_msgs = _flatten_groups(recent_groups)
    
    return first_msgs + recent_msgs


def smart_trim_context(
    messages: List[Dict[str, Any]],
    max_tokens: int = 80000,
    recent_window: int = 12,
) -> List[Dict[str, Any]]:
    """
    Smart context trimming with 3 levels:
    
    Level 1: TargetProfile + AttackPlan are in system prompt (not in messages)
    Level 2: Middle messages get tool results compressed
    Level 3: Recent window (last N messages) kept intact
    
    This is more intelligent than simple message count trimming.
    """
    total_tokens = sum(estimate_tokens(msg.get("content", "")) for msg in messages)
    
    if total_tokens <= max_tokens:
        return messages
    
    # Group messages
    groups = _group_messages(messages)
    
    if len(groups) <= 3:
        return messages
    
    # Split into: first group, middle groups, recent groups
    recent_group_count = min(recent_window // 2, len(groups) - 2)
    first_groups = groups[:1]  # Keep first user message
    middle_groups = groups[1:-recent_group_count] if recent_group_count > 0 else groups[1:]
    recent_groups = groups[-recent_group_count:] if recent_group_count > 0 else []
    
    # Compress middle groups: summarize tool results
    compressed_middle = []
    for group in middle_groups:
        compressed_group = []
        for msg in group:
            if msg.get("role") == "tool":
                # Compress tool results in middle section
                content = msg.get("content", "")
                if isinstance(content, dict):
                    tool_content = content.get("content", "")
                    if isinstance(tool_content, str) and len(tool_content) > 500:
                        compressed_content = _summarize_tool_result(tool_content)
                        compressed_msg = dict(msg)
                        compressed_msg["content"] = {
                            "tool_call_id": content.get("tool_call_id", ""),
                            "content": compressed_content,
                        }
                        compressed_group.append(compressed_msg)
                        continue
                elif isinstance(content, str) and len(content) > 500:
                    compressed_msg = dict(msg)
                    compressed_msg["content"] = _summarize_tool_result(content)
                    compressed_group.append(compressed_msg)
                    continue
            compressed_group.append(msg)
        compressed_middle.append(compressed_group)
    
    # Check if compressed version fits
    result = _flatten_groups(first_groups + compressed_middle + recent_groups)
    result_tokens = sum(estimate_tokens(msg.get("content", "")) for msg in result)
    
    if result_tokens <= max_tokens:
        return result
    
    # Still too large — drop middle groups from oldest
    while compressed_middle and result_tokens > max_tokens:
        dropped = compressed_middle.pop(0)
        dropped_tokens = sum(estimate_tokens(msg.get("content", "")) for msg in dropped)
        result_tokens -= dropped_tokens
    
    return _flatten_groups(first_groups + compressed_middle + recent_groups)


def _group_messages(messages: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """Group messages into atomic units that can't be split."""
    groups = []
    i = 0
    while i < len(messages):
        msg = messages[i]
        role = msg.get("role")
        
        if role == "assistant":
            content = msg.get("content", [])
            has_tool_calls = False
            
            if isinstance(content, list):
                has_tool_calls = any(
                    isinstance(item, dict) and item.get("type") == "tool_use"
                    for item in content
                )
            
            if has_tool_calls:
                group = [messages[i]]
                j = i + 1
                while j < len(messages) and messages[j].get("role") == "tool":
                    group.append(messages[j])
                    j += 1
                groups.append(group)
                i = j
            else:
                groups.append([messages[i]])
                i += 1
        else:
            groups.append([messages[i]])
            i += 1
    
    return groups


def _flatten_groups(groups: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Flatten a list of groups into a flat message list."""
    result = []
    for g in groups:
        result.extend(g)
    return result


def _summarize_tool_result(result: str, max_chars: int = 300) -> str:
    """Heuristically summarize a tool result for middle context."""
    if len(result) <= max_chars:
        return result
    
    # For JSON-like results, try to extract key info
    if result.strip().startswith("{") or result.strip().startswith("["):
        # Keep first few lines which usually have summary info
        lines = result.split("\n")
        summary_lines = lines[:8]
        summary = "\n".join(summary_lines)
        if len(summary) > max_chars:
            summary = summary[:max_chars]
        return summary + f"\n[... {len(result) - len(summary)} chars compressed ...]"
    
    # For text results, keep beginning (usually has key info)
    return result[:max_chars] + f"\n[... {len(result) - max_chars} chars compressed ...]"


def estimate_tokens(content: Any) -> int:
    """
    Estimate token count for content.
    Rough estimate: 1 token ≈ 4 characters (English)
    """
    if isinstance(content, str):
        return len(content) // 4
    elif isinstance(content, list):
        return sum(estimate_tokens(item) for item in content)
    elif isinstance(content, dict):
        return sum(estimate_tokens(v) for v in content.values())
    return 0


def calculate_context_cost(
    messages: List[Dict[str, Any]], 
    system_prompt: str,
    cost_per_1k_tokens: float = 0.00014,  # DeepSeek default
) -> float:
    """Calculate input token cost for current context."""
    system_tokens = estimate_tokens(system_prompt)
    message_tokens = sum(
        estimate_tokens(msg.get("content", "")) 
        for msg in messages
    )
    total_tokens = system_tokens + message_tokens
    return (total_tokens / 1000) * cost_per_1k_tokens


def should_trim_context(
    messages: List[Dict[str, Any]], 
    threshold: int = 25,
    max_tokens: int = 100000,
) -> tuple[bool, int]:
    """
    Check if context should be trimmed.
    
    Returns (needs_trim, current_token_count) so callers can reuse the count
    instead of re-computing it.
    
    Checks both message count AND estimated token count.
    DeepSeek limit: 131,072 tokens (messages + completion)
    We use 100k as safety margin (leaving 31k for system + completion)
    """
    total_tokens = sum(estimate_tokens(msg.get("content", "")) for msg in messages)
    needs_trim = len(messages) > threshold or total_tokens > max_tokens
    return needs_trim, total_tokens


def should_trim_context_tokens(messages: List[Dict[str, Any]], max_tokens: int = 100000) -> bool:
    """Token-aware context trimming check."""
    total_tokens = sum(estimate_tokens(msg.get("content", "")) for msg in messages)
    return total_tokens > max_tokens
