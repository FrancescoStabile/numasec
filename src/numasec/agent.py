"""
NumaSec v3 - Agent

THE agent loop — ReAct architecture with structured intelligence.

Architecture:
1. Build DYNAMIC system prompt (base + profile + plan + knowledge + chains)
2. Call LLM (streaming, task-aware routing)
3. Execute tools if requested
4. Run extractors → update TargetProfile
5. Reflect on results → generate strategic insight
6. Inject escalation chains if vulnerability confirmed
7. Self-correct on failures with error recovery guidance
8. Loop detection prevents infinite cycles
9. Adaptive timeouts per tool type
10. Repeat until plan complete or max iterations
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from collections import deque
from pathlib import Path
from typing import AsyncGenerator, Any, Union

from numasec.router import LLMRouter, Provider, TaskType
from numasec.state import State, Finding
from numasec.tools import create_tool_registry, ToolRegistry, check_tool_availability, format_tool_availability
from numasec.error_recovery import inject_recovery_guidance
from numasec.tools.browser_fallback import should_retry_with_browser, format_browser_suggestion
from numasec.context import smart_trim_context, should_trim_context, estimate_tokens
from numasec.extractors import run_extractor
from numasec.planner import generate_plan
from numasec.reflection import reflect_on_result
from numasec.chains import format_chain_for_prompt
from numasec.knowledge_loader import get_relevant_knowledge

logger = logging.getLogger("numasec.agent")


# ═══════════════════════════════════════════════════════════════════════════
# Adaptive Timeouts per tool type
# ═══════════════════════════════════════════════════════════════════════════

TOOL_TIMEOUTS: dict[str, int] = {
    "nmap": 600,
    "nuclei": 600,
    "sqlmap": 600,
    "ffuf": 300,
    "subfinder": 120,
    "httpx": 60,
    "http": 30,
    "run_command": 120,
    "run_exploit": 120,
    "read_file": 10,
    "write_file": 10,
    # Browser tools: generous timeouts to allow smart retry cascade
    # (resilient_navigate + dismiss_overlays + smart_fill/click + dialog wait)
    "browser_navigate": 90,
    "browser_fill": 90,      # Was 30 — caused Juice Shop timeout
    "browser_click": 60,     # Was 30
    "browser_screenshot": 60, # Was 30
    "browser_login": 90,     # Was 60
    "browser_get_cookies": 30,
    "browser_set_cookies": 10,
    "browser_clear_session": 10,
}


# ═══════════════════════════════════════════════════════════════════════════
# Agent Events (for CLI streaming)
# ═══════════════════════════════════════════════════════════════════════════


class AgentEvent:
    """Event emitted by agent during execution."""
    
    def __init__(self, type: str, **data):
        self.type = type
        self.data = data
    
    @property
    def content(self) -> str:
        return self.data.get("content", "")
    
    @property
    def tool_name(self) -> str:
        return self.data.get("tool_name", "")
    
    @property
    def tool_result(self) -> str:
        return self.data.get("tool_result", "")
    
    @property
    def finding(self) -> Finding | None:
        return self.data.get("finding")


# ═══════════════════════════════════════════════════════════════════════════
# The Agent — v3 with ReAct, extractors, planner, reflection
# ═══════════════════════════════════════════════════════════════════════════


class Agent:
    """
    The NumaSec agent — v3 architecture.
    
    Key architecture features:
    - TargetProfile: Structured memory of everything discovered
    - Extractors: Auto-parse tool results into TargetProfile
    - Planner: Hierarchical attack plan guides LLM decisions
    - Reflection: Strategic analysis after each tool call
    - Chains: Escalation paths for confirmed vulns
    - Knowledge: Context-aware cheatsheet injection
    - Loop detection: Prevents infinite tool call cycles
    - Smart _is_failure: Context-aware failure detection
    - Adaptive timeouts: Per-tool-type timeout values
    - Task-based routing: Best provider for each task type
    """
    
    def __init__(
        self,
        router: LLMRouter | None = None,
        tools: ToolRegistry | None = None,
        max_iterations: int = 50,
        tool_timeout: int = 300,
        session_timeout: int = 3600,
    ):
        self.router = router or LLMRouter(primary=Provider.DEEPSEEK)
        self.tools = tools or create_tool_registry()
        self.max_iterations = max_iterations
        self.tool_timeout = tool_timeout
        self.session_timeout = session_timeout
        
        # State
        self.state = State()
        self.is_running = False
        
        # Circuit breaker: Track repeated errors
        self.error_counter: dict[str, int] = {}
        self.max_repeated_errors = 3
        
        # Loop detection: Track recent tool calls
        self._recent_tool_hashes: deque[str] = deque(maxlen=10)
        self._loop_threshold = 2  # Block after 2 identical calls
        
        # Tool availability: detect which external tools are installed
        self._tool_availability = check_tool_availability()
        self._tool_availability_prompt = format_tool_availability(self._tool_availability)
        
        # Load base system prompt
        self._base_system_prompt = self._load_system_prompt()
    
    def _load_system_prompt(self) -> str:
        """Load base system prompt from file."""
        prompt_file = Path(__file__).parent / "prompts" / "system.md"
        if prompt_file.exists():
            return prompt_file.read_text()
        return "You are an expert penetration tester."
    
    def _build_dynamic_system_prompt(self) -> str:
        """
        Build dynamic system prompt that includes:
        1. Base system prompt
        2. TargetProfile summary (structured memory)
        3. AttackPlan status (what to do next)
        4. Escalation chains (for confirmed vulns)
        5. Relevant knowledge (context-aware)
        """
        parts = [self._base_system_prompt]
        
        # Tool availability — tell LLM what's installed
        if self._tool_availability_prompt:
            parts.append("\n" + self._tool_availability_prompt)
        
        # TargetProfile summary
        profile_summary = self.state.profile.to_prompt_summary()
        if profile_summary and "No data" not in profile_summary:
            parts.append("\n\n---\n\n" + profile_summary)
        
        # AttackPlan status
        if self.state.plan and self.state.plan.objective:
            plan_summary = self.state.plan.to_prompt_summary()
            parts.append("\n\n---\n\n" + plan_summary)
        
        # Escalation chains for confirmed vulns
        confirmed = self.state.profile.get_confirmed_vulns()
        for vuln in confirmed[:3]:  # Limit to avoid token bloat
            chain_text = format_chain_for_prompt(vuln.vuln_type)
            if chain_text:
                parts.append("\n" + chain_text)
        
        # Context-aware knowledge injection
        current_phase = ""
        if self.state.plan:
            cp = self.state.plan.current_phase()
            if cp:
                current_phase = cp.name.lower()
        
        knowledge = get_relevant_knowledge(self.state.profile, current_phase)
        if knowledge:
            parts.append("\n\n---\n\n## Relevant Knowledge\n\n" + knowledge)
        
        return "\n".join(parts)
    
    def _compute_tool_hash(self, name: str, args: dict) -> str:
        """Compute hash for a tool call to detect loops."""
        key = json.dumps({"name": name, "args": args}, sort_keys=True)
        return hashlib.md5(key.encode()).hexdigest()[:12]
    
    def _detect_loop(self, name: str, args: dict) -> bool:
        """
        Check if this tool call is a repeated loop.
        Returns True if the same call was made recently.
        """
        tool_hash = self._compute_tool_hash(name, args)
        count = sum(1 for h in self._recent_tool_hashes if h == tool_hash)
        self._recent_tool_hashes.append(tool_hash)
        return count >= self._loop_threshold
    
    def _get_tool_timeout(self, tool_name: str) -> int:
        """Get adaptive timeout for a tool."""
        return TOOL_TIMEOUTS.get(tool_name, self.tool_timeout)
    
    async def run(self, user_input: str) -> AsyncGenerator[AgentEvent, None]:
        """
        Run agent loop with user input.
        Yields AgentEvent objects for CLI to render.
        """
        self.is_running = True
        
        # Add user message
        self.state.add_message("user", user_input)
        
        # Generate attack plan if this is a new objective
        if not self.state.plan.objective or self.state.plan.is_complete():
            self.state.plan = generate_plan(user_input, self.state.profile)
            yield AgentEvent("plan_generated", plan=self.state.plan.to_prompt_summary())
        
        try:
            for iteration in range(self.max_iterations):
                if not self.is_running:
                    yield AgentEvent("paused")
                    break
                
                # Smart context trimming
                needs_trim, tokens_before = should_trim_context(self.state.messages, threshold=25, max_tokens=80000)
                if needs_trim:
                    msgs_before = len(self.state.messages)
                    
                    self.state.messages = smart_trim_context(
                        self.state.messages,
                        max_tokens=80000,
                        recent_window=12,
                    )
                    
                    tokens_after = sum(estimate_tokens(msg.get("content", "")) for msg in self.state.messages)
                    logger.info(
                        f"Context trimmed: {msgs_before}→{len(self.state.messages)} msgs, "
                        f"~{tokens_before:,}→{tokens_after:,} tokens"
                    )
                
                # Build dynamic system prompt
                system_prompt = self._build_dynamic_system_prompt()
                
                # Call LLM
                text_buffer = ""
                tool_calls = []
                usage_stats = {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cache_read_tokens": 0,
                    "cache_creation_tokens": 0
                }
                
                try:
                    async for chunk in self.router.stream(
                        messages=self.state.messages,
                        tools=self.tools.get_schemas(),
                        system=system_prompt,
                        task_type=TaskType.TOOL_USE,
                    ):
                        if chunk.content:
                            text_buffer += chunk.content
                            yield AgentEvent("text", content=chunk.content)
                    
                        if chunk.tool_call:
                            tool_calls.append(chunk.tool_call)
                        
                        if chunk.input_tokens or chunk.cache_read_tokens:
                            usage_stats["input_tokens"] += chunk.input_tokens
                            usage_stats["output_tokens"] += chunk.output_tokens
                            usage_stats["cache_read_tokens"] += chunk.cache_read_tokens
                            usage_stats["cache_creation_tokens"] += chunk.cache_creation_tokens
                        
                        if chunk.done:
                            break
                
                except Exception as e:
                    error_msg = str(e)
                    logger.error(f"LLM streaming error: {error_msg}", exc_info=True)
                    
                    self.error_counter[error_msg] = self.error_counter.get(error_msg, 0) + 1
                    
                    if self.error_counter[error_msg] >= self.max_repeated_errors:
                        logger.error(f"Circuit breaker triggered: Same error {self.max_repeated_errors} times")
                        yield AgentEvent("error", message=f"STOPPING: Repeated LLM error detected.\n\nError: {error_msg}\n\nCheck your API keys and configuration.")
                        break
                    
                    yield AgentEvent("error", message=f"LLM API error: {error_msg}")
                    continue
                
                # Emit usage stats
                if usage_stats["input_tokens"] or usage_stats["cache_read_tokens"]:
                    yield AgentEvent("usage", **usage_stats)
                
                # Check for findings in text
                if text_buffer:
                    finding = self._extract_finding(text_buffer)
                    if finding:
                        self.state.add_finding(finding)
                        yield AgentEvent("finding", finding=finding)
                
                # Process tool calls
                if tool_calls:
                    if text_buffer:
                        content = [{"type": "text", "text": text_buffer}]
                        content.extend([
                            {"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]}
                            for tc in tool_calls
                        ])
                        self.state.add_message("assistant", content)
                    else:
                        self.state.add_message("assistant", [
                            {"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]}
                            for tc in tool_calls
                        ])
                    
                    # Execute tools
                    for tc in tool_calls:
                        # Loop detection
                        if self._detect_loop(tc["name"], tc["arguments"]):
                            loop_msg = (
                                f"LOOP DETECTED: '{tc['name']}' with same arguments was called recently. "
                                "Try a DIFFERENT approach, tool, or parameter."
                            )
                            yield AgentEvent("tool_start", tool_name=tc["name"], arguments=tc["arguments"])
                            yield AgentEvent("tool_end", tool_name=tc["name"], tool_result=loop_msg)
                            self.state.add_message("tool", {
                                "tool_call_id": tc["id"],
                                "content": loop_msg
                            })
                            continue
                        
                        yield AgentEvent("tool_start", tool_name=tc["name"], arguments=tc["arguments"])
                        
                        # ── CREATE_FINDING: intercept and register ──
                        if tc["name"] == "create_finding":
                            args = tc.get("arguments", {})
                            finding = Finding(
                                title=args.get("title", "Untitled"),
                                severity=args.get("severity", "info"),
                                description=args.get("description", ""),
                                evidence=args.get("evidence", ""),
                            )
                            self.state.add_finding(finding)
                            # Update TargetProfile with confirmed finding
                            if finding.severity in ("critical", "high", "medium"):
                                from numasec.target_profile import VulnHypothesis
                                hyp = VulnHypothesis(
                                    vuln_type=finding.title[:30],
                                    location=finding.evidence[:100] if finding.evidence else "",
                                    confidence=0.95,
                                    evidence=finding.description,
                                )
                                hyp.tested = True
                                hyp.confirmed = True
                                self.state.profile.hypotheses.append(hyp)
                            result = json.dumps({"registered": True, "title": finding.title, "severity": finding.severity})
                            yield AgentEvent("finding", finding=finding)
                            yield AgentEvent("tool_end", tool_name=tc["name"], tool_result=result)
                            self.state.add_message("tool", {
                                "tool_call_id": tc["id"],
                                "content": result
                            })
                            continue
                        
                        # Execute with adaptive timeout
                        timeout = self._get_tool_timeout(tc["name"])
                        try:
                            result = await asyncio.wait_for(
                                self.tools.call(tc["name"], tc["arguments"]),
                                timeout=timeout
                            )
                        except asyncio.TimeoutError:
                            logger.error(f"Tool timeout: {tc['name']} exceeded {timeout}s")
                            result = f"Error: Tool '{tc['name']}' timed out after {timeout} seconds. Try with smaller scope or different approach."
                        except Exception as e:
                            logger.error(f"Tool execution error: {tc['name']}: {e}", exc_info=True)
                            result = f"Error executing tool: {str(e)}"
                        
                        yield AgentEvent("tool_end", tool_name=tc["name"], tool_result=result)
                        
                        # ── EXTRACTOR: Update TargetProfile ──
                        try:
                            run_extractor(tc["name"], self.state.profile, result, tc.get("arguments", {}))
                        except Exception as e:
                            logger.warning(f"Extractor failed for {tc['name']}: {e}")
                        
                        # ── PLANNER: Mark step complete ──
                        if self.state.plan and self.state.plan.objective:
                            summary = result[:200] if isinstance(result, str) else str(result)[:200]
                            failed = self._is_failure(tc["name"], result)
                            self.state.plan.mark_step_complete(tc["name"], summary, is_failure=failed)
                        
                        # Build tool result content
                        tool_result_content = self._truncate_tool_result(tc["name"], result)
                        
                        if isinstance(tool_result_content, dict):
                            tool_result_content = json.dumps(tool_result_content, indent=2)
                        
                        # ── REFLECTION: Strategic insight ──
                        reflection_text = ""
                        try:
                            reflection_text = reflect_on_result(
                                tc["name"], tc["arguments"], result, self.state.profile
                            )
                        except Exception as e:
                            logger.warning(f"Reflection failed: {e}")
                        
                        # Check for failure and inject recovery guidance
                        if self._is_failure(tc["name"], result):
                            guidance = inject_recovery_guidance(tc["name"], result)
                            tool_result_content = f"{tool_result_content}\n\n{guidance}"
                            yield AgentEvent("reflection", tool_name=tc["name"], guidance=guidance)
                        else:
                            # Check browser fallback suggestion
                            should_retry, reason = should_retry_with_browser(
                                tc["name"], tc["arguments"], result
                            )
                            if should_retry:
                                suggestion = format_browser_suggestion(tc["name"], tc["arguments"], reason)
                                tool_result_content = f"{tool_result_content}\n\n{suggestion}"
                                yield AgentEvent("browser_suggestion", suggestion=suggestion)
                        
                        # Append reflection
                        if reflection_text:
                            tool_result_content = f"{tool_result_content}\n\n---\n**Reflection:**\n{reflection_text}"
                        
                        # Add tool message
                        self.state.add_message("tool", {
                            "tool_call_id": tc["id"],
                            "content": tool_result_content
                        })
                    
                    # Check if plan phase should advance
                    if self.state.plan and self.state.plan.objective:
                        current = self.state.plan.current_phase()
                        if current:
                            all_done = all(
                                s.status.value in ("complete", "skipped")
                                for s in current.steps
                            )
                            if all_done:
                                completed_name = current.name
                                self.state.plan.advance_phase()
                                # Find the new active phase for transition display
                                next_phase = self.state.plan.current_phase()
                                next_name = next_phase.name if next_phase else ""
                                yield AgentEvent("phase_complete", phase_name=completed_name, next_phase=next_name)
                    
                    continue
                
                # No tool calls - text-only response
                if text_buffer and not tool_calls:
                    self.state.add_message("assistant", text_buffer)
                    
                    # ── TERMINATION DETECTION ──
                    # The LLM is talking without calling tools.
                    # If it signals completion, stop immediately.
                    done_indicators = [
                        "i have completed",
                        "testing complete",
                        "no further",
                        "that's all",
                        "finished the",
                        "no more tests",
                        "assessment complete",
                        "pentest complete",
                        "security assessment is complete",
                        "all phases",
                        "assessment is done",
                        "testing is complete",
                        "completed the assessment",
                        "completed my assessment",
                        "here is a summary",
                        "here's a summary",
                        "in summary",
                        "to summarize",
                        "wrapping up",
                    ]
                    text_lower = text_buffer.lower()
                    is_done = any(indicator in text_lower for indicator in done_indicators)
                    
                    # Also terminate if the plan is fully complete
                    plan_done = self.state.plan and self.state.plan.is_complete()
                    
                    # Also terminate after 2+ consecutive text-only responses
                    # (the LLM is just talking, not acting)
                    consecutive_text = 0
                    for msg in reversed(self.state.messages):
                        if isinstance(msg.get("content"), str) and msg.get("role") == "assistant":
                            consecutive_text += 1
                        else:
                            break
                    
                    if is_done or plan_done or consecutive_text >= 3:
                        break
                    else:
                        continue
                
                # Safety: empty response
                if not text_buffer and not tool_calls:
                    yield AgentEvent("error", message="LLM returned empty response")
                    break
            
            yield AgentEvent("done")
        
        finally:
            self.is_running = False
    
    def _is_failure(self, tool_name: str, result: str) -> bool:
        """
        Context-aware failure detection.
        
        v3 improvements:
        - HTTP responses with status_code are NEVER marked as failure
          (even 404/403 are useful information)
        - Scan results with findings are NOT failures
        - Only genuine errors (timeouts, crashes, command not found)
        """
        result_lower = result.lower()
        
        # HTTP responses are informational, not failures
        if tool_name in ("http", "http_request"):
            http_errors = ["connection refused", "timeout", "dns resolution failed", "ssl error"]
            return any(err in result_lower for err in http_errors)
        
        # Browser tools — similar to HTTP
        if tool_name.startswith("browser_"):
            browser_errors = [
                "page crashed", "navigation failed", "timeout", "target closed",
                "all fill strategies failed", "all click strategies failed",
                "browser disconnected", "execution context was destroyed",
            ]
            return any(err in result_lower for err in browser_errors)
        
        # Scan tools — only fail on actual errors
        if tool_name in ("nmap", "nuclei", "sqlmap", "ffuf", "httpx"):
            scan_errors = ["command failed", "timed out", "not found", "permission denied"]
            return any(err in result_lower for err in scan_errors)
        
        # Generic tools
        failure_indicators = [
            "error executing",
            "command failed",
            "timed out",
            "command not found",
            "permission denied",
            "connection refused",
        ]
        return any(ind in result_lower for ind in failure_indicators)
    
    def _extract_finding(self, text: str) -> Finding | None:
        """
        Extract finding from agent text.
        Looks for pattern: [FINDING: SEVERITY] Title
        """
        match = re.search(r'\[FINDING:\s*(\w+)\]\s*(.+?)(?:\n|$)', text, re.IGNORECASE)
        if not match:
            return None
        
        severity = match.group(1).lower()
        title = match.group(2).strip()
        
        description = ""
        evidence = ""
        
        desc_match = re.search(r'\*\*Description\*\*:\s*(.+?)(?:\n\*\*|\n\n|$)', text, re.DOTALL)
        if desc_match:
            description = desc_match.group(1).strip()
        
        ev_match = re.search(r'\*\*Evidence\*\*:\s*(.+?)(?:\n\*\*|\n\n|$)', text, re.DOTALL)
        if ev_match:
            evidence = ev_match.group(1).strip()
        
        title = self._clean_rich_tags(title)
        description = self._clean_rich_tags(description)
        evidence = self._clean_rich_tags(evidence)
        
        # Also update TargetProfile with confirmed finding
        if severity in ("critical", "high", "medium"):
            from numasec.target_profile import VulnHypothesis
            hyp = VulnHypothesis(
                vuln_type=title.split(":")[0].strip() if ":" in title else title[:30],
                location=evidence[:100] if evidence else "",
                confidence=0.95,
                evidence=description or title,
            )
            hyp.tested = True
            hyp.confirmed = True
            self.state.profile.hypotheses.append(hyp)
        
        return Finding(
            title=title,
            severity=severity,
            description=description or title,
            evidence=evidence,
        )
    
    def _clean_rich_tags(self, text: str) -> str:
        """Remove Rich markup tags from text."""
        if not text:
            return text
        cleaned = re.sub(r'\[/?(?:[a-z_]+)?(?:\s*#?[0-9a-fA-F]{6})?\s*[^\]]*?\]', '', text)
        cleaned = re.sub(r'\*\*|\__', '', cleaned)
        return cleaned.strip()
    
    def _truncate_tool_result(self, tool_name: str, result: Any, max_chars: int = 10000) -> str:
        """Intelligently truncate tool results to prevent context overflow."""
        if isinstance(result, dict):
            result_str = json.dumps(result)
        elif isinstance(result, str):
            result_str = result
        else:
            result_str = str(result)
        
        if len(result_str) <= max_chars:
            return result_str
        
        logger.info(f"Truncating {tool_name} result: {len(result_str)} chars → {max_chars} chars")
        
        if tool_name == "http" or (isinstance(result, dict) and "status_code" in result):
            return self._truncate_http_result(result if isinstance(result, dict) else result_str, max_chars)
        elif tool_name in ("nmap", "nuclei", "sqlmap", "ffuf"):
            return self._truncate_scan_result(result_str, max_chars)
        else:
            head_size = max_chars // 2
            tail_size = max_chars - head_size - 100
            head = result_str[:head_size]
            tail = result_str[-tail_size:]
            return f"{head}\n\n... [TRUNCATED {len(result_str) - max_chars} characters] ...\n\n{tail}"
    
    def _truncate_http_result(self, result: Union[str, dict], max_chars: int) -> str:
        """Intelligently truncate HTTP tool results."""
        if isinstance(result, dict):
            data = result
        else:
            try:
                data = json.loads(result)
            except (json.JSONDecodeError, ValueError):
                head_size = max_chars // 2
                tail_size = max_chars - head_size - 100
                return f"{result[:head_size]}\n\n... [TRUNCATED] ...\n\n{result[-tail_size:]}"
        
        critical_fields = {
            "status_code": data.get("status_code"),
            "headers": data.get("headers", {}),
        }
        
        if "body" in data:
            body = data["body"]
            if len(body) > max_chars - 1000:
                body_max = max_chars - 1000
                head = body[:body_max // 2]
                tail = body[-(body_max // 2):]
                critical_fields["body"] = f"{head}\n... [TRUNCATED {len(body) - body_max} chars] ...\n{tail}"
            else:
                critical_fields["body"] = body
        
        if "response_text" in data:
            text = data["response_text"]
            if len(text) > max_chars - 1000:
                text_max = max_chars - 1000
                critical_fields["response_text"] = f"{text[:text_max]}... [TRUNCATED]"
            else:
                critical_fields["response_text"] = text
        
        return json.dumps(critical_fields, indent=2)
    
    def _truncate_scan_result(self, result: str, max_chars: int) -> str:
        """Truncate scan tool results."""
        if len(result) <= max_chars:
            return result
        
        head_size = int(max_chars * 0.3)
        tail_size = int(max_chars * 0.7)
        head = result[:head_size]
        tail = result[-tail_size:]
        truncated_bytes = len(result) - max_chars
        return f"{head}\n\n... [TRUNCATED {truncated_bytes} characters of scan output] ...\n\n{tail}"
    
    def pause(self):
        """Pause agent execution."""
        self.is_running = False
    
    def reset(self):
        """Reset agent state."""
        self.state.clear()
        self._recent_tool_hashes.clear()
        self.error_counter.clear()
    
    async def close(self):
        """Cleanup all resources — router, browser, HTTP client."""
        errors = []
        # Close tool resources (browser, HTTP client) first
        try:
            await self.tools.close()
        except Exception as e:
            errors.append(f"tools: {e}")
        # Close LLM router (HTTP connections to providers)
        try:
            await self.router.close()
        except Exception as e:
            errors.append(f"router: {e}")
        if errors:
            logger.debug(f"Cleanup warnings: {'; '.join(errors)}")


# ═══════════════════════════════════════════════════════════════════════════
# Convenience
# ═══════════════════════════════════════════════════════════════════════════


async def create_agent(**kwargs) -> Agent:
    """Create and initialize agent."""
    return Agent(**kwargs)
