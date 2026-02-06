"""
NumaSec v3 - LLM Router

Multi-provider LLM routing with streaming, fallback, task-based selection, and cost tracking.

Supports: DeepSeek, Claude, OpenAI, Ollama (local)
Task-based routing: SELECT best provider per task type.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import AsyncGenerator

import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger("numasec.router")


# ═══════════════════════════════════════════════════════════════════════════
# Security Helper
# ═══════════════════════════════════════════════════════════════════════════


def redact_api_keys(text: str) -> str:
    """Redact API keys from error messages for security."""
    import re
    patterns = [
        (r'sk-[a-zA-Z0-9]{20,}', 'sk-***REDACTED***'),
        (r'sk-ant-[a-zA-Z0-9-]{40,}', 'sk-ant-***REDACTED***'),
        (r'Bearer\s+[a-zA-Z0-9_-]+', 'Bearer ***REDACTED***'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


# ═══════════════════════════════════════════════════════════════════════════
# Types
# ═══════════════════════════════════════════════════════════════════════════


class Provider(str, Enum):
    """Supported LLM providers."""
    DEEPSEEK = "deepseek"
    CLAUDE = "claude"
    OPENAI = "openai"
    LOCAL = "local"  # Ollama


class TaskType(str, Enum):
    """Task types for smart routing."""
    PLANNING = "planning"       # Attack plan generation
    TOOL_USE = "tool_use"       # Standard tool-calling iteration
    ANALYSIS = "analysis"       # Deep analysis of results
    REFLECTION = "reflection"   # Self-evaluation
    REPORT = "report"           # Report writing


@dataclass
class StreamChunk:
    """Single streaming chunk."""
    content: str | None = None
    tool_call: dict | None = None  # {id, name, arguments}
    done: bool = False
    model: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0  # Anthropic prompt cache hits
    cache_creation_tokens: int = 0  # Anthropic cache creation


# ═══════════════════════════════════════════════════════════════════════════
# Provider Configs
# ═══════════════════════════════════════════════════════════════════════════


PROVIDERS = {
    Provider.DEEPSEEK: {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "cost_per_1k_in": 0.00014,
        "cost_per_1k_out": 0.00028,
    },
    Provider.CLAUDE: {
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-sonnet-4-20250514",
        "api_key_env": "ANTHROPIC_API_KEY",
        "cost_per_1k_in": 0.003,
        "cost_per_1k_out": 0.015,
    },
    Provider.OPENAI: {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
        "cost_per_1k_in": 0.00015,
        "cost_per_1k_out": 0.0006,
    },
    Provider.LOCAL: {
        "base_url": "http://localhost:11434/v1",
        "model": "qwen2.5-coder:3b-instruct",
        "api_key_env": "",
        "cost_per_1k_in": 0.0,
        "cost_per_1k_out": 0.0,
    },
}


# Task-based routing rules: task_type → preferred provider (if available)
TASK_ROUTING: dict[TaskType, list[Provider]] = {
    TaskType.PLANNING: [Provider.CLAUDE, Provider.DEEPSEEK],    # Claude excels at strategic reasoning
    TaskType.TOOL_USE: [Provider.DEEPSEEK, Provider.OPENAI],    # DeepSeek is cheapest for tool calls
    TaskType.ANALYSIS: [Provider.CLAUDE, Provider.DEEPSEEK],    # Claude for deep analysis
    TaskType.REFLECTION: [Provider.DEEPSEEK, Provider.LOCAL],   # Cheap reflection
    TaskType.REPORT: [Provider.CLAUDE, Provider.OPENAI],        # Claude for writing quality
}


# ═══════════════════════════════════════════════════════════════════════════
# Router
# ═══════════════════════════════════════════════════════════════════════════


class LLMRouter:
    """
    Multi-provider LLM router with streaming, fallback, and task-based routing.
    
    Usage:
        router = LLMRouter(primary=Provider.DEEPSEEK)
        
        # Streaming (auto-selects provider for task)
        async for chunk in router.stream(messages, tools, system, task_type=TaskType.TOOL_USE):
            print(chunk.content, end="", flush=True)
    """
    
    def __init__(
        self,
        primary: Provider = Provider.DEEPSEEK,
        fallback: Provider | None = Provider.CLAUDE,
    ):
        self.primary = primary
        # Only use fallback if API key is available
        if fallback and not self._get_api_key(fallback):
            logger.warning(f"No API key for {fallback.value}, disabling fallback")
            self.fallback = None
        else:
            self.fallback = fallback
        self._client: httpx.AsyncClient | None = None
        self.current_provider: Provider = primary  # Track current provider for cost tracking
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=180.0)
        return self._client
    
    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _get_api_key(self, provider: Provider) -> str | None:
        """Get API key for provider."""
        config = PROVIDERS[provider]
        env_var = config["api_key_env"]
        if not env_var:
            return None
        return os.environ.get(env_var)
    
    def select_provider(self, task_type: TaskType | None = None) -> Provider:
        """
        Select best provider for a task type.
        Falls back through preferred providers by availability.
        """
        if task_type and task_type in TASK_ROUTING:
            for provider in TASK_ROUTING[task_type]:
                if self._get_api_key(provider):
                    return provider
        
        # Default: use primary
        return self.primary
    
    async def stream(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        system: str | list[dict] | None = None,
        task_type: TaskType | None = None,
        provider_override: Provider | None = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """
        Stream LLM response with real-time tokens.
        
        Args:
            messages: Conversation messages
            tools: Tool schemas (OpenAI format)
            system: System prompt (string or Anthropic cacheable format)
            task_type: Optional task type for smart routing
            provider_override: Force a specific provider
        """
        # Select provider
        if provider_override:
            selected = provider_override
        elif task_type:
            selected = self.select_provider(task_type)
        else:
            selected = self.primary
        
        self.current_provider = selected
        
        providers = [selected]
        if self.fallback and self.fallback != selected:
            providers.append(self.fallback)
        elif self.primary != selected:
            providers.append(self.primary)
        
        for provider in providers:
            try:
                async for chunk in self._stream_provider(provider, messages, tools, system):
                    yield chunk
                return  # Success - don't try other providers
            except Exception as e:
                error_msg = redact_api_keys(str(e))
                
                # Special handling for 400 Bad Request - try without system prompt
                if "400" in error_msg and provider == self.primary and system:
                    logger.warning(f"Got 400 from {provider}, retrying without system prompt...")
                    try:
                        async for chunk in self._stream_provider(provider, messages, tools, None):
                            yield chunk
                        return  # Success with reduced payload
                    except Exception as e2:
                        logger.error(f"Retry also failed: {redact_api_keys(str(e2))}")
                
                logger.error(f"Streaming failed with {provider}: {error_msg}", exc_info=True)
                if provider == providers[-1]:
                    # Last provider failed - raise exception instead of yielding error text
                    # This prevents breaking message sequence (assistant → tool → assistant error text)
                    raise Exception(f"All providers failed. Last error: {error_msg}")
    
    async def _stream_provider(
        self,
        provider: Provider,
        messages: list[dict],
        tools: list[dict] | None,
        system: str | list[dict] | None,  # Support both formats
    ) -> AsyncGenerator[StreamChunk, None]:
        """Stream from specific provider."""
        if provider == Provider.CLAUDE:
            async for chunk in self._stream_anthropic(provider, messages, tools, system):
                yield chunk
        else:
            # OpenAI-compatible (DeepSeek, OpenAI, Ollama)
            async for chunk in self._stream_openai(provider, messages, tools, system):
                yield chunk
    
    async def _stream_openai(
        self,
        provider: Provider,
        messages: list[dict],
        tools: list[dict] | None,
        system: str | list[dict] | None,  # Support both formats
    ) -> AsyncGenerator[StreamChunk, None]:
        """Stream from OpenAI-compatible API."""
        client = await self._get_client()
        config = PROVIDERS[provider]
        
        # DEBUG: Log request details
        logger.debug(f"OpenAI stream request to {provider.value}")
        logger.debug(f"Messages count: {len(messages)}")
        logger.debug(f"System prompt type: {type(system).__name__}")
        logger.debug(f"Tools: {len(tools) if tools else 0}")
        
        headers = {"Content-Type": "application/json"}
        api_key = self._get_api_key(provider)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        # Extract system text (handle both string and Anthropic array format)
        system_text = None
        if system:
            if isinstance(system, list):
                # Anthropic cacheable format: [{"type": "text", "text": "...", "cache_control": {...}}]
                if system and len(system) > 0 and "text" in system[0]:
                    system_text = system[0]["text"]
                else:
                    logger.warning(f"Invalid system prompt array format: {system}")
            else:
                system_text = system
        
        # Build messages - DeepSeek doesn't support system role with tools
        # Inject system as first user message instead
        all_messages = []
        if system_text and not tools:
            # Only use system role when no tools
            all_messages.append({"role": "system", "content": system_text})
            all_messages.extend(messages)
        elif system_text and tools:
            # Merge system into first user message when tools present
            # Find first user message
            first_user_idx = next((i for i, m in enumerate(messages) if m.get("role") == "user"), 0)
            
            if first_user_idx < len(messages):
                # Inject system before first user message
                first_user_content = messages[first_user_idx].get("content", "")
                all_messages.extend(messages[:first_user_idx])
                all_messages.append({
                    "role": "user",
                    "content": f"[SYSTEM]: {system_text}\n\n[USER]: {first_user_content}"
                })
                all_messages.extend(messages[first_user_idx + 1:])
            else:
                # No user messages - just add system as user
                all_messages.extend(messages)
                all_messages.append({"role": "user", "content": f"[SYSTEM]: {system_text}"})
        else:
            all_messages.extend(messages)
        
        # Normalize messages for OpenAI format (convert Claude-style tool messages)
        normalized_messages = []
        for msg in all_messages:
            if msg["role"] == "tool":
                # Tool result - extract tool_call_id properly
                content_data = msg.get("content", {})
                
                if isinstance(content_data, dict):
                    # New format: {"tool_call_id": "xxx", "content": "..."}
                    tool_call_id = content_data.get("tool_call_id", "call_unknown")
                    content_str = content_data.get("content", "")
                    
                    # Ensure content is string
                    if isinstance(content_str, dict):
                        content_str = json.dumps(content_str)
                    
                    normalized_messages.append({
                        "role": "tool",
                        "content": str(content_str),
                        "tool_call_id": tool_call_id
                    })
                else:
                    # Old format - content is already a string
                    # Generate ID from hash (shouldn't happen now)
                    normalized_messages.append({
                        "role": "tool",
                        "content": str(content_data),
                        "tool_call_id": "call_" + str(abs(hash(str(content_data))))[:8]
                    })
            elif msg["role"] == "assistant" and isinstance(msg.get("content"), list):
                # Convert Claude-style content (can have text + tool_use)
                text_content = ""
                tool_calls_list = []
                
                for item in msg["content"]:
                    if isinstance(item, dict):
                        if item.get("type") == "text":
                            text_content += item.get("text", "")
                        elif item.get("type") == "tool_use":
                            tool_calls_list.append({
                                "id": item["id"],
                                "type": "function",
                                "function": {
                                    "name": item["name"],
                                    "arguments": json.dumps(item.get("input", {}))
                                }
                            })
                
                if tool_calls_list:
                    # Has tool calls - OpenAI format with optional content
                    msg_dict = {
                        "role": "assistant",
                        "tool_calls": tool_calls_list
                    }
                    # Only add content if there's text
                    if text_content:
                        msg_dict["content"] = text_content
                    normalized_messages.append(msg_dict)
                else:
                    # No tool calls, just text
                    normalized_messages.append({
                        "role": "assistant",
                        "content": text_content or ""
                    })
            else:
                normalized_messages.append(msg)
        
        payload = {
            "model": config["model"],
            "messages": normalized_messages,
            "stream": True,
            "stream_options": {"include_usage": True},  # Get token counts in final chunk
            "max_tokens": 4096,
        }
        
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"  # Force DeepSeek to consider tools
        
        # Log payload size (lightweight, always useful)
        logger.debug(f"Payload: {len(normalized_messages)} messages, {len(tools) if tools else 0} tools")
        
        # CRITICAL: Validate sequence BEFORE sending to catch issues early
        validation_errors = []
        for i, msg in enumerate(normalized_messages):
            if msg.get("role") == "assistant" and "tool_calls" in msg:
                expected_ids = {tc["id"] for tc in msg["tool_calls"]}
                # Count following tool messages
                actual_ids = set()
                j = i + 1
                while j < len(normalized_messages) and normalized_messages[j].get("role") == "tool":
                    actual_ids.add(normalized_messages[j].get("tool_call_id"))
                    j += 1
                
                missing = expected_ids - actual_ids
                if missing:
                    validation_errors.append(f"Position {i+1}: assistant expects {len(expected_ids)} tools, got {len(actual_ids)}. Missing: {missing}")
        
        if validation_errors:
            logger.error(f"MESSAGE SEQUENCE VALIDATION FAILED:")
            for err in validation_errors:
                logger.error(f"   {err}")
            logger.error(f"This WILL cause 400 Bad Request from DeepSeek!")
            # Log the problematic messages
            logger.error(f"Dumping last 10 messages for debugging:")
            for i, msg in enumerate(normalized_messages[-10:], start=len(normalized_messages)-9):
                logger.error(f"  {i}. {msg.get('role')}: {str(msg)[:200]}...")
        else:
            logger.debug(f"Message sequence validation passed")
        
        # Tool call accumulator
        tool_calls_buffer = {}
        
        async with client.stream(
            "POST",
            f"{config['base_url']}/chat/completions",
            headers=headers,
            json=payload,
        ) as response:
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                # Log error details for debugging (with API key redaction)
                error_body = await response.aread()
                error_msg = redact_api_keys(error_body.decode())
                logger.error(f"Provider {provider} HTTP {e.response.status_code} error")
                logger.error(f"Response body: {error_msg}")
                logger.error(f"Request payload sample (last message): {json.dumps(normalized_messages[-1] if normalized_messages else {}, indent=2)[:500]}")
                raise
            
            async for line in response.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                
                if line == "data: [DONE]":
                    continue
                
                try:
                    data = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                
                # Usage stats (final chunk with stream_options.include_usage)
                usage = data.get("usage")
                if usage:
                    yield StreamChunk(
                        model=config["model"],
                        input_tokens=usage.get("prompt_tokens", 0),
                        output_tokens=usage.get("completion_tokens", 0),
                    )
                
                choice = data.get("choices", [{}])[0]
                delta = choice.get("delta", {})
                finish = choice.get("finish_reason")
                
                # Content
                if delta.get("content"):
                    yield StreamChunk(content=delta["content"], model=config["model"])
                
                # Tool calls (accumulate)
                if delta.get("tool_calls"):
                    for tc in delta["tool_calls"]:
                        idx = tc.get("index", 0)
                        if idx not in tool_calls_buffer:
                            tool_calls_buffer[idx] = {"id": "", "name": "", "arguments": ""}
                        if tc.get("id"):
                            tool_calls_buffer[idx]["id"] = tc["id"]
                        if tc.get("function", {}).get("name"):
                            tool_calls_buffer[idx]["name"] = tc["function"]["name"]
                        if tc.get("function", {}).get("arguments"):
                            tool_calls_buffer[idx]["arguments"] += tc["function"]["arguments"]
                
                # Done
                if finish:
                    # Yield complete tool calls
                    for tc in tool_calls_buffer.values():
                        try:
                            args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                        except (json.JSONDecodeError, ValueError) as e:
                            logger.error(f"Failed to parse tool arguments for {tc.get('name')}: {e}")
                            logger.error(f"Raw arguments string: {tc.get('arguments')}")
                            args = {}
                        
                        # DEBUG: Log parsed tool call
                        logger.debug(f"Tool call: {tc.get('name')} with {len(args)} args")
                        
                        yield StreamChunk(
                            tool_call={"id": tc["id"], "name": tc["name"], "arguments": args},
                            model=config["model"]
                        )
                    yield StreamChunk(done=True, model=config["model"])
                    return
    
    async def _stream_anthropic(
        self,
        provider: Provider,
        messages: list[dict],
        tools: list[dict] | None,
        system: str | list[dict] | None,  # Support both formats
    ) -> AsyncGenerator[StreamChunk, None]:
        """Stream from Anthropic Claude."""
        client = await self._get_client()
        config = PROVIDERS[provider]
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._get_api_key(provider) or "",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "prompt-caching-2024-07-31",  # Enable prompt caching
        }
        
        payload = {
            "model": config["model"],
            "max_tokens": 4096,
            "messages": messages,
            "stream": True,
        }
        
        # Prompt caching: Mark system prompt as cacheable
        # Saves 90% on repeated system prompt tokens!
        if system:
            if isinstance(system, list):
                # Already in cacheable format
                payload["system"] = system
            else:
                # Convert string to cacheable format
                payload["system"] = [
                    {
                        "type": "text",
                        "text": system,
                        "cache_control": {"type": "ephemeral"}  # Cache for 5 minutes
                    }
                ]
        
        if tools:
            payload["tools"] = self._convert_tools_anthropic(tools)
        
        current_tool = None
        
        async with client.stream(
            "POST",
            f"{config['base_url']}/messages",
            headers=headers,
            json=payload,
        ) as response:
            response.raise_for_status()
            
            async for line in response.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                
                try:
                    data = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                
                event_type = data.get("type")
                
                if event_type == "content_block_start":
                    block = data.get("content_block", {})
                    if block.get("type") == "tool_use":
                        current_tool = {
                            "id": block.get("id", ""),
                            "name": block.get("name", ""),
                            "arguments": ""
                        }
                
                elif event_type == "content_block_delta":
                    delta = data.get("delta", {})
                    if delta.get("type") == "text_delta":
                        yield StreamChunk(content=delta.get("text"), model=config["model"])
                    elif delta.get("type") == "input_json_delta" and current_tool:
                        current_tool["arguments"] += delta.get("partial_json", "")
                
                elif event_type == "content_block_stop":
                    if current_tool:
                        try:
                            args = json.loads(current_tool["arguments"]) if current_tool["arguments"] else {}
                        except (json.JSONDecodeError, ValueError) as e:
                            logger.warning(f"Failed to parse tool arguments: {e}")
                            args = {}
                        yield StreamChunk(
                            tool_call={"id": current_tool["id"], "name": current_tool["name"], "arguments": args},
                            model=config["model"]
                        )
                        current_tool = None
                
                elif event_type == "message_delta":
                    # Contains usage stats including cache hits!
                    usage = data.get("usage", {})
                    if usage:
                        yield StreamChunk(
                            model=config["model"],
                            input_tokens=usage.get("input_tokens", 0),
                            output_tokens=usage.get("output_tokens", 0),
                            cache_read_tokens=usage.get("cache_read_input_tokens", 0),
                            cache_creation_tokens=usage.get("cache_creation_input_tokens", 0)
                        )
                
                elif event_type == "message_stop":
                    yield StreamChunk(done=True, model=config["model"])
                    return
    
    def _convert_tools_anthropic(self, tools: list[dict]) -> list[dict]:
        """Convert OpenAI tool format to Anthropic format."""
        return [
            {
                "name": t["function"]["name"],
                "description": t["function"].get("description", ""),
                "input_schema": t["function"].get("parameters", {}),
            }
            for t in tools
        ]
