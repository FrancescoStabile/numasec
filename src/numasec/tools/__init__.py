"""
NumaSec v3 - Tools

Core + Recon + Exploit tools registry.
Direct Python functions, no MCP overhead.
SOTA: Few-shot examples integrated for +25% accuracy.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("numasec.tools")

# ── Persistent HTTP client (connection pooling + keepalive) ──
_http_client: httpx.AsyncClient | None = None


async def _get_http_client(timeout: int = 10) -> httpx.AsyncClient:
    """Get or create the persistent HTTP client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
                keepalive_expiry=30,
            ),
        )
    return _http_client


# Import recon tools
from numasec.tools.recon import nmap, httpx_probe, subfinder, ffuf, TOOL_SCHEMAS as RECON_SCHEMAS

# Import exploit tools
from numasec.tools.exploit import nuclei, sqlmap, run_exploit, TOOL_SCHEMAS as EXPLOIT_SCHEMAS

# Import browser tools
from numasec.tools.browser import (
    browser_navigate,
    browser_fill,
    browser_click,
    browser_screenshot,
    browser_login,
    browser_get_cookies,
    browser_set_cookies,
    browser_clear_session,
    TOOL_SCHEMAS as BROWSER_SCHEMAS
)

# Import few-shot examples (SOTA)
from numasec.few_shot_examples import get_few_shot_examples


# ═══════════════════════════════════════════════════════════════════════════
# Tool Registry
# ═══════════════════════════════════════════════════════════════════════════


class ToolRegistry:
    """Direct tool registry with scope checking. No MCP protocol."""
    
    def __init__(self, allowed_targets: list[str] | None = None):
        self.tools: dict[str, dict] = {}
        self.allowed_targets = allowed_targets or []
        self._logger = logging.getLogger("numasec.tools")
    
    def register(self, name: str, func: callable, schema: dict):
        """Register a tool."""
        self.tools[name] = {"func": func, "schema": schema}
    
    def set_scope(self, targets: list[str]):
        """Set allowed targets for scope checking."""
        self.allowed_targets = targets
    
    def _check_scope(self, name: str, args: dict) -> str | None:
        """
        Check if tool arguments are within allowed scope.
        Returns error message if out of scope, None if OK.
        
        Only checks network-targeting tools.
        """
        if not self.allowed_targets:
            return None  # No scope set = allow everything
        
        # Tools that target network resources
        target_arg_map = {
            "nmap": "target",
            "httpx": "url",
            "subfinder": "domain",
            "nuclei": "url",
            "sqlmap": "url",
            "http": "url",
            "ffuf": "url",
            "browser_navigate": "url",
            "browser_fill": "url",
            "browser_click": "url",
            "browser_login": "url",
        }
        
        target_key = target_arg_map.get(name)
        if not target_key:
            return None  # Non-network tool
        
        target_value = args.get(target_key, "")
        if not target_value:
            return None
        
        # Check if target matches any allowed target
        target_lower = target_value.lower()
        for allowed in self.allowed_targets:
            allowed_lower = allowed.lower()
            if allowed_lower in target_lower or target_lower in allowed_lower:
                return None
        
        return f"SCOPE ERROR: {target_value} is not in allowed targets: {self.allowed_targets}. Adjust your target or ask user for permission."
    
    async def call(self, name: str, args: dict) -> str:
        """Call a tool directly."""
        tool = self.tools.get(name)
        if not tool:
            return json.dumps({"error": f"Unknown tool: {name}"})
        
        # Scope check
        scope_error = self._check_scope(name, args)
        if scope_error:
            self._logger.warning(f"Scope violation: {name} → {args}")
            return json.dumps({"error": scope_error})
        
        try:
            func = tool["func"]
            self._logger.debug(f"Tool call: {name} with args: {args}")
            
            if asyncio.iscoroutinefunction(func):
                result = await func(**args)
            else:
                result = func(**args)
            
            # Return as string (JSON if dict)
            if isinstance(result, str):
                return result
            return json.dumps(result, indent=2)
        except Exception as e:
            self._logger.error(f"Tool execution error for {name}: {e}", exc_info=True)
            return json.dumps({"error": str(e)})
    
    def get_schemas(self) -> list[dict]:
        """Get all tool schemas for LLM with few-shot examples."""
        schemas = []
        for name, tool in self.tools.items():
            schema = {
                "type": "function",
                "function": {
                    "name": name,
                    **tool["schema"]
                }
            }
            
            # Add few-shot examples (SOTA)
            examples = get_few_shot_examples(name)
            if examples:
                # Extend description with examples
                desc = schema["function"]["description"]
                desc += "\n\n**Examples:**"
                for i, ex in enumerate(examples, 1):
                    outcome_emoji = "+" if ex.is_good else "-"
                    desc += f"\n{outcome_emoji} Example {i}: {ex.scenario}"
                    if ex.thinking:
                        desc += f"\n   Thinking: {ex.thinking[:100]}..."
                    desc += f"\n   Expected: {ex.expected_result[:80]}..."
                schema["function"]["description"] = desc
            
            schemas.append(schema)
        
        return schemas


# ═══════════════════════════════════════════════════════════════════════════
# Tools
# ═══════════════════════════════════════════════════════════════════════════


async def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    data: dict | str | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Make HTTP request.
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE, etc)
        headers: HTTP headers
        data: Request body (dict for JSON, str for raw)
        timeout: Request timeout in seconds
    
    Returns:
        dict with status, headers, body
    """
    client = await _get_http_client(timeout=timeout)
    try:
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            json=data if isinstance(data, dict) else None,
            content=data if isinstance(data, str) else None,
            timeout=timeout,
        )
        
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "url": str(response.url),
        }
    except Exception as e:
        return {"error": str(e)}


def read_file(path: str) -> dict[str, Any]:
    """
    Read file contents.
    
    Args:
        path: File path to read
    
    Returns:
        dict with content or error
        
    Security: Only allows reading from:
    - Current working directory
    - ~/.numasec directory
    """
    try:
        file_path = Path(path).resolve()
        
        # Check if path is allowed
        allowed_dirs = [
            Path.cwd(),
            Path.home() / ".numasec",
        ]
        
        # Verify path is within allowed directories
        is_allowed = any(
            file_path.is_relative_to(allowed_dir) 
            for allowed_dir in allowed_dirs
        )
        
        if not is_allowed:
            return {
                "error": f"Access denied: {path} is outside allowed directories. "
                         f"Allowed: current directory, ~/.numasec"
            }
        
        content = file_path.read_text()
        return {"content": content, "path": str(file_path)}
    except Exception as e:
        return {"error": str(e)}


def write_file(path: str, content: str) -> dict[str, Any]:
    """
    Write content to file.
    
    Args:
        path: File path to write
        content: Content to write
    
    Returns:
        dict with success status
        
    Security: Only allows writing to:
    - Current working directory
    - ~/.numasec directory
    """
    try:
        file_path = Path(path).resolve()
        
        # Check if path is allowed
        allowed_dirs = [
            Path.cwd(),
            Path.home() / ".numasec",
        ]
        
        # Verify path is within allowed directories
        is_allowed = any(
            file_path.is_relative_to(allowed_dir) 
            for allowed_dir in allowed_dirs
        )
        
        if not is_allowed:
            return {"error": f"Access denied: {path} is outside allowed directories"}
        
        # Create parent directory if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")
        return {"success": True, "path": str(file_path)}
    except Exception as e:
        return {"error": str(e)}


async def run_command(command: str, timeout: int = 30) -> dict[str, Any]:
    """
    Execute shell command.
    
    Args:
        command: Shell command to run
        timeout: Timeout in seconds
    
    Returns:
        dict with stdout, stderr, returncode
        
    Security Warning: This uses shell execution which can be dangerous.
    Only use in controlled environments. All commands are logged.
    """
    # Log command for audit trail
    logger.warning(f"Executing shell command: {command}")
    
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )
        
        return {
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
            "returncode": proc.returncode,
        }
    except asyncio.TimeoutError:
        logger.error(f"Command timed out after {timeout}s: {command}")
        return {"error": f"Command timed out after {timeout}s"}
    except Exception as e:
        logger.error(f"Command execution failed: {e}", exc_info=True)
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════
# Tool Schemas (OpenAI format)
# ═══════════════════════════════════════════════════════════════════════════


TOOL_SCHEMAS = {
    "http": {
        "description": "Make HTTP request to a URL. Use for testing web endpoints.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "description": "HTTP method (GET, POST, etc)", "default": "GET"},
                "headers": {"type": "object", "description": "HTTP headers"},
                "data": {"description": "Request body"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 10},
            },
            "required": ["url"],
        },
    },
    "read_file": {
        "description": "Read file contents from disk.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    },
    "write_file": {
        "description": "Write content to a file.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["path", "content"],
        },
    },
    "run_command": {
        "description": "Execute shell command. Use carefully.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
            },
            "required": ["command"],
        },
    },
    "create_finding": {
        "description": (
            "Register a security finding. MUST be called every time you discover "
            "a vulnerability, misconfiguration, or information disclosure. "
            "If in doubt, register it — it is far better to over-report than to miss something. "
            "Severity guide: critical = RCE/auth bypass/data breach, high = SQLi/XSS/SSRF, "
            "medium = info disclosure/misconfig, low = missing headers/minor issues, "
            "info = version disclosure/technology detected."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short finding title, e.g. 'SQL Injection in /login'"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Finding severity level",
                },
                "description": {"type": "string", "description": "Detailed description of the vulnerability"},
                "evidence": {"type": "string", "description": "Proof: HTTP response, command output, screenshot path, etc."},
            },
            "required": ["title", "severity", "description"],
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# create_finding stub — actual logic lives in agent.py, this is a
# passthrough so the tool registry can call *something*.  The agent
# intercepts create_finding calls before they reach the registry.
# ═══════════════════════════════════════════════════════════════════════════


def _create_finding_stub(
    title: str,
    severity: str,
    description: str,
    evidence: str = "",
) -> dict[str, Any]:
    """Stub — intercepted by Agent before execution."""
    return {"registered": True, "title": title, "severity": severity}


# ═══════════════════════════════════════════════════════════════════════════
# Create Default Registry
# ═══════════════════════════════════════════════════════════════════════════


def create_tool_registry() -> ToolRegistry:
    """Create registry with all tools."""
    registry = ToolRegistry()
    
    # Core tools
    registry.register("http", http_request, TOOL_SCHEMAS["http"])
    registry.register("read_file", read_file, TOOL_SCHEMAS["read_file"])
    registry.register("write_file", write_file, TOOL_SCHEMAS["write_file"])
    registry.register("run_command", run_command, TOOL_SCHEMAS["run_command"])
    registry.register("create_finding", _create_finding_stub, TOOL_SCHEMAS["create_finding"])
    
    # Recon tools
    registry.register("nmap", nmap, RECON_SCHEMAS["nmap"])
    registry.register("httpx", httpx_probe, RECON_SCHEMAS["httpx"])
    registry.register("subfinder", subfinder, RECON_SCHEMAS["subfinder"])
    registry.register("ffuf", ffuf, RECON_SCHEMAS["ffuf"])
    
    # Exploit tools
    registry.register("nuclei", nuclei, EXPLOIT_SCHEMAS["nuclei"])
    registry.register("sqlmap", sqlmap, EXPLOIT_SCHEMAS["sqlmap"])
    registry.register("run_exploit", run_exploit, EXPLOIT_SCHEMAS["run_exploit"])
    
    # Browser tools
    registry.register("browser_navigate", browser_navigate, BROWSER_SCHEMAS["browser_navigate"])
    registry.register("browser_fill", browser_fill, BROWSER_SCHEMAS["browser_fill"])
    registry.register("browser_click", browser_click, BROWSER_SCHEMAS["browser_click"])
    registry.register("browser_screenshot", browser_screenshot, BROWSER_SCHEMAS["browser_screenshot"])
    registry.register("browser_login", browser_login, BROWSER_SCHEMAS["browser_login"])
    registry.register("browser_get_cookies", browser_get_cookies, BROWSER_SCHEMAS["browser_get_cookies"])
    registry.register("browser_set_cookies", browser_set_cookies, BROWSER_SCHEMAS["browser_set_cookies"])
    registry.register("browser_clear_session", browser_clear_session, BROWSER_SCHEMAS["browser_clear_session"])
    
    return registry
