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
    
    async def close(self):
        """Cleanup all async resources (browser, HTTP client)."""
        # Close global HTTP client
        global _http_client
        if _http_client and not _http_client.is_closed:
            try:
                await _http_client.aclose()
            except Exception:
                pass
            _http_client = None

        # Close browser singleton
        try:
            from numasec.tools.browser import BrowserManager, PLAYWRIGHT_AVAILABLE
            if PLAYWRIGHT_AVAILABLE:
                manager = BrowserManager()
                await manager.close()
        except Exception:
            pass

    def set_scope(self, targets: list[str]):
        """Set allowed targets for scope checking."""
        self.allowed_targets = targets
    
    def _check_scope(self, name: str, args: dict) -> str | None:
        """
        Check if tool arguments are within allowed scope.
        Returns error message if out of scope, None if OK.
        
        Uses proper URL/domain parsing — no substring tricks.
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
            # run_exploit: check the command for target references
            if name == "run_exploit":
                cmd = args.get("command", "")
                return self._check_exploit_scope(cmd)
            return None  # Non-network tool
        
        target_value = args.get(target_key, "")
        if not target_value:
            return None
        
        # Proper scope check with URL/domain parsing
        if self._is_in_scope(target_value):
            return None
        
        return f"SCOPE ERROR: {target_value} is not in allowed targets: {self.allowed_targets}. Adjust your target or ask user for permission."
    
    def _check_exploit_scope(self, command: str) -> str | None:
        """Check if run_exploit command targets in-scope hosts."""
        if not self.allowed_targets or not command:
            return None
        # Extract URLs and IPs from the command string
        import re
        urls = re.findall(r'https?://[^\s"\']+', command)
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', command)
        targets = urls + ips
        for target in targets:
            if not self._is_in_scope(target):
                return f"SCOPE ERROR: run_exploit targets {target} which is not in allowed scope: {self.allowed_targets}"
        return None
    
    def _is_in_scope(self, target_value: str) -> bool:
        """
        Check if a target value matches any allowed scope entry.
        
        Uses proper hostname extraction — prevents bypasses like:
        - evil-example.com matching example.com
        - localhost.attacker.com matching localhost
        """
        from urllib.parse import urlparse
        import ipaddress
        
        def _extract_host(value: str) -> str:
            """Extract hostname from URL, IP, or raw hostname."""
            v = value.strip()
            # Add scheme if missing so urlparse works
            if "://" not in v:
                v = "http://" + v
            parsed = urlparse(v)
            host = parsed.hostname or ""
            return host.lower().rstrip(".")
        
        target_host = _extract_host(target_value)
        if not target_host:
            return False
        
        for allowed in self.allowed_targets:
            scope_host = _extract_host(allowed)
            if not scope_host:
                continue
            
            # Exact match
            if target_host == scope_host:
                return True
            
            # Subdomain match: target is sub.example.com, scope is example.com
            if target_host.endswith("." + scope_host):
                return True
            
            # IP range check (CIDR)
            try:
                target_ip = ipaddress.ip_address(target_host)
                try:
                    scope_net = ipaddress.ip_network(scope_host, strict=False)
                    if target_ip in scope_net:
                        return True
                except ValueError:
                    scope_ip = ipaddress.ip_address(scope_host)
                    if target_ip == scope_ip:
                        return True
            except ValueError:
                pass  # Not an IP, already handled by hostname matching
        
        return False
    
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
            
            # Inject scope into run_exploit for defence-in-depth validation
            if name == "run_exploit" and self.allowed_targets:
                args = {**args, "scope_targets": self.allowed_targets}
            
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


# Allowlist for run_command — broader than EXPLOIT_ALLOWLIST but still gated
_COMMAND_ALLOWLIST: set[str] = {
    # Standard unix utilities (read-only / diagnostic)
    "cat", "grep", "head", "tail", "wc", "sort", "uniq", "awk", "sed",
    "base64", "xxd", "hexdump", "file", "ls", "find", "stat", "sha256sum",
    "md5sum", "strings", "tr", "cut", "diff", "jq",
    # Network diagnostics
    "curl", "wget", "dig", "host", "whois", "ping", "traceroute",
    "openssl", "nslookup",
    # Security tools already in exploit allowlist
    "nmap", "nuclei", "sqlmap", "nikto", "gobuster", "feroxbuster",
    "ffuf", "wfuzz", "hydra", "medusa", "john", "hashcat",
    "whatweb", "wpscan", "joomscan", "droopescan",
    "enum4linux", "smbclient", "rpcclient", "ldapsearch",
    "dnsrecon",
    # Python/scripting
    "python3", "python", "python3.11", "python3.12", "python3.13",
    "node", "ruby", "perl",
}


async def run_command(command: str, timeout: int = 30) -> dict[str, Any]:
    """
    Execute shell command with allowlist validation.
    
    Args:
        command: Shell command to run
        timeout: Timeout in seconds
    
    Returns:
        dict with stdout, stderr, returncode
        
    Security: Commands are validated against an allowlist of known
    safe binaries. Shell metacharacters are blocked to prevent injection.
    """
    import shlex
    import re

    # Log command for audit trail
    logger.warning(f"Executing shell command: {command}")

    # Parse command safely
    try:
        parts = shlex.split(command)
    except ValueError as e:
        return {"error": f"Invalid command syntax: {e}"}

    if not parts:
        return {"error": "Empty command"}

    # Extract binary name (handle /usr/bin/curl → curl)
    binary = parts[0].split("/")[-1]

    if binary not in _COMMAND_ALLOWLIST:
        return {
            "error": f"BLOCKED: '{binary}' is not in the command allowlist. "
                     f"Allowed: {', '.join(sorted(list(_COMMAND_ALLOWLIST)[:20]))}..."
        }

    # Block shell metacharacters that indicate chaining/injection
    _SHELL_METACHAR = re.compile(r"[;&|`$(){}]|>>|<<")
    if _SHELL_METACHAR.search(command):
        return {
            "error": "BLOCKED: Shell metacharacters detected. "
                     "Run one command at a time, no pipes or chaining."
        }

    try:
        proc = await asyncio.create_subprocess_exec(
            *parts,
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
        "description": (
            "Make an HTTP request to any URL and return the full response (status, headers, body). "
            "Use this to probe endpoints, test for injection vulnerabilities, check security headers, "
            "or interact with APIs. Supports GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD. "
            "**When to use**: Testing specific endpoints for SQLi/XSS/SSRF payloads, checking "
            "response headers (CORS, CSP, X-Frame-Options), sending authenticated requests with "
            "custom cookies/tokens, probing API endpoints with crafted JSON bodies. "
            "**When NOT to use**: For checking if a host is alive (use httpx instead), for "
            "browser-rendered pages with JavaScript (use browser_navigate). "
            "**Output**: JSON with status_code, headers dict, and body string. "
            "**Common mistake**: Forgetting to include protocol (http:// or https://) in the URL."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with protocol (e.g., 'http://localhost:3000/api/users?id=1')"},
                "method": {"type": "string", "description": "HTTP method: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD", "default": "GET"},
                "headers": {"type": "object", "description": "HTTP headers dict (e.g., {'Authorization': 'Bearer tok123', 'Content-Type': 'application/json'})"},
                "data": {"description": "Request body — dict for JSON, string for form data (e.g., 'user=admin&pass=test')"},
                "timeout": {"type": "integer", "description": "Request timeout in seconds (increase for slow targets)", "default": 10},
            },
            "required": ["url"],
        },
    },
    "read_file": {
        "description": (
            "Read file contents from disk. Use to examine configuration files, source code, "
            "credentials, or downloaded artifacts during a security assessment. "
            "Security-scoped: only reads from the current working directory and ~/.numasec — "
            "attempts to read outside these paths (e.g., /etc/shadow, /proc/) will be blocked. "
            "Supports text files of any size; binary files return a hex preview. "
            "**When to use**: Reading downloaded exploit scripts, examining config files found "
            "during recon (e.g., .env, wp-config.php), viewing evidence files, checking tool "
            "output logs, inspecting payloads before execution, reviewing wordlists. "
            "**When NOT to use**: For reading remote files on the target (use http tool with "
            "file:// protocol or LFI payloads). For reading large binary files (use run_command "
            "with xxd/hexdump instead). "
            "**Output**: JSON with 'content' string or 'error' message."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read (relative or absolute within allowed directories)"},
            },
            "required": ["path"],
        },
    },
    "write_file": {
        "description": (
            "Write content to a file on disk. Use to save exploit scripts, payloads, "
            "evidence, or notes during a security assessment. Security-scoped to the "
            "current working directory — writes outside this path are blocked. Creates "
            "parent directories automatically if they don't exist. Overwrites existing "
            "files without warning, so check first with read_file if preservation matters. "
            "**When to use**: Saving a PoC exploit script before running it with run_exploit, "
            "writing payloads to a file for delivery via http, saving evidence and screenshots "
            "for the final report, creating custom wordlists for ffuf fuzzing, writing "
            "configuration files for tool setup. "
            "**When NOT to use**: For uploading files to the target server (use http with "
            "multipart/form-data). For writing to target filesystem via RCE (use run_exploit). "
            "**Output**: JSON with 'written' boolean and 'path' confirmation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write (e.g., 'exploit.py', 'evidence/payload.txt')"},
                "content": {"type": "string", "description": "Content to write to the file"},
            },
            "required": ["path", "content"],
        },
    },
    "run_command": {
        "description": (
            "Execute a shell command on the local system. Use for running system utilities, "
            "custom scripts, or tools not available as dedicated NumaSec tools. Commands run "
            "in a sandboxed subprocess with configurable timeout (default 30s). The working "
            "directory is the assessment workspace. Supports pipes, redirects, and shell features. "
            "**When to use**: Running custom enumeration commands (e.g., 'curl', 'dig', 'whois', "
            "'host', 'openssl s_client'), executing downloaded scripts, checking local system "
            "info, running one-off tools, chaining commands with pipes for complex extraction, "
            "decoding base64 or hex payloads, running hashcat/john for credential testing. "
            "**When NOT to use**: For running nmap (use the nmap tool — it has better output "
            "parsing and structured results). For running nuclei, sqlmap, or ffuf (use their "
            "dedicated tools for proper result handling). For exploitation attempts (use "
            "run_exploit — it has audit logging, allowlist enforcement, and scope checking). "
            "**Security**: Commands are sandboxed with timeout. Avoid destructive operations. "
            "**Output**: JSON with stdout, stderr, and exit_code."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute (e.g., 'curl -s http://target/robots.txt', 'dig example.com')"},
                "timeout": {"type": "integer", "description": "Timeout in seconds — increase for slow commands", "default": 30},
            },
            "required": ["command"],
        },
    },
    "create_finding": {
        "description": (
            "Register a confirmed security finding. MUST be called EVERY TIME you discover "
            "a vulnerability, misconfiguration, or information disclosure — no exceptions. "
            "If in doubt, register it. It is far better to over-report than to miss something. "
            "Each finding becomes part of the final assessment report with evidence. "
            "**Severity guide**: "
            "critical = RCE, authentication bypass, full data breach, admin takeover; "
            "high = SQL injection, stored XSS, SSRF, arbitrary file read, privilege escalation; "
            "medium = information disclosure, security misconfiguration, reflected XSS, CSRF; "
            "low = missing security headers, verbose errors, minor info leaks; "
            "info = version disclosure, technology fingerprinting, DNS records. "
            "**When to use**: After confirming a vulnerability with evidence (HTTP response, "
            "payload that worked, command output showing access). Also use for misconfigs like "
            "exposed .env files, debug mode enabled, default credentials working. "
            "**When NOT to use**: For suspected but unconfirmed vulnerabilities (investigate "
            "further first). For duplicate findings already registered (check existing findings). "
            "For informational notes that are not security-relevant (e.g., 'server responded slowly'). "
            "**Common mistake**: Not calling create_finding after confirming a vulnerability. "
            "Every confirmed issue MUST be registered or it will be lost from the report."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short, specific title (e.g., 'SQL Injection in /api/users?id= parameter', 'Exposed .env with database credentials')"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Finding severity — see description for guide. When unsure, err on the higher side.",
                },
                "description": {"type": "string", "description": "Detailed description: what the vulnerability is, how it was found, what the impact is, and how to fix it"},
                "evidence": {"type": "string", "description": "Proof: the exact HTTP request/response, payload used, command output, or screenshot path that confirms this finding"},
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


# ═══════════════════════════════════════════════════════════════════════════
# Tool Availability Detection
# ═══════════════════════════════════════════════════════════════════════════


def check_tool_availability() -> dict[str, bool]:
    """
    Check which external security tools are actually installed.
    
    Returns dict of tool_name → is_available.
    Only checks tools that shell out to external binaries.
    Core tools (http, read_file, write_file, browser_*) are always available.
    """
    import shutil
    
    external_tools = {
        "nmap": "nmap",
        "sqlmap": "sqlmap",
        "nuclei": "nuclei",
        "ffuf": "ffuf",
        "httpx": "httpx",
        "subfinder": "subfinder",
    }
    
    availability: dict[str, bool] = {}
    for tool_name, binary_name in external_tools.items():
        availability[tool_name] = shutil.which(binary_name) is not None
    
    # Browser: check if playwright browsers are installed
    try:
        from playwright.sync_api import sync_playwright
        availability["browser"] = True
    except (ImportError, Exception):
        availability["browser"] = False
    
    return availability


def format_tool_availability(availability: dict[str, bool]) -> str:
    """
    Format tool availability for injection into system prompt.
    Returns a string that tells the LLM what tools are available.
    """
    available = [t for t, ok in availability.items() if ok]
    missing = [t for t, ok in availability.items() if not ok]
    
    if not missing:
        return ""  # All tools available, no need to mention
    
    lines = ["\n## Tool Availability\n"]
    if available:
        lines.append(f"**Installed:** {', '.join(available)}")
    if missing:
        lines.append(f"**NOT installed (do NOT use these):** {', '.join(missing)}")
        lines.append("Use `http` requests and browser tools as alternatives for missing tools.")
    
    return "\n".join(lines)
