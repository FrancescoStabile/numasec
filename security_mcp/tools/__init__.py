"""Tool execution backends — consolidated 20-tool registry.

Composite tools dispatch to existing scanner implementations internally.
This reduces tool count from 50 to 20, improving LLM reasoning quality.
"""

import logging
import shutil

logger = logging.getLogger(__name__)

from security_mcp.tools._base import ToolRegistry

__all__ = ["ToolRegistry", "create_default_tool_registry"]


async def port_scan(
    target: str,
    ports: str = "top-100",
    timeout: float = 2.0,
) -> dict:
    """Run a TCP port scan with banner grabbing and version detection."""
    from security_mcp.scanners.python_connect import PythonConnectScanner

    scanner = PythonConnectScanner()
    return await scanner.scan_with_banners(target, ports=ports, timeout=timeout)


def create_default_tool_registry() -> ToolRegistry:
    """Create a ToolRegistry with all built-in tools and their schemas.

    Consolidated from 50 tools to 20 composite tools.
    Each composite tool dispatches to existing scanner implementations.
    """
    from security_mcp.tools.command_tool import run_command
    from security_mcp.tools.http_tool import http_request

    registry = ToolRegistry()

    # ------------------------------------------------------------------
    # 1. http_request — raw HTTP (replaces fetch_page too)
    # ------------------------------------------------------------------
    registry.register(
        "http_request",
        http_request,
        {
            "name": "http_request",
            "description": (
                "Send an HTTP request and return status, headers, body. "
                "Use for fingerprinting, manual exploitation, header checks, "
                "or any custom request. Replaces fetch_page for simple GETs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                        "default": "GET",
                    },
                    "headers": {"type": "object", "description": "Custom headers"},
                    "body": {"type": "string", "description": "Request body"},
                    "follow_redirects": {"type": "boolean", "default": True},
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 2. recon — unified reconnaissance
    # ------------------------------------------------------------------
    from security_mcp.tools.composite_recon import recon

    registry.register(
        "recon",
        recon,
        {
            "name": "recon",
            "description": (
                "Unified reconnaissance: port scan, technology fingerprint, "
                "subdomain enumeration, DNS lookup, protocol-specific service "
                "probing (FTP/SSH/SMB/SMTP/DB), and CVE enrichment for detected versions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Hostname, IP, or URL to scan"},
                    "checks": {
                        "type": "string",
                        "description": (
                            "Comma-separated checks: ports, tech, subdomains, dns, services. "
                            "'services' probes FTP/SSH/SMB/SMTP/Redis/MongoDB/MySQL on discovered ports. "
                            "CVE enrichment runs automatically when port versions are detected."
                        ),
                        "default": "ports,tech",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port spec: 'top-100', 'top-1000', '80,443', '1-1024'",
                        "default": "top-100",
                    },
                    "timeout": {"type": "number", "description": "Per-connection timeout", "default": 2.0},
                },
                "required": ["target"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 3. crawl — smart crawl with SPA auto-detection
    # ------------------------------------------------------------------
    from security_mcp.tools.composite_crawl import crawl

    registry.register(
        "crawl",
        crawl,
        {
            "name": "crawl",
            "description": (
                "Crawl a website to discover endpoints, forms, JS files. "
                "Auto-detects SPAs and upgrades to browser crawl. "
                "Supports OpenAPI/Swagger spec import for instant endpoint discovery."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Starting URL for the crawl"},
                    "depth": {"type": "integer", "description": "Max crawl depth", "default": 2},
                    "max_pages": {"type": "integer", "description": "Max pages to crawl", "default": 50},
                    "force_browser": {
                        "type": "boolean",
                        "description": "Force browser-based crawling even for non-SPA sites",
                        "default": False,
                    },
                    "openapi_url": {
                        "type": "string",
                        "description": (
                            "URL to OpenAPI/Swagger spec (JSON or YAML). "
                            "Extracts all endpoints, params, auth requirements. "
                            "Ideal for CI/CD — skip crawling, go straight to testing."
                        ),
                    },
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 4. injection_test — SQL, NoSQL, SSTI, CmdI, GraphQL
    # ------------------------------------------------------------------
    from security_mcp.tools.composite_injection import injection_test

    registry.register(
        "injection_test",
        injection_test,
        {
            "name": "injection_test",
            "description": (
                "Test for injection vulnerabilities: SQL injection, NoSQL injection, "
                "Server-Side Template Injection (SSTI), OS Command Injection, and "
                "GraphQL security issues. Specify types to test."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to test"},
                    "types": {
                        "type": "string",
                        "description": "Comma-separated: sql, nosql, ssti, cmdi, graphql",
                        "default": "sql,nosql,ssti,cmdi",
                    },
                    "params": {"type": "string", "description": "Comma-separated param names. Auto-detect if omitted"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    "body": {
                        "type": "string",
                        "description": "Request body (JSON string for APIs). Used with method=POST",
                    },
                    "content_type": {
                        "type": "string",
                        "enum": ["form", "json"],
                        "default": "form",
                    },
                    "headers": {"type": "string", "description": "JSON string of HTTP headers for auth testing"},
                    "waf_evasion": {"type": "boolean", "description": "Enable WAF bypass encoding", "default": False},
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 5. xss_test — reflected + DOM XSS (kept separate, distinct methodology)
    # ------------------------------------------------------------------
    from security_mcp.scanners.xss_tester import python_xss_test

    registry.register(
        "xss_test",
        python_xss_test,
        {
            "name": "xss_test",
            "description": (
                "Test for Cross-Site Scripting (XSS): reflected XSS via canary "
                "injection and payload escalation, plus DOM XSS indicators "
                "(dangerous sinks and sources in JavaScript)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL with query parameters"},
                    "params": {"type": "string", "description": "Comma-separated param names. Auto-detect if omitted"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    "headers": {"type": "string", "description": "JSON string of HTTP headers for auth testing"},
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 6. access_control_test — IDOR, CSRF, CORS
    # ------------------------------------------------------------------
    from security_mcp.tools.composite_access import access_control_test

    registry.register(
        "access_control_test",
        access_control_test,
        {
            "name": "access_control_test",
            "description": (
                "Test for access control issues: IDOR (Insecure Direct Object Reference), "
                "CSRF (Cross-Site Request Forgery), and CORS misconfiguration. "
                "Specify checks to run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to test"},
                    "checks": {
                        "type": "string",
                        "description": "Comma-separated: idor, csrf, cors",
                        "default": "idor,csrf,cors",
                    },
                    "headers": {"type": "string", "description": "JSON string of HTTP headers for auth testing"},
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 7. auth_test — JWT / OAuth (kept separate, specialized)
    # ------------------------------------------------------------------
    from security_mcp.scanners.auth_tester import python_auth_test

    registry.register(
        "auth_test",
        python_auth_test,
        {
            "name": "auth_test",
            "description": (
                "Test JWT and OAuth authentication security: alg:none attack, "
                "weak HS256 secrets (50 common), kid path traversal, OAuth state "
                "validation, Bearer/API key exposure, default credentials, and "
                "password spray. Use 'checks' to select: jwt, creds, spray."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to test for auth vulnerabilities"},
                    "token": {
                        "type": "string",
                        "description": (
                            "Optional JWT to test directly. If provided, skips JWT discovery "
                            "and runs alg:none, weak-secret, kid-injection against this token."
                        ),
                    },
                    "headers": {
                        "type": "string",
                        "description": (
                            "Optional comma-separated key:value headers "
                            "(e.g. 'Authorization:Bearer xyz,X-Api-Key:abc')"
                        ),
                    },
                    "checks": {
                        "type": "string",
                        "description": (
                            "Comma-separated check types: jwt, creds, spray. "
                            "Default 'jwt,creds'. Spray must be explicitly opted in."
                        ),
                        "default": "jwt,creds",
                    },
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 8. ssrf_test — kept separate, distinct methodology
    # ------------------------------------------------------------------
    from security_mcp.scanners.ssrf_tester import python_ssrf_test

    registry.register(
        "ssrf_test",
        python_ssrf_test,
        {
            "name": "ssrf_test",
            "description": (
                "Test for Server-Side Request Forgery (SSRF). Injects internal and "
                "cloud metadata URLs into query params. Auto-injects SSRF param names "
                "(url, uri, path, dest, callback) even without existing params."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to test for SSRF"},
                    "headers": {"type": "string", "description": "JSON string of HTTP headers for auth testing"},
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 9. path_test — LFI, XXE, Open Redirect, Host Header
    # ------------------------------------------------------------------
    from security_mcp.tools.composite_path import path_test

    registry.register(
        "path_test",
        path_test,
        {
            "name": "path_test",
            "description": (
                "Test for path traversal (LFI), XXE injection, open redirect, "
                "and host header injection. Specify checks to run."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to test"},
                    "checks": {
                        "type": "string",
                        "description": "Comma-separated: lfi, xxe, redirect, host_header",
                        "default": "lfi,xxe,redirect,host_header",
                    },
                    "params": {"type": "string", "description": "Comma-separated param names. Auto-detect if omitted"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    "headers": {"type": "string", "description": "JSON string of HTTP headers for auth testing"},
                    "waf_evasion": {"type": "boolean", "description": "Enable WAF bypass encoding", "default": False},
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 10. dir_fuzz — directory/file fuzzing (kept separate)
    # ------------------------------------------------------------------
    if shutil.which("ffuf"):
        from security_mcp.tools.command_tool import run_command as _ffuf_run

        registry.register(
            "dir_fuzz",
            _ffuf_run,
            {
                "name": "dir_fuzz",
                "description": "Fuzz directories and files on a web server using ffuf.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "array", "items": {"type": "string"}, "description": "ffuf command and args"},
                    },
                    "required": ["command"],
                },
            },
        )
    else:
        from security_mcp.scanners.dir_fuzzer import python_dir_fuzz

        registry.register(
            "dir_fuzz",
            python_dir_fuzz,
            {
                "name": "dir_fuzz",
                "description": (
                    "Fuzz directories and files on a web server. Discovers hidden "
                    "paths, admin panels, config files, backups using a built-in wordlist."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target base URL"},
                        "wordlist": {"type": "string", "description": "Comma-separated custom paths. Uses built-in if omitted"},
                        "extensions": {"type": "string", "description": "File extensions to append (e.g. 'php,bak,old')"},
                    },
                    "required": ["url"],
                },
            },
        )

    # ------------------------------------------------------------------
    # 11. js_analyze — JavaScript security analysis (kept separate)
    # ------------------------------------------------------------------
    from security_mcp.scanners.js_analyzer import python_js_analyze

    registry.register(
        "js_analyze",
        python_js_analyze,
        {
            "name": "js_analyze",
            "description": (
                "Analyze JavaScript files for security issues: API endpoints, "
                "hardcoded secrets (API keys, tokens, AWS creds), sensitive routes, "
                "DOM XSS sinks, source maps, and debug flags."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target page URL (JS files auto-discovered)"},
                    "js_files": {"type": "string", "description": "Comma-separated JS file URLs (optional)"},
                    "headers": {"type": "string", "description": "JSON string of HTTP headers for auth testing"},
                },
                "required": ["url"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 12. browser — unified navigate/click/fill/screenshot
    # ------------------------------------------------------------------
    from security_mcp.tools.composite_browser import browser

    registry.register(
        "browser",
        browser,
        {
            "name": "browser",
            "description": (
                "Interact with a headless browser: navigate to URL, click elements, "
                "fill form fields, or take screenshots. For SPA testing and DOM interaction."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["navigate", "click", "fill", "screenshot"],
                        "description": "Browser action to perform",
                    },
                    "url": {"type": "string", "description": "URL for navigate action"},
                    "selector": {"type": "string", "description": "CSS/text selector for click/fill"},
                    "value": {"type": "string", "description": "Value to type for fill action"},
                    "wait_for": {
                        "type": "string",
                        "enum": ["load", "domcontentloaded", "networkidle"],
                        "default": "load",
                    },
                },
                "required": ["action"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 13. oob — Out-of-Band setup/poll
    # ------------------------------------------------------------------
    from security_mcp.tools.composite_oob import oob

    registry.register(
        "oob",
        oob,
        {
            "name": "oob",
            "description": (
                "Out-of-Band blind vulnerability detection via interactsh. "
                "Setup: creates a callback listener domain. Poll: checks for "
                "DNS/HTTP/SMTP callbacks. Confirms blind SSRF, XXE, XSS, SQLi."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["setup", "poll"],
                        "description": "OOB action: setup or poll",
                    },
                    "server": {"type": "string", "description": "Interactsh server (default: oast.live)"},
                    "correlation_id": {"type": "string", "description": "Correlation ID from setup (for poll)"},
                },
                "required": ["action"],
            },
        },
    )

    # ------------------------------------------------------------------
    # 14. run_command (internal, excluded from MCP by default)
    # ------------------------------------------------------------------
    registry.register(
        "run_command",
        run_command,
        {
            "name": "run_command",
            "description": "Execute a command in a sandboxed environment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "array", "items": {"type": "string"}, "description": "Command and arguments"},
                    "timeout": {"type": "integer", "default": 300},
                },
                "required": ["command"],
            },
        },
    )

    # ------------------------------------------------------------------
    # External tool integrations (available when binaries present)
    # ------------------------------------------------------------------
    if shutil.which("sqlmap"):
        from security_mcp.tools.exploit_tools import sqlmap_scan

        registry.register(
            "sqlmap_scan",
            sqlmap_scan,
            {
                "name": "sqlmap_scan",
                "description": "Deep SQL injection testing via sqlmap. Use after injection_test confirms SQLi.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL with parameters"},
                        "params": {"type": "object", "description": "Extra sqlmap options: level, risk, tamper"},
                    },
                    "required": ["url"],
                },
            },
        )

    if shutil.which("nuclei"):
        from security_mcp.tools.exploit_tools import nuclei_scan

        registry.register(
            "nuclei_scan",
            nuclei_scan,
            {
                "name": "nuclei_scan",
                "description": "Run nuclei vulnerability scanner with community templates.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL or host"},
                        "templates": {"type": "array", "items": {"type": "string"}, "description": "Template IDs to use"},
                    },
                    "required": ["target"],
                },
            },
        )

    logger.info(
        "Tool registry created: %d tools (%d available for MCP)",
        len(registry._tools),
        len([t for t in registry._tools if t != "run_command"]),
    )
    return registry
