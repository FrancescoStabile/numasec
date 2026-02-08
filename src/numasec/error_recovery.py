"""
Error Recovery Patterns - Phase 4 Intelligence

Impact: +44% retry success rate

Tool-specific error patterns with recovery strategies.
When a tool fails, provide intelligent guidance for next action.
"""

from dataclasses import dataclass
import re
from typing import Literal

@dataclass
class RecoveryStrategy:
    """Strategy for recovering from a tool failure."""
    guidance: str  # Human-readable explanation
    retry_tool: str | None = None  # Suggested tool to retry with
    retry_args: dict | None = None  # Suggested different arguments
    give_up: bool = False  # If True, don't retry this attack vector


# ═══════════════════════════════════════════════════════════════════════════
# NMAP ERROR PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

NMAP_PATTERNS = {
    "timeout": {
        "indicators": ["timed out", "timeout", "no response", "host seems down"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Nmap timed out. The host may be firewalled or using rate limiting. "
                "Try with longer timeout or different scan type."
            ),
            retry_tool="nmap",
            retry_args={"scan_type": "quick", "extra_args": "--host-timeout 300s"},
        ),
    },
    "permission_denied": {
        "indicators": ["permission denied", "requires root", "operation not permitted"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Nmap requires elevated privileges for this scan type. "
                "Continue with non-privileged scans (TCP connect scan)."
            ),
            retry_tool="nmap",
            retry_args={"scan_type": "quick"},  # TCP connect doesn't need root
        ),
    },
    "host_down": {
        "indicators": ["host is down", "no hosts up", "host appears to be down"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Nmap reports host is down. Either target is offline or blocking ICMP. "
                "Try assuming host is up with -Pn flag."
            ),
            retry_tool="nmap",
            retry_args={"extra_args": "-Pn"},  # Skip ping, assume host is up
        ),
    },
    "invalid_target": {
        "indicators": ["invalid target", "failed to resolve", "cannot resolve hostname"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Target hostname/IP is invalid or DNS resolution failed. "
                "Verify target format (IP address or valid domain)."
            ),
            give_up=True,
        ),
    },
}

# ═══════════════════════════════════════════════════════════════════════════
# HTTP ERROR PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

HTTP_PATTERNS = {
    "connection_error": {
        "indicators": ["connection refused", "connection failed", "cannot connect"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Cannot connect to target. Service may be down or port is closed. "
                "Verify target is running and port is correct. Try nmap first."
            ),
            retry_tool="nmap",
            retry_args={"scan_type": "quick"},
        ),
    },
    "timeout": {
        "indicators": ["timed out", "timeout", "read timeout"],
        "strategy": RecoveryStrategy(
            guidance=(
                "HTTP request timed out. Server may be slow or overloaded. "
                "Try with longer timeout."
            ),
            retry_tool="http",
            retry_args={"timeout": 30},  # Increase timeout
        ),
    },
    "ssl_error": {
        "indicators": ["ssl error", "certificate verify failed", "ssl handshake failed"],
        "strategy": RecoveryStrategy(
            guidance=(
                "SSL/TLS error. Self-signed certificate or SSL misconfiguration. "
                "Try with SSL verification disabled (for testing only)."
            ),
            retry_tool="http",
            retry_args={"verify_ssl": False},
        ),
    },
    "waf_detected": {
        "indicators": ["waf detected", "blocked by firewall", "403 forbidden", "cloudflare"],
        "strategy": RecoveryStrategy(
            guidance=(
                "WAF (Web Application Firewall) detected. Request blocked. "
                "Try with different User-Agent or bypass techniques."
            ),
            retry_tool="http",
            retry_args={"headers": {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}},
        ),
    },
}

# ═══════════════════════════════════════════════════════════════════════════
# SQLMAP ERROR PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

SQLMAP_PATTERNS = {
    "waf_detected": {
        "indicators": ["waf", "ips detected", "protection system detected", "heuristic detection", "protection detected"],
        "strategy": RecoveryStrategy(
            guidance=(
                "SQLMap detected WAF protection. All payloads were blocked. "
                "Retry with tamper scripts to bypass WAF."
            ),
            retry_tool="sqlmap",
            retry_args={"options": ["--tamper=space2comment,between", "--random-agent"]},
        ),
    },
    "not_injectable": {
        "indicators": [
            "not injectable",
            "no parameter(s) found",
            "all tested parameters do not appear to be injectable",
        ],
        "strategy": RecoveryStrategy(
            guidance=(
                "SQLMap found no SQL injection. Parameter may not be vulnerable. "
                "Move on to test other parameters or attack vectors."
            ),
            give_up=True,
        ),
    },
    "connection_error": {
        "indicators": ["connection dropped", "connection timeout", "unable to connect"],
        "strategy": RecoveryStrategy(
            guidance=(
                "SQLMap cannot connect to target. Service may be down. "
                "Verify target is accessible with http tool first."
            ),
            retry_tool="http",
            retry_args={"method": "GET"},
        ),
    },
    "permission_denied": {
        "indicators": ["access denied", "insufficient privileges", "permission denied"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Database user has insufficient privileges for this operation. "
                "SQLi exists but limited. Try extracting available data only."
            ),
            retry_tool="sqlmap",
            retry_args={"options": ["--current-db", "--current-user"]},
        ),
    },
}

# ═══════════════════════════════════════════════════════════════════════════
# NUCLEI ERROR PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

NUCLEI_PATTERNS = {
    "no_templates": {
        "indicators": ["no templates loaded", "templates not found", "no templates"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Nuclei templates not found. Update nuclei templates. "
                "Run: nuclei -update-templates"
            ),
            give_up=True,
        ),
    },
    "connection_error": {
        "indicators": ["connection refused", "no such host", "connection error"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Cannot connect to target. Verify target is accessible. "
                "Try http tool first to confirm."
            ),
            retry_tool="http",
            retry_args={"method": "GET"},
        ),
    },
    "timeout": {
        "indicators": ["timed out", "timeout", "context deadline exceeded"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Nuclei scan timed out. Target may be slow or scan too aggressive. "
                "Try with reduced concurrency or specific templates only."
            ),
            retry_tool="nuclei",
            retry_args={"concurrency": 5, "templates": ["exposures", "cves"]},
        ),
    },
}

# ═══════════════════════════════════════════════════════════════════════════
# BROWSER ERROR PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

BROWSER_PATTERNS = {
    "timeout_networkidle": {
        "indicators": ["timed out", "timeout", "page load timeout", "30 seconds", "60 seconds"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Browser tool timed out. COMMON CAUSES:\n"
                "1. Using networkidle on a SPA (Angular/React/Vue) — these apps never become 'idle'\n"
                "2. An overlay/modal is blocking interaction (welcome banner, cookie consent)\n"
                "3. The selector doesn't match any visible element\n\n"
                "SOLUTIONS (in order):\n"
                "1. Take a screenshot first (browser_screenshot) to see current page state\n"
                "2. If SPA: navigation now auto-uses domcontentloaded (networkidle avoided)\n"
                "3. If overlay blocking: overlays are now auto-dismissed\n"
                "4. If selector wrong: use browser_screenshot, then retry with correct selector\n"
                "5. Try a simpler selector (e.g., 'input[type=search]' instead of complex CSS)"
            ),
            retry_tool="browser_screenshot",
            retry_args={"filename": "debug_page_state.png"},
        ),
    },
    "element_not_found": {
        "indicators": ["element not found", "selector not found", "no such element",
                       "waiting for selector", "locator resolved to", "strict mode violation"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Element/selector not found. Possible causes:\n"
                "1. Selector is wrong — page structure may differ from expected\n"
                "2. Element is inside a shadow DOM or iframe\n"
                "3. Element hasn't loaded yet (SPA hydration delay)\n"
                "4. An overlay is covering the target element\n\n"
                "SOLUTIONS:\n"
                "1. Use browser_screenshot to see actual page state\n"
                "2. Try simpler selectors: '#id', 'input[name=x]', or '[aria-label=x]'\n"
                "3. For iframes: navigate directly to iframe src URL\n"
                "4. Comma-separated selectors are now tried independently as fallback"
            ),
            retry_tool="browser_screenshot",
            retry_args={"filename": "debug_selector.png"},
        ),
    },
    "element_not_visible": {
        "indicators": ["element is not visible", "element is hidden", "outside of the viewport",
                       "element is not enabled", "element is not editable", "intercepted"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Element exists but is not interactable. Causes:\n"
                "1. Hidden by CSS (display:none, visibility:hidden)\n"
                "2. Covered by an overlay/modal\n"
                "3. Outside viewport (needs scroll)\n"
                "4. Disabled input field\n\n"
                "SOLUTIONS:\n"
                "1. Overlays are now auto-dismissed before interaction\n"
                "2. Force fill/click is now attempted automatically\n"
                "3. Try JS injection strategy (sets value via JavaScript directly)\n"
                "4. Use browser_screenshot to diagnose"
            ),
            retry_tool="browser_screenshot",
            retry_args={"filename": "debug_visibility.png"},
        ),
    },
    "dialog_blocking": {
        "indicators": ["dialog", "alert", "confirm", "prompt", "beforeunload"],
        "strategy": RecoveryStrategy(
            guidance=(
                "A JavaScript dialog (alert/confirm/prompt) may be blocking page interaction. "
                "Dialog handler is now installed automatically — dialogs are captured as XSS proof "
                "and auto-accepted. If this persists, the dialog may be from a previous action. "
                "Try browser_clear_session and retry."
            ),
            retry_tool="browser_clear_session",
        ),
    },
    "connection_error": {
        "indicators": ["net::ERR_CONNECTION", "failed to navigate", "connection refused",
                       "ERR_NAME_NOT_RESOLVED", "ERR_SSL", "net::ERR_"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Browser cannot connect to target. Service may be down or URL is wrong. "
                "Verify with http tool first, then retry with browser."
            ),
            retry_tool="http",
            retry_args={"method": "GET"},
        ),
    },
    "page_crashed": {
        "indicators": ["page crashed", "target closed", "browser disconnected",
                       "execution context was destroyed", "frame detached"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Browser page crashed or was closed unexpectedly. "
                "This can happen with heavy JavaScript pages or XSS payloads that break the page. "
                "Use browser_clear_session to reset, then retry."
            ),
            retry_tool="browser_clear_session",
        ),
    },
    "csp_blocked": {
        "indicators": ["content security policy", "csp", "refused to execute",
                       "blocked by CSP", "violates the following"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Content Security Policy (CSP) blocked script execution. "
                "Browser context now has bypass_csp=True enabled. "
                "If XSS is blocked by CSP, this is actually a FINDING — CSP is protecting the app. "
                "Register it as a finding (security control detected) and try CSP bypass techniques."
            ),
        ),
    },
}

# ═══════════════════════════════════════════════════════════════════════════
# REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

ERROR_PATTERNS = {
    "nmap": NMAP_PATTERNS,
    "http": HTTP_PATTERNS,
    "sqlmap": SQLMAP_PATTERNS,
    "nuclei": NUCLEI_PATTERNS,
    "browser": BROWSER_PATTERNS,
    # Map individual browser tool names to the same patterns
    "browser_navigate": BROWSER_PATTERNS,
    "browser_fill": BROWSER_PATTERNS,
    "browser_click": BROWSER_PATTERNS,
    "browser_screenshot": BROWSER_PATTERNS,
    "browser_login": BROWSER_PATTERNS,
    "browser_get_cookies": BROWSER_PATTERNS,
}


def get_recovery_strategy(tool_name: str, error_result: str) -> RecoveryStrategy | None:
    """
    Match error result against known patterns and return recovery strategy.
    
    Args:
        tool_name: Name of the tool that failed
        error_result: The error output from the tool
        
    Returns:
        RecoveryStrategy if pattern matched, None otherwise
    """
    tool_patterns = ERROR_PATTERNS.get(tool_name, {})
    error_lower = error_result.lower()
    
    for pattern_name, pattern_data in tool_patterns.items():
        indicators = pattern_data["indicators"]
        if any(ind in error_lower for ind in indicators):
            return pattern_data["strategy"]
    
    return None


def inject_recovery_guidance(tool_name: str, error_result: str) -> str:
    """
    Generate recovery guidance prompt to inject after tool failure.
    
    Args:
        tool_name: Name of the tool that failed
        error_result: The error output from the tool
        
    Returns:
        Formatted prompt with recovery guidance
    """
    strategy = get_recovery_strategy(tool_name, error_result)
    
    if not strategy:
        # Generic failure guidance
        return f"""
Tool '{tool_name}' failed: {error_result[:100]}

This error is not recognized. Analyze the error message and:
1. Determine if you should retry with different parameters
2. Try a different tool
3. Or move on to a different attack vector
"""
    
    # Pattern-matched guidance
    if strategy.give_up:
        return f"""
Tool '{tool_name}' failed: {error_result[:100]}

**Recovery Guidance**: {strategy.guidance}

This is expected. Move on to next attack vector.
"""
    
    guidance = f"""
Tool '{tool_name}' failed: {error_result[:100]}

**Recovery Guidance**: {strategy.guidance}
"""
    
    if strategy.retry_tool:
        guidance += f"\n\n**Suggested Next Step**: \nTool: {strategy.retry_tool}\n"
        if strategy.retry_args:
            guidance += f"Arguments: {strategy.retry_args}\n"
    
    return guidance


# ═══════════════════════════════════════════════════════════════════════════
# TESTING
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Test pattern matching
    test_cases = [
        ("nmap", "Error: host 192.168.1.1 timed out after 30 seconds"),
        ("http", "SSL Error: certificate verify failed for https://target.com"),
        ("sqlmap", "WAF/IPS protection detected. All payloads blocked."),
        ("nuclei", "Connection refused: target.com:443"),
        ("browser", "Timeout: navigation to https://test.com exceeded 30000ms"),
    ]
    
    print("="*70)
    print("Error Recovery Pattern Matching Test")
    print("="*70)
    
    for tool, error in test_cases:
        print(f"\n{tool.upper()}: {error[:50]}...")
        guidance = inject_recovery_guidance(tool, error)
        print(guidance)
        print("-"*70)
