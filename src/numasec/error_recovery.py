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
    "timeout": {
        "indicators": ["timeout", "navigation timeout", "page load timeout"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Browser navigation timed out. Page may be slow or stuck. "
                "Try with longer timeout or simpler http tool."
            ),
            retry_tool="http",
            retry_args={"method": "GET"},
        ),
    },
    "element_not_found": {
        "indicators": ["element not found", "selector not found", "no such element"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Element/selector not found on page. Page structure may have changed. "
                "Verify selector is correct or take screenshot to inspect."
            ),
            retry_tool="browser",
            retry_args={"action": "screenshot"},
        ),
    },
    "connection_error": {
        "indicators": ["net::ERR_CONNECTION", "failed to navigate", "connection refused"],
        "strategy": RecoveryStrategy(
            guidance=(
                "Browser cannot connect to target. Service may be down. "
                "Verify with http tool first."
            ),
            retry_tool="http",
            retry_args={"method": "GET"},
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
