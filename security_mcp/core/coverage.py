"""OWASP coverage data — maps tools to OWASP Top 10 categories.

Used by MCP intel_tools (get_coverage_gaps, get_mandatory_tests) to
determine which OWASP categories have been tested.
"""

from __future__ import annotations

# Maps OWASP categories to the tools that can test them.
OWASP_TOOL_MAP: dict[str, list[str]] = {
    "A01_access_control": ["idor_test", "auth_test", "csrf_test", "access_control_test"],
    "A02_crypto_failures": ["auth_test", "http_request"],
    "A03_injection": ["sqli_test", "nosql_test", "xss_test", "xxe_test", "ssti_test"],
    "A04_insecure_design": ["idor_test", "http_request", "injection_test"],
    "A05_misconfiguration": [
        "http_request",
        "nuclei_scan",
        "cors_test",
        "host_header_test",
        "js_analyze",
        "browser_crawl_site",
    ],
    "A06_vuln_components": ["nuclei_scan", "http_request"],
    "A07_auth_failures": ["auth_test", "sqli_test"],
    "A08_integrity_failures": ["csrf_test", "http_request"],
    "A09_logging_failures": ["http_request"],
    "A10_ssrf": ["ssrf_test", "open_redirect_test"],
}

# Reverse map: tool → OWASP categories it covers.
_TOOL_TO_OWASP: dict[str, list[str]] = {}
for _cat, _tools in OWASP_TOOL_MAP.items():
    for _t in _tools:
        _TOOL_TO_OWASP.setdefault(_t, []).append(_cat)

# Human-readable category labels.
_OWASP_LABELS: dict[str, str] = {
    "A01_access_control": "A01 Broken Access Control (IDOR, CSRF)",
    "A02_crypto_failures": "A02 Cryptographic Failures (weak hashing, JWT leaks)",
    "A03_injection": "A03 Injection (SQLi, NoSQL, XSS, XXE, SSTI)",
    "A04_insecure_design": "A04 Insecure Design (business logic, price tampering)",
    "A05_misconfiguration": "A05 Security Misconfiguration (headers, CORS, errors)",
    "A06_vuln_components": "A06 Vulnerable Components (CVEs, outdated libs)",
    "A07_auth_failures": "A07 Auth Failures (JWT weakness, password change, default creds)",
    "A08_integrity_failures": "A08 Integrity Failures (CSRF, unsigned updates)",
    "A09_logging_failures": "A09 Logging Failures (verbose errors, stack traces)",
    "A10_ssrf": "A10 SSRF (server-side request forgery)",
}
