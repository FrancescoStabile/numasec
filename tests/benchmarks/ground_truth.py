"""
NumaSec Benchmark — Ground Truth Definitions

Defines the known vulnerabilities in DVWA and OWASP Juice Shop
that NumaSec should detect. Used as the gold standard for F1
precision/recall scoring.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GroundTruthVuln:
    """A known vulnerability in a benchmark target."""
    id: str                 # Unique identifier (e.g. "dvwa_sqli")
    name: str               # Human-readable name
    vuln_type: str           # Category (sqli, xss, lfi, etc.)
    severity: str            # critical, high, medium, low, info
    location: str            # URL path or affected endpoint
    description: str         # Brief description
    match_keywords: tuple[str, ...] = ()  # Keywords to match in findings


# ═══════════════════════════════════════════════════════════════════════════
# DVWA — Damn Vulnerable Web Application (10 vulnerabilities)
# ═══════════════════════════════════════════════════════════════════════════

DVWA_VULNS: list[GroundTruthVuln] = [
    GroundTruthVuln(
        id="dvwa_sqli",
        name="SQL Injection",
        vuln_type="sqli",
        severity="critical",
        location="/vulnerabilities/sqli/",
        description="Classic error-based SQL injection in User ID parameter",
        match_keywords=("sql injection", "sqli", "sql", "injection"),
    ),
    GroundTruthVuln(
        id="dvwa_sqli_blind",
        name="Blind SQL Injection",
        vuln_type="sqli_blind",
        severity="high",
        location="/vulnerabilities/sqli_blind/",
        description="Boolean-based blind SQL injection in User ID parameter",
        match_keywords=("blind sql", "sqli_blind", "blind injection", "boolean-based"),
    ),
    GroundTruthVuln(
        id="dvwa_xss_reflected",
        name="Reflected XSS",
        vuln_type="xss_reflected",
        severity="medium",
        location="/vulnerabilities/xss_r/",
        description="Reflected cross-site scripting in name parameter",
        match_keywords=("reflected xss", "xss", "cross-site scripting", "reflected"),
    ),
    GroundTruthVuln(
        id="dvwa_xss_stored",
        name="Stored XSS",
        vuln_type="xss_stored",
        severity="high",
        location="/vulnerabilities/xss_s/",
        description="Stored cross-site scripting in guestbook",
        match_keywords=("stored xss", "persistent xss", "xss", "stored"),
    ),
    GroundTruthVuln(
        id="dvwa_cmdi",
        name="Command Injection",
        vuln_type="cmdi",
        severity="critical",
        location="/vulnerabilities/exec/",
        description="OS command injection in IP address parameter",
        match_keywords=("command injection", "os command", "cmdi", "rce", "exec"),
    ),
    GroundTruthVuln(
        id="dvwa_lfi",
        name="Local File Inclusion",
        vuln_type="lfi",
        severity="high",
        location="/vulnerabilities/fi/",
        description="Local file inclusion via page parameter",
        match_keywords=("file inclusion", "lfi", "local file", "path traversal"),
    ),
    GroundTruthVuln(
        id="dvwa_upload",
        name="File Upload",
        vuln_type="upload",
        severity="critical",
        location="/vulnerabilities/upload/",
        description="Unrestricted file upload allowing PHP webshell",
        match_keywords=("file upload", "upload", "webshell", "unrestricted"),
    ),
    GroundTruthVuln(
        id="dvwa_csrf",
        name="Cross-Site Request Forgery",
        vuln_type="csrf",
        severity="medium",
        location="/vulnerabilities/csrf/",
        description="CSRF in password change functionality",
        match_keywords=("csrf", "cross-site request forgery", "request forgery"),
    ),
    GroundTruthVuln(
        id="dvwa_brute",
        name="Brute Force",
        vuln_type="brute_force",
        severity="high",
        location="/vulnerabilities/brute/",
        description="Login form vulnerable to brute force attacks",
        match_keywords=("brute force", "brute", "password", "login"),
    ),
    GroundTruthVuln(
        id="dvwa_captcha",
        name="Insecure CAPTCHA",
        vuln_type="captcha",
        severity="medium",
        location="/vulnerabilities/captcha/",
        description="CAPTCHA can be bypassed by manipulating step parameter",
        match_keywords=("captcha", "insecure captcha", "captcha bypass"),
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# OWASP Juice Shop (12 vulnerabilities)
# ═══════════════════════════════════════════════════════════════════════════

JUICESHOP_VULNS: list[GroundTruthVuln] = [
    GroundTruthVuln(
        id="js_sqli",
        name="SQL Injection (login)",
        vuln_type="sqli",
        severity="critical",
        location="/rest/user/login",
        description="SQL injection in login email parameter",
        match_keywords=("sql injection", "sqli", "login", "authentication bypass"),
    ),
    GroundTruthVuln(
        id="js_xss",
        name="Reflected XSS (search)",
        vuln_type="xss",
        severity="medium",
        location="/#/search",
        description="Reflected XSS in search functionality",
        match_keywords=("xss", "cross-site scripting", "reflected", "search"),
    ),
    GroundTruthVuln(
        id="js_dir_listing",
        name="Exposed /ftp directory",
        vuln_type="dir_listing",
        severity="medium",
        location="/ftp",
        description="Directory listing enabled on /ftp exposing sensitive files",
        match_keywords=("directory listing", "ftp", "exposed", "dir listing", "directory"),
    ),
    GroundTruthVuln(
        id="js_default_creds",
        name="Default admin credentials",
        vuln_type="default_creds",
        severity="critical",
        location="/rest/user/login",
        description="Admin account accessible with default/guessable credentials",
        match_keywords=("default cred", "admin", "default password", "weak password"),
    ),
    GroundTruthVuln(
        id="js_headers",
        name="Missing security headers",
        vuln_type="headers",
        severity="low",
        location="/",
        description="Missing security headers (CSP, HSTS, X-Frame-Options, etc.)",
        match_keywords=("security header", "missing header", "csp", "hsts", "x-frame"),
    ),
    GroundTruthVuln(
        id="js_idor",
        name="IDOR (basket access)",
        vuln_type="idor",
        severity="high",
        location="/rest/basket/",
        description="IDOR allows accessing other users' shopping baskets",
        match_keywords=("idor", "insecure direct object", "basket", "authorization"),
    ),
    GroundTruthVuln(
        id="js_api_exposure",
        name="Exposed /api-docs",
        vuln_type="api_exposure",
        severity="medium",
        location="/api-docs",
        description="Swagger API documentation exposed publicly",
        match_keywords=("api-docs", "swagger", "api documentation", "api exposure", "exposed api"),
    ),
    GroundTruthVuln(
        id="js_jwt",
        name="JWT none algorithm",
        vuln_type="jwt_vuln",
        severity="critical",
        location="/rest/user/login",
        description="JWT tokens accept 'none' algorithm allowing token forgery",
        match_keywords=("jwt", "json web token", "token", "none algorithm", "token forgery"),
    ),
    GroundTruthVuln(
        id="js_dom_xss",
        name="DOM XSS",
        vuln_type="dom_xss",
        severity="medium",
        location="/#/search",
        description="DOM-based XSS through URL fragment in search",
        match_keywords=("dom xss", "dom-based", "xss", "client-side"),
    ),
    GroundTruthVuln(
        id="js_info_disclosure",
        name="Verbose error messages",
        vuln_type="info_disclosure",
        severity="low",
        location="/api/",
        description="Verbose SQL/stack trace error messages exposed to users",
        match_keywords=("error message", "verbose", "stack trace", "info disclosure", "information disclosure"),
    ),
    GroundTruthVuln(
        id="js_config_exposure",
        name="Config/env exposure",
        vuln_type="config_exposure",
        severity="high",
        location="/.env",
        description="Environment files or configuration exposed publicly",
        match_keywords=("config", ".env", "environment", "config exposure", "sensitive file"),
    ),
    GroundTruthVuln(
        id="js_dependencies",
        name="Outdated dependencies",
        vuln_type="dependencies",
        severity="medium",
        location="/",
        description="Application uses libraries with known vulnerabilities",
        match_keywords=("outdated", "dependencies", "vulnerable lib", "known vulnerabilit"),
    ),
]


# Combined
ALL_VULNS = DVWA_VULNS + JUICESHOP_VULNS
