"""
NumaSec Standards — Vulnerability Type to CWE-ID Mapping

Maps finding titles/descriptions to CWE (Common Weakness Enumeration) IDs.
100+ mappings covering OWASP Top 10 and common web vulnerabilities.

Reference: https://cwe.mitre.org/
"""

from __future__ import annotations

import re
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════
# CWE Database — keyword patterns → CWE entries
# ═══════════════════════════════════════════════════════════════════════════

CWE_DATABASE: list[dict[str, Any]] = [
    # ── Injection ──
    {
        "id": "CWE-89",
        "name": "SQL Injection",
        "keywords": ("sql injection", "sqli", "sql inject", "blind sql", "error-based sql"),
        "owasp": "A03:2021",
    },
    {
        "id": "CWE-78",
        "name": "OS Command Injection",
        "keywords": ("command injection", "os command", "cmd injection", "cmdi", "shell injection", "rce via command"),
        "owasp": "A03:2021",
    },
    {
        "id": "CWE-79",
        "name": "Cross-site Scripting (XSS)",
        "keywords": ("xss", "cross-site scripting", "cross site scripting", "reflected xss", "stored xss", "dom xss", "dom-based xss"),
        "owasp": "A03:2021",
    },
    {
        "id": "CWE-90",
        "name": "LDAP Injection",
        "keywords": ("ldap injection", "ldap inject"),
        "owasp": "A03:2021",
    },
    {
        "id": "CWE-91",
        "name": "XML Injection",
        "keywords": ("xml injection", "xml inject"),
        "owasp": "A03:2021",
    },
    {
        "id": "CWE-611",
        "name": "XML External Entity (XXE)",
        "keywords": ("xxe", "xml external entity", "xml entity"),
        "owasp": "A05:2021",
    },
    {
        "id": "CWE-917",
        "name": "Server-Side Template Injection (SSTI)",
        "keywords": ("ssti", "server-side template injection", "template injection", "jinja injection"),
        "owasp": "A03:2021",
    },
    {
        "id": "CWE-943",
        "name": "NoSQL Injection",
        "keywords": ("nosql injection", "nosql inject", "mongodb injection"),
        "owasp": "A03:2021",
    },
    # ── Broken Authentication ──
    {
        "id": "CWE-287",
        "name": "Improper Authentication",
        "keywords": ("authentication bypass", "auth bypass", "broken authentication", "improper auth"),
        "owasp": "A07:2021",
    },
    {
        "id": "CWE-798",
        "name": "Hard-coded Credentials",
        "keywords": ("hard-coded credential", "hardcoded credential", "default credential", "default password", "default cred"),
        "owasp": "A07:2021",
    },
    {
        "id": "CWE-307",
        "name": "Brute Force",
        "keywords": ("brute force", "brute-force", "password brute", "credential stuffing"),
        "owasp": "A07:2021",
    },
    {
        "id": "CWE-384",
        "name": "Session Fixation",
        "keywords": ("session fixation", "session fix"),
        "owasp": "A07:2021",
    },
    {
        "id": "CWE-613",
        "name": "Insufficient Session Expiration",
        "keywords": ("session expir", "session timeout", "insufficient session"),
        "owasp": "A07:2021",
    },
    # ── JWT ──
    {
        "id": "CWE-345",
        "name": "Insufficient Verification of Data Authenticity",
        "keywords": ("jwt", "json web token", "jwt none", "jwt algorithm", "token forgery"),
        "owasp": "A02:2021",
    },
    # ── Access Control ──
    {
        "id": "CWE-639",
        "name": "Authorization Bypass (IDOR)",
        "keywords": ("idor", "insecure direct object", "authorization bypass", "access control", "broken access"),
        "owasp": "A01:2021",
    },
    {
        "id": "CWE-284",
        "name": "Improper Access Control",
        "keywords": ("improper access control", "privilege escalation", "vertical escalation", "horizontal escalation"),
        "owasp": "A01:2021",
    },
    {
        "id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "keywords": ("csrf", "cross-site request forgery", "request forgery", "xsrf"),
        "owasp": "A01:2021",
    },
    # ── File Handling ──
    {
        "id": "CWE-22",
        "name": "Path Traversal",
        "keywords": ("path traversal", "directory traversal", "lfi", "local file inclusion", "file inclusion", "../"),
        "owasp": "A01:2021",
    },
    {
        "id": "CWE-434",
        "name": "Unrestricted File Upload",
        "keywords": ("file upload", "unrestricted upload", "webshell upload", "arbitrary file upload"),
        "owasp": "A04:2021",
    },
    {
        "id": "CWE-98",
        "name": "Remote File Inclusion (RFI)",
        "keywords": ("remote file inclusion", "rfi"),
        "owasp": "A03:2021",
    },
    # ── SSRF ──
    {
        "id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "keywords": ("ssrf", "server-side request forgery", "server side request forgery"),
        "owasp": "A10:2021",
    },
    # ── Information Disclosure ──
    {
        "id": "CWE-200",
        "name": "Exposure of Sensitive Information",
        "keywords": ("information disclosure", "info disclosure", "sensitive information", "data exposure", "data leak", "version disclosure", "server version", "banner grab", "version leak"),
        "owasp": "A01:2021",
    },
    {
        "id": "CWE-209",
        "name": "Information Exposure Through Error Messages",
        "keywords": ("error message", "verbose error", "stack trace", "debug information", "debug mode"),
        "owasp": "A05:2021",
    },
    {
        "id": "CWE-548",
        "name": "Exposure of Information Through Directory Listing",
        "keywords": ("directory listing", "dir listing", "exposed directory", "index of"),
        "owasp": "A05:2021",
    },
    {
        "id": "CWE-532",
        "name": "Insertion of Sensitive Information into Log File",
        "keywords": ("log file", "log exposure", "sensitive log"),
        "owasp": "A09:2021",
    },
    # ── Security Misconfiguration ──
    {
        "id": "CWE-16",
        "name": "Configuration",
        "keywords": ("misconfiguration", "misconfig", "config exposure", "configuration error"),
        "owasp": "A05:2021",
    },
    {
        "id": "CWE-693",
        "name": "Protection Mechanism Failure",
        "keywords": ("missing header", "security header", "hsts", "x-frame-options", "csp", "content-security-policy", "x-content-type"),
        "owasp": "A05:2021",
    },
    {
        "id": "CWE-942",
        "name": "Permissive CORS Policy",
        "keywords": ("cors", "cross-origin", "cors misconfiguration", "permissive cors"),
        "owasp": "A05:2021",
    },
    {
        "id": "CWE-614",
        "name": "Sensitive Cookie Without 'Secure' Flag",
        "keywords": ("cookie", "secure flag", "httponly", "samesite", "cookie flag"),
        "owasp": "A05:2021",
    },
    # ── Cryptographic Failures ──
    {
        "id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "keywords": ("weak encryption", "weak cipher", "inadequate encryption", "weak ssl", "weak tls"),
        "owasp": "A02:2021",
    },
    {
        "id": "CWE-327",
        "name": "Use of Broken Crypto Algorithm",
        "keywords": ("broken crypto", "md5", "sha1 hash", "weak hash", "broken algorithm"),
        "owasp": "A02:2021",
    },
    {
        "id": "CWE-319",
        "name": "Cleartext Transmission",
        "keywords": ("cleartext", "plaintext", "unencrypted", "http without tls", "no https"),
        "owasp": "A02:2021",
    },
    {
        "id": "CWE-312",
        "name": "Cleartext Storage",
        "keywords": ("cleartext storage", "plaintext password", "cleartext password", "password in plaintext"),
        "owasp": "A02:2021",
    },
    # ── Deserialization ──
    {
        "id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "keywords": ("deserialization", "insecure deserialization", "unserialize", "pickle", "yaml load"),
        "owasp": "A08:2021",
    },
    # ── Vulnerable Components ──
    {
        "id": "CWE-1395",
        "name": "Dependency on Vulnerable Third-Party Component",
        "keywords": ("outdated", "vulnerable component", "vulnerable dependency", "known vulnerability", "cve-", "outdated lib"),
        "owasp": "A06:2021",
    },
    # ── Logging ──
    {
        "id": "CWE-117",
        "name": "Improper Output Neutralization for Logs",
        "keywords": ("log injection", "log poisoning", "log4shell", "log4j"),
        "owasp": "A09:2021",
    },
    # ── Open Redirect ──
    {
        "id": "CWE-601",
        "name": "URL Redirection to Untrusted Site",
        "keywords": ("open redirect", "url redirect", "redirect", "phishing redirect"),
        "owasp": "A01:2021",
    },
    # ── Race Conditions ──
    {
        "id": "CWE-362",
        "name": "Race Condition",
        "keywords": ("race condition", "toctou", "time of check"),
        "owasp": "A04:2021",
    },
    # ── Missing Rate Limiting ──
    {
        "id": "CWE-770",
        "name": "Allocation of Resources Without Limits",
        "keywords": ("rate limit", "no rate limit", "dos", "denial of service", "resource exhaustion"),
        "owasp": "A04:2021",
    },
    # ── CAPTCHA Issues ──
    {
        "id": "CWE-804",
        "name": "Guessable CAPTCHA",
        "keywords": ("captcha", "captcha bypass", "insecure captcha"),
        "owasp": "A07:2021",
    },
    # ── API Security ──
    {
        "id": "CWE-1059",
        "name": "Incomplete Documentation",
        "keywords": ("api doc", "swagger", "api-docs", "exposed api", "api documentation exposed"),
        "owasp": "A05:2021",
    },
    # ── Sensitive Data in URL ──
    {
        "id": "CWE-598",
        "name": "Use of GET Request Method With Sensitive Query Strings",
        "keywords": ("sensitive data in url", "token in url", "password in url", "api key in url"),
        "owasp": "A04:2021",
    },
    # ── Subdomain Takeover ──
    {
        "id": "CWE-350",
        "name": "Reliance on Reverse DNS Resolution",
        "keywords": ("subdomain takeover", "dangling dns", "unclaimed subdomain"),
        "owasp": "A05:2021",
    },
    # ── Clickjacking ──
    {
        "id": "CWE-1021",
        "name": "Improper Restriction of Rendered UI Layers",
        "keywords": ("clickjacking", "click jacking", "ui redressing", "frame injection"),
        "owasp": "A05:2021",
    },
    # ── Server Version Disclosure ──
    # NOTE: merged into CWE-200 above — "version disclosure" is a keyword there
    # ── Environment/Config File Exposure ──
    {
        "id": "CWE-538",
        "name": "Insertion of Sensitive Information into Externally-Accessible File",
        "keywords": (".env", "config file", "environment file", ".git exposed", "git config", "config exposure"),
        "owasp": "A05:2021",
    },
]


def map_to_cwe(text: str) -> dict[str, Any] | None:
    """Map a finding title/description to the best matching CWE.

    Uses word-boundary matching: keyword 'sql' won't match 'result'.

    Args:
        text: Finding title + description (lowercased)

    Returns:
        CWE entry dict with 'id', 'name', 'keywords', 'owasp', or None
    """
    text = text.lower()

    best_match = None
    best_score = 0

    for entry in CWE_DATABASE:
        score = 0
        for kw in entry["keywords"]:
            # Use word boundary for short keywords (<5 chars) to prevent
            # false positives like "sql" matching "result"
            if len(kw) < 5:
                if re.search(r'\b' + re.escape(kw) + r'\b', text):
                    score += 1
            else:
                if kw in text:
                    score += 1
        if score > best_score:
            best_score = score
            best_match = entry

    return best_match if best_score > 0 else None


def get_cwe_by_id(cwe_id: str) -> dict[str, Any] | None:
    """Look up a CWE entry by its ID.

    Args:
        cwe_id: CWE identifier (e.g. "CWE-89")

    Returns:
        CWE entry dict or None
    """
    cwe_id = cwe_id.upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"

    for entry in CWE_DATABASE:
        if entry["id"] == cwe_id:
            return entry
    return None
