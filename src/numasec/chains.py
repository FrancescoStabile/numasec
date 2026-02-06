"""
NumaSec — Attack Chains

When a vulnerability is confirmed, suggest escalation chains.
Maps vuln_type → ordered list of next steps.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ChainStep:
    description: str
    tool_hint: str = ""
    knowledge_ref: str = ""  # reference to knowledge file


# ── Attack Chain Definitions ──

ATTACK_CHAINS: dict[str, list[ChainStep]] = {
    "sqli": [
        ChainStep("Enumerate database type and version", "sqlmap", "attack_chains/sqli_to_rce.md"),
        ChainStep("Dump table names and schemas", "sqlmap"),
        ChainStep("Extract credentials from user tables", "sqlmap"),
        ChainStep("Attempt file read via LOAD_FILE()", "sqlmap"),
        ChainStep("Attempt OS command execution via INTO OUTFILE or xp_cmdshell", "sqlmap", "attack_chains/sqli_to_rce.md"),
        ChainStep("If file write works, drop a web shell", "http"),
        ChainStep("Escalate to reverse shell", "run_command"),
    ],
    "xss": [
        ChainStep("Confirm reflected/stored/DOM XSS", "browser_fill"),
        ChainStep("Test cookie theft payload", "browser_execute_js"),
        ChainStep("Test session hijacking", "http"),
        ChainStep("Attempt DOM manipulation for phishing PoC", "browser_execute_js"),
    ],
    "lfi": [
        ChainStep("Read /etc/passwd for user enumeration", "http", "attack_chains/lfi_to_rce.md"),
        ChainStep("Attempt /proc/self/environ for secret leaking", "http"),
        ChainStep("Try log poisoning (inject PHP into User-Agent, access log)", "http", "attack_chains/lfi_to_rce.md"),
        ChainStep("Read application config files (wp-config.php, .env)", "http"),
        ChainStep("Try PHP filter chains for RCE", "http", "attack_chains/lfi_to_rce.md"),
    ],
    "rfi": [
        ChainStep("Host a PHP shell on attacker server", "run_command"),
        ChainStep("Include remote file via vulnerable param", "http"),
        ChainStep("Verify code execution", "http"),
    ],
    "ssti": [
        ChainStep("Identify template engine ({{7*7}}, ${7*7}, <%=7*7%>)", "http", "attack_chains/ssti_to_rce.md"),
        ChainStep("Use engine-specific payload for RCE", "http", "attack_chains/ssti_to_rce.md"),
        ChainStep("Attempt reverse shell via SSTI", "http"),
    ],
    "file_upload": [
        ChainStep("Test allowed extensions (.php, .phtml, .php5)", "http", "attack_chains/upload_to_rce.md"),
        ChainStep("Try double extension bypass (shell.php.jpg)", "http"),
        ChainStep("Try content-type manipulation", "http"),
        ChainStep("Try null byte injection (shell.php%00.jpg)", "http"),
        ChainStep("Upload web shell and access it", "http", "attack_chains/upload_to_rce.md"),
    ],
    "ssrf": [
        ChainStep("Test internal port scanning via SSRF", "http"),
        ChainStep("Access cloud metadata (169.254.169.254)", "http"),
        ChainStep("Try file:// protocol for local file read", "http"),
        ChainStep("Try gopher:// for internal service interaction", "http"),
    ],
    "auth_bypass": [
        ChainStep("Enumerate valid usernames", "http"),
        ChainStep("Test common credentials", "http"),
        ChainStep("Test JWT manipulation if token-based", "http", "web/payloads_jwt.md"),
        ChainStep("Test IDOR on authenticated endpoints", "http"),
        ChainStep("Attempt privilege escalation to admin", "http"),
    ],
    "command_injection": [
        ChainStep("Identify injection type (direct, blind)", "http", "payloads/command_injection.md"),
        ChainStep("Exfiltrate data via injection", "http"),
        ChainStep("Establish reverse shell", "http", "payloads/command_injection.md"),
    ],
    "deserialization": [
        ChainStep("Identify serialization format (Java, PHP, Python, .NET)", "http", "web/payloads_deserialization.md"),
        ChainStep("Generate appropriate payload", "run_command"),
        ChainStep("Achieve RCE via deserialization", "http"),
    ],
    "xxe": [
        ChainStep("Test basic XXE for file read", "http", "web/payloads_xxe.md"),
        ChainStep("Try OOB XXE for blind exfiltration", "http"),
        ChainStep("Attempt SSRF via XXE", "http"),
    ],
    "nosql_injection": [
        ChainStep("Test NoSQL injection with operator payloads", "http", "web/payloads_nosql.md"),
        ChainStep("Extract data with $regex enumeration", "http"),
        ChainStep("Attempt authentication bypass", "http"),
    ],
    "ldap_injection": [
        ChainStep("Test LDAP injection with wildcard payloads", "http", "web/payloads_ldap.md"),
        ChainStep("Enumerate LDAP tree", "http"),
        ChainStep("Attempt authentication bypass", "http"),
    ],
    "graphql": [
        ChainStep("Run introspection query", "http", "web/payloads_graphql.md"),
        ChainStep("Enumerate all types and fields", "http"),
        ChainStep("Test for authorization bypass on mutations", "http"),
    ],
}


def get_escalation_chain(vuln_type: str) -> list[ChainStep] | None:
    """
    Get the escalation chain for a vulnerability type.
    Returns None if no chain exists.
    """
    # Normalize the vuln type
    normalized = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")

    # Direct match
    if normalized in ATTACK_CHAINS:
        return ATTACK_CHAINS[normalized]

    # Partial match
    for key, chain in ATTACK_CHAINS.items():
        if key in normalized or normalized in key:
            return chain

    # Keyword match
    keyword_map = {
        "sql": "sqli",
        "injection": "command_injection",
        "template": "ssti",
        "upload": "file_upload",
        "cross_site": "xss",
        "cross-site": "xss",
        "local_file": "lfi",
        "remote_file": "rfi",
        "server_side_request": "ssrf",
        "xml": "xxe",
        "deseriali": "deserialization",
    }
    for keyword, chain_key in keyword_map.items():
        if keyword in normalized:
            return ATTACK_CHAINS.get(chain_key)

    return None


def format_chain_for_prompt(vuln_type: str) -> str:
    """Format an escalation chain as prompt text."""
    chain = get_escalation_chain(vuln_type)
    if not chain:
        return ""

    lines = [f"\n## Escalation Chain: {vuln_type}\n"]
    for i, step in enumerate(chain, 1):
        lines.append(f"  {i}. {step.description}")
        if step.tool_hint:
            lines.append(f"     → use: {step.tool_hint}")
    return "\n".join(lines)
