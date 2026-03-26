"""Standard response envelope for scanner outputs.

All scanner results can use ``wrap_result()`` to produce consistent output
that helps the host LLM parse results quickly.
"""

from __future__ import annotations

import time
from typing import Any

# Maps vulnerability types to recommended follow-up actions.
_NEXT_STEPS: dict[str, list[str]] = {
    "sql_injection": [
        "Run injection_test with types=sql on related endpoints",
        "Use http_request for UNION extraction (ORDER BY -> string column -> schema -> data)",
        "Check plan(action='chain') for SQLi->credential dump->privilege escalation",
    ],
    "xss": [
        "Test stored XSS on write endpoints (feedback, reviews, profiles)",
        "Check for DOM XSS on SPA hash routes via js_analyze",
        "Chain with CSRF for session hijacking",
    ],
    "nosql_injection": [
        "Test with different NoSQL operators ($gt, $ne, $regex)",
        "Extract data via boolean-based enumeration with http_request",
    ],
    "ssti": [
        "Identify template engine via kb_search(query='ssti identification')",
        "Escalate to RCE with engine-specific payloads",
    ],
    "command_injection": [
        "Confirm with out-of-band via oob(action='setup') + blind payload",
        "Escalate to reverse shell or data exfiltration",
    ],
    "idor": [
        "Test adjacent IDs (+1/-1) on the same endpoint",
        "Test other resource endpoints with the same pattern",
        "Chain with auth_test to verify JWT-based access control",
    ],
    "csrf": [
        "Chain with XSS for automated CSRF exploitation",
        "Test state-changing endpoints: password change, email update, transfers",
    ],
    "cors": [
        "Verify if credentials are exposed (Access-Control-Allow-Credentials: true)",
        "Chain with XSS for cross-origin data theft",
    ],
    "ssrf": [
        "Probe cloud metadata: 169.254.169.254/latest/meta-data/iam/",
        "Test internal service discovery on common ports",
    ],
    "lfi": [
        "Escalate with null byte bypass, double encoding, php://filter wrappers",
        "Chain LFI->log poisoning->RCE via access log injection",
    ],
    "xxe": [
        "Test blind XXE with oob(action='setup') for out-of-band exfiltration",
        "Extract sensitive files: /etc/passwd, application config, credentials",
    ],
    "auth_bypass": [
        "Capture session token and run plan(action='post_auth')",
        "Test all authenticated endpoints with obtained token",
    ],
    "jwt_weak": [
        "Forge admin token with cracked secret or alg:none",
        "Run access_control_test with forged token for privilege escalation",
    ],
    "open_redirect": [
        "Chain with OAuth flows for token theft",
        "Test for SSRF via redirect parameter",
    ],
}

_GENERIC_NEXT_STEPS = [
    "Save confirmed findings with save_finding()",
    "Check plan(action='chain') for escalation opportunities",
]


def _build_summary(tool: str, target: str, vulns: list[dict[str, Any]]) -> str:
    """Build a one-line summary from findings."""
    if not vulns:
        return f"No vulnerabilities found on {target}"

    count = len(vulns)
    types = set()
    max_severity = "info"
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for v in vulns:
        vtype = v.get("type", v.get("subtype", "unknown"))
        types.add(vtype)
        sev = str(v.get("severity", "info")).lower()
        if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
            max_severity = sev

    type_str = ", ".join(sorted(types)[:3])
    if len(types) > 3:
        type_str += f" +{len(types) - 3} more"

    return f"{count} vuln(s) found ({type_str}), max severity: {max_severity}"


def _build_next_steps(vulns: list[dict[str, Any]]) -> list[str]:
    """Build next_steps from vulnerability types found."""
    if not vulns:
        return []

    steps: list[str] = []
    seen_types: set[str] = set()

    for v in vulns:
        vtype = str(v.get("type", v.get("subtype", ""))).lower().replace("-", "_").replace(" ", "_")
        if vtype in seen_types:
            continue
        seen_types.add(vtype)

        # Try exact match, then partial match
        matched = _NEXT_STEPS.get(vtype)
        if not matched:
            for key, val in _NEXT_STEPS.items():
                if key in vtype or vtype in key:
                    matched = val
                    break

        if matched:
            steps.extend(matched)

    if not steps:
        steps = list(_GENERIC_NEXT_STEPS)

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for s in steps:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    return unique[:5]  # Cap at 5 to avoid bloat


def wrap_result(
    tool: str,
    target: str,
    result: dict[str, Any],
    start_time: float | None = None,
) -> dict[str, Any]:
    """Wrap a scanner result dict in a standard envelope.

    Adds: status, tool, target, duration_ms, summary, next_steps fields.
    Preserves all existing fields from result.

    Args:
        tool: Tool name (e.g., "injection_test", "xss_test").
        target: Target URL that was scanned.
        result: Raw result dict from scanner.
        start_time: monotonic start time for duration calculation.
    """
    vulns = result.get("vulnerabilities", result.get("findings", []))
    has_error = "error" in result

    envelope: dict[str, Any] = {
        "status": "error" if has_error else ("ok" if not vulns else "findings"),
        "tool": tool,
        "target": target,
    }

    if start_time is not None:
        envelope["duration_ms"] = round((time.monotonic() - start_time) * 1000, 1)

    # Merge all result fields (result fields take precedence)
    envelope.update(result)

    # Add summary and next_steps (don't override if result already has them)
    if "summary" not in envelope:
        envelope["summary"] = _build_summary(tool, target, vulns) if not has_error else result.get("error", "Error")
    if "next_steps" not in envelope:
        envelope["next_steps"] = _build_next_steps(vulns)

    return envelope
