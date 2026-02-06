"""
NumaSec — Reflection Engine

Analyzes tool results and generates strategic insights.
Runs after each tool call to update hypotheses and guide next action.
"""

from __future__ import annotations

from numasec.target_profile import TargetProfile, VulnHypothesis


def reflect_on_result(
    tool_name: str,
    tool_args: dict,
    result: str,
    profile: TargetProfile,
) -> str:
    """
    Generate a reflection summary after a tool execution.

    Returns a concise analysis string that gets injected as an assistant
    thought, guiding the LLM's next decision.
    """
    lines: list[str] = []

    # ── Tool-specific reflection ──
    if tool_name == "nmap":
        _reflect_nmap(result, profile, lines)
    elif tool_name in ("http_request", "http"):
        _reflect_http(result, tool_args, profile, lines)
    elif tool_name == "nuclei":
        _reflect_nuclei(result, profile, lines)
    elif tool_name == "sqlmap":
        _reflect_sqlmap(result, profile, lines)
    elif tool_name in ("ffuf", "gobuster"):
        _reflect_ffuf(result, profile, lines)
    elif tool_name in ("browser_navigate", "browser_click", "browser_fill"):
        _reflect_browser(result, tool_args, profile, lines)
    elif tool_name == "run_command":
        _reflect_command(result, tool_args, profile, lines)

    # ── General intelligence ──
    untested = profile.get_untested_hypotheses()
    if untested:
        top3 = sorted(untested, key=lambda h: _confidence_score(h), reverse=True)[:3]
        lines.append("\n**Top untested hypotheses:**")
        for h in top3:
            lines.append(f"  - [{h.confidence}] {h.vuln_type}: {h.evidence}")

    confirmed = profile.get_confirmed_vulns()
    if confirmed:
        lines.append(f"\n**{len(confirmed)} confirmed vulnerabilities** — consider exploitation or escalation.")

    if not lines:
        return ""

    return "\n".join(lines)


def _confidence_score(h: VulnHypothesis) -> float:
    """Convert confidence to sortable score (0.0-1.0 float)."""
    return h.confidence


def _reflect_nmap(result: str, profile: TargetProfile, lines: list[str]):
    """Reflect on nmap results."""
    open_ports = profile.get_open_ports()
    web_ports = profile.get_web_ports()

    if open_ports:
        lines.append(f"**Scan complete**: {len(open_ports)} open ports found: {', '.join(str(p) for p in open_ports[:15])}")
    else:
        lines.append("**Scan complete**: No open ports found — verify target is up, try different scan techniques.")

    if web_ports:
        lines.append(f"**Web services** on ports: {', '.join(str(p) for p in web_ports)} — enumerate these next.")

    # Check for interesting services
    for port in profile.ports:
        service = port.service.lower() if port.service else ""
        if "ssh" in service:
            lines.append(f"  SSH on :{port.number} — note version for CVE check.")
        elif "ftp" in service:
            lines.append(f"  FTP on :{port.number} — test anonymous login.")
        elif "smb" in service or "microsoft-ds" in service:
            lines.append(f"  SMB on :{port.number} — enumerate shares with smbclient.")
        elif "mysql" in service or "postgres" in service:
            lines.append(f"  Database on :{port.number} ({service}) — try default creds.")


def _reflect_http(result: str, args: dict, profile: TargetProfile, lines: list[str]):
    """Reflect on HTTP request results."""
    url = args.get("url", "")
    result_lower = result.lower()

    # Detect interesting responses
    if "200" in result[:50] or '"status": 200' in result[:100]:
        if any(kw in url.lower() for kw in [".env", ".git", "admin", "config", "backup", ".bak"]):
            # Guard against SPA catch-all false positives
            if profile.spa_shell_title and profile.spa_shell_title.lower() in result_lower:
                lines.append(
                    f"**\u26a0 SPA catch-all at {url}** \u2014 response contains the app shell "
                    f"title '{profile.spa_shell_title}', NOT the actual file. "
                    f"This is NOT a real exposure. Do NOT register as a finding."
                )
            else:
                lines.append(f"**Sensitive file accessible**: {url} \u2014 extract contents!")

    if "401" in result[:50] or "403" in result[:50]:
        lines.append(f"**Access restricted** at {url} — try bypass techniques (header manipulation, path traversal).")

    if "error" in result_lower and any(kw in result_lower for kw in ["sql", "syntax", "mysql", "postgres", "oracle"]):
        lines.append(f"**Possible SQL error** at {url} — test injection carefully.")

    if any(kw in result_lower for kw in ["{{", "jinja", "twig", "freemarker", "${", "<%"]):
        lines.append(f"**Template syntax detected** at {url} — test SSTI payloads.")

    if "upload" in result_lower or "file" in result_lower and "multipart" in result_lower:
        lines.append(f"**File upload detected** at {url} — test for unrestricted upload.")

    if len(result) > 5000 and not lines:
        lines.append(f"**Large response** ({len(result)} chars) from {url} — may contain useful data.")


def _reflect_nuclei(result: str, profile: TargetProfile, lines: list[str]):
    """Reflect on nuclei results."""
    confirmed = profile.get_confirmed_vulns()
    recent_confirmed = [h for h in confirmed if h.vuln_type and "nuclei" in (h.evidence or "").lower()]

    if "No vulnerabilities found" in result or not result.strip():
        lines.append("**Nuclei found nothing** — try manual testing for logic flaws and custom vulns.")
    else:
        lines.append(f"**Nuclei findings**: check each for exploitability and false positives.")


def _reflect_sqlmap(result: str, profile: TargetProfile, lines: list[str]):
    """Reflect on sqlmap results."""
    result_lower = result.lower()

    if "is vulnerable" in result_lower or "injectable" in result_lower:
        lines.append("**SQLi CONFIRMED** — extract database schema, dump interesting tables.")
    elif "not injectable" in result_lower:
        lines.append("**SQLi not found** at this endpoint — try other parameters or techniques.")
    elif "all tested parameters do not appear" in result_lower:
        lines.append("**No injectable params** — move to next endpoint.")


def _reflect_ffuf(result: str, profile: TargetProfile, lines: list[str]):
    """Reflect on ffuf/directory fuzzing results."""
    interesting = profile.get_interesting_endpoints()
    if interesting:
        lines.append(f"**Fuzzing found {len(interesting)} interesting endpoints** — investigate each:")
        for ep in interesting[:5]:
            lines.append(f"  - {ep.url} [{ep.status_code}] ({ep.method})")


def _reflect_browser(result: str, args: dict, profile: TargetProfile, lines: list[str]):
    """Reflect on browser interaction results."""
    url = args.get("url", "")

    if "alert" in result.lower() or "xss" in result.lower():
        lines.append(f"**Possible XSS** at {url} — verify and document.")

    if "login" in result.lower() or "password" in result.lower():
        lines.append(f"**Login form found** — test default/common credentials.")


def _reflect_command(result: str, args: dict, profile: TargetProfile, lines: list[str]):
    """Reflect on raw command results."""
    cmd = args.get("command", "")
    result_lower = result.lower()

    if "permission denied" in result_lower:
        lines.append("**Permission denied** — try with different privileges or techniques.")
    elif "command not found" in result_lower or "not found" in result_lower:
        lines.append(f"**Command not available** — install it or use an alternative.")
    elif "root" in result_lower and ("id" in cmd or "whoami" in cmd):
        lines.append("**ROOT ACCESS** — document this as critical finding!")
