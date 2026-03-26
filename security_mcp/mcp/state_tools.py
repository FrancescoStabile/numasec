"""MCP state management and reporting tools (v2.0).

Four tools for the host LLM to manage assessment state:

create_session
    Must be called first, before any save_finding call.
    Returns a session_id that scopes all subsequent findings.

save_finding
    Save a security finding. session_id is required.
    Auto-enriches with CVSS score, OWASP category, and CWE details.

get_findings
    Retrieve all findings for a session, optionally filtered by severity.

generate_report
    Generate a SARIF, Markdown, or JSON report from saved findings.

Session storage is delegated to McpSessionStore (singleton in _singletons.py),
which persists all state to SQLite via CheckpointStore.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)


def _check_session_rate(session_id: str) -> None:
    """Check per-session rate limit; raise RateLimitExceeded if exceeded."""
    from security_mcp.mcp._singletons import get_rate_limiter
    from security_mcp.mcp.server import RateLimitExceeded

    limiter = get_rate_limiter()
    if not limiter.check(session_id=session_id):
        raise RateLimitExceeded(
            f"Rate limit exceeded for session '{session_id}'. "
            "Too many concurrent calls — try again shortly."
        )
    limiter.acquire(session_id=session_id)


def _release_session_rate(session_id: str) -> None:
    """Release per-session concurrency slot."""
    from security_mcp.mcp._singletons import get_rate_limiter

    get_rate_limiter().release(session_id=session_id)


def register(mcp: Any) -> None:
    """Register state management and reporting tools with FastMCP."""

    @mcp.tool(
        name="create_session",
        description=(
            "Create a new security assessment session. "
            "Call this FIRST before any save_finding calls. "
            "Returns a session_id that must be passed to save_finding, "
            "get_findings, and generate_report."
        ),
    )
    async def create_session(target: str) -> str:
        """Create a new assessment session.

        Args:
            target: Target URL or hostname being assessed (e.g., "https://example.com").

        Returns:
            JSON with session_id ("mcp-{8hex}") and instructions for next steps.
        """
        from security_mcp.mcp._singletons import get_mcp_session_store

        store = get_mcp_session_store()
        session_id = await store.create(target=target)
        logger.info("MCP session created: %s (target=%s)", session_id, target)
        return json.dumps(
            {
                "session_id": session_id,
                "target": target,
                "status": "active",
                "message": (
                    f"Session created. Use session_id='{session_id}' in all "
                    "save_finding, get_findings, and generate_report calls."
                ),
            },
            indent=2,
        )

    @mcp.tool(
        name="save_finding",
        description=(
            "Save a security finding discovered during testing. "
            "Requires a session_id from create_session. "
            "Auto-enriches with CVSS score, OWASP category, and CWE details. "
            "Returns the finding ID for reference."
        ),
    )
    async def save_finding(
        session_id: str,
        title: str,
        severity: Literal["critical", "high", "medium", "low", "info"],
        url: str = "",
        cwe: str = "",
        evidence: str = "",
        description: str = "",
        parameter: str = "",
        payload: str = "",
        tool_used: str = "",
        related_to: str = "",
        chain_id: str = "",
    ) -> str:
        """Save a security finding.

        Args:
            session_id:  Session ID from create_session (required).
            title:       Finding title (e.g., "SQL Injection in login form").
            severity:    Severity level: critical, high, medium, low, info.
            url:         Affected URL.
            cwe:         CWE identifier (e.g., "CWE-89").
            evidence:    Evidence string from testing.
            description: Detailed description.
            parameter:   Vulnerable parameter name.
            payload:     Payload that triggered the finding.
            tool_used:   Name of the tool that discovered the finding (e.g., "sqli_test").
            related_to:  Comma-separated finding IDs this finding is related to (attack chain).
            chain_id:    Attack chain identifier grouping related findings.
        """
        from security_mcp.mcp._singletons import get_mcp_session_store
        from security_mcp.models.enums import Severity
        from security_mcp.models.finding import Finding

        _check_session_rate(session_id)
        try:
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            sev = sev_map.get(severity.lower(), Severity.INFO)

            related_ids = [r.strip() for r in related_to.split(",") if r.strip()] if related_to else []
            finding = Finding(
                title=title,
                severity=sev,
                url=url,
                cwe_id=cwe,
                evidence=evidence,
                description=description or title,
                parameter=parameter,
                payload=payload,
                tool_used=tool_used,
                related_finding_ids=related_ids,
                chain_id=chain_id,
            )

            from security_mcp.standards import enrich_finding

            enrich_finding(finding)

            store = get_mcp_session_store()
            try:
                finding_id = await store.add_finding(session_id, finding)
            except KeyError:
                return json.dumps(
                    {"error": f"Session not found: {session_id}. Call create_session first."},
                    indent=2,
                )
            logger.info("Finding saved: %s [%s] in session %s", title, severity, session_id)

            meta = await store.get_session(session_id)
            total = meta["finding_count"] if meta else 1

            return json.dumps(
                {
                    "finding_id": finding_id,
                    "session_id": session_id,
                    "severity": sev.value,
                    "total_findings": total,
                    "enriched": {
                        "cwe_id": finding.cwe_id,
                        "cvss_score": finding.cvss_score,
                        "cvss_vector": finding.cvss_vector,
                        "owasp_category": finding.owasp_category,
                        "attack_technique": finding.attack_technique,
                    },
                },
                indent=2,
            )
        finally:
            _release_session_rate(session_id)

    @mcp.tool(
        name="get_findings",
        description=(
            "Get all security findings for a session, optionally filtered by severity. "
            "Returns findings with summary statistics."
        ),
    )
    async def get_findings(
        session_id: str,
        severity_filter: str = "",
    ) -> str:
        """Get findings for a session.

        Args:
            session_id:      Session ID from create_session (required).
            severity_filter: Filter by severity: critical, high, medium, low, info.
                             Leave empty for all findings.
        """
        from security_mcp.mcp._singletons import get_mcp_session_store

        _check_session_rate(session_id)
        try:
            store = get_mcp_session_store()

            try:
                all_findings = await store.get_findings(session_id)
            except KeyError:
                return json.dumps(
                    {"error": f"Session not found: {session_id}", "findings": [], "summary": {}},
                    indent=2,
                )

            filtered = (
                [f for f in all_findings if f.severity.value == severity_filter.lower()]
                if severity_filter
                else all_findings
            )

            severity_counts: dict[str, int] = {}
            for f in all_findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            return json.dumps(
                {
                    "session_id": session_id,
                    "findings": [
                        {
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                            "url": f.url,
                            "cwe_id": f.cwe_id,
                            "evidence": (f.evidence or "")[:500],
                            "confidence": f.confidence,
                        }
                        for f in filtered
                    ],
                    "summary": {
                        "total": len(all_findings),
                        "filtered": len(filtered),
                        **severity_counts,
                    },
                },
                indent=2,
                default=str,
            )
        finally:
            _release_session_rate(session_id)

    @mcp.tool(
        name="generate_report",
        description=(
            "Generate a security assessment report from saved findings. "
            "Supports SARIF (for CI/CD), Markdown, and JSON formats."
        ),
    )
    async def generate_report(
        session_id: str,
        format: Literal["sarif", "markdown", "json"] = "sarif",
        previous_session_id: str = "",
    ) -> str:
        """Generate a report from findings.

        Args:
            session_id:          Session ID from create_session (required).
            format:              Report format: sarif, markdown, json.
            previous_session_id: Compare against a previous session for delta reporting.
        """
        from security_mcp.mcp._singletons import get_mcp_session_store

        _check_session_rate(session_id)
        try:
            store = get_mcp_session_store()

            try:
                findings = await store.get_findings(session_id)
            except KeyError:
                return json.dumps({"error": f"Session not found: {session_id}"}, indent=2)

            meta = await store.get_session(session_id)
            target = meta.get("target", "") if meta else ""

            # Delta reporting
            delta: dict[str, Any] | None = None
            if previous_session_id:
                try:
                    prev_findings = await store.get_findings(previous_session_id)
                    curr_fps = {f.fingerprint() for f in findings}
                    prev_fps = {f.fingerprint() for f in prev_findings}
                    new_ids = curr_fps - prev_fps
                    fixed_ids = prev_fps - curr_fps
                    persistent_ids = curr_fps & prev_fps

                    from security_mcp.reporting import calculate_risk_score

                    curr_score = calculate_risk_score(findings)
                    prev_score = calculate_risk_score(prev_findings)

                    delta = {
                        "previous_session_id": previous_session_id,
                        "new_findings": len(new_ids),
                        "fixed_findings": len(fixed_ids),
                        "persistent_findings": len(persistent_ids),
                        "risk_score_current": curr_score,
                        "risk_score_previous": prev_score,
                        "risk_trend": curr_score - prev_score,
                    }
                except KeyError:
                    delta = {"error": f"Previous session not found: {previous_session_id}"}

            fmt = format.lower()

            if fmt == "sarif":
                from security_mcp.reporting.sarif import generate_sarif_report

                report = generate_sarif_report(findings)
                result_obj: dict[str, Any] = {"format": "sarif", "findings_count": len(findings), "content": report}
                if delta:
                    result_obj["delta"] = delta
                return json.dumps(result_obj, indent=2, default=str)

            if fmt == "markdown":
                from security_mcp.reporting.markdown import generate_markdown_report

                report = generate_markdown_report(findings, target=target)
                result_obj = {"format": "markdown", "findings_count": len(findings), "content": report}
                if delta:
                    result_obj["delta"] = delta
                return json.dumps(result_obj, indent=2, default=str)

            # Default: json
            from security_mcp.reporting import build_executive_summary

            json_report: dict[str, Any] = {
                "format": "json",
                "findings_count": len(findings),
                "session_id": session_id,
                "target": target,
                "executive_summary": build_executive_summary(findings, target=target),
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        "url": f.url,
                        "cwe_id": f.cwe_id,
                        "evidence": f.evidence,
                        "description": f.description,
                        "parameter": f.parameter,
                        "cvss_score": f.cvss_score,
                        "owasp_category": f.owasp_category,
                        "confidence": f.confidence,
                    }
                    for f in findings
                ],
            }
            if delta:
                json_report["delta"] = delta
            return json.dumps(json_report, indent=2, default=str)
        finally:
            _release_session_rate(session_id)

    @mcp.tool(
        name="run_scanner_batch",
        description=(
            "Run multiple scanners in parallel for faster vulnerability testing. "
            "Pass a JSON array of {tool, params} objects. Each scanner runs "
            "concurrently with a 2-minute timeout. Returns per-tool results "
            "and total duration. Use this instead of calling scanners sequentially "
            "when testing multiple endpoints or vulnerability classes."
        ),
    )
    async def run_scanner_batch(session_id: str, tasks: str) -> str:
        """Run multiple scanners in parallel.

        Args:
            session_id: Session ID for rate limiting.
            tasks:      JSON array of objects: [{"tool": "sqli_test", "params": {"url": "..."}}, ...]
        """
        import asyncio
        import time as _time

        from security_mcp.mcp._singletons import get_tool_registry

        _check_session_rate(session_id)
        try:
            try:
                task_list = json.loads(tasks)
            except json.JSONDecodeError as exc:
                return json.dumps({"error": f"Invalid JSON: {exc}"}, indent=2)

            if not isinstance(task_list, list):
                return json.dumps({"error": "tasks must be a JSON array"}, indent=2)

            registry = get_tool_registry()
            batch_start = _time.monotonic()

            async def _run_one(task: dict[str, Any]) -> dict[str, Any]:
                tool = task.get("tool", "")
                params = task.get("params", {})
                start = _time.monotonic()
                try:
                    result = await asyncio.wait_for(
                        registry.call(tool, **params),
                        timeout=120.0,
                    )
                    return {
                        "tool": tool,
                        "status": "ok",
                        "result": result if isinstance(result, str) else json.dumps(result, default=str),
                        "duration_ms": round((_time.monotonic() - start) * 1000, 1),
                    }
                except asyncio.TimeoutError:
                    return {"tool": tool, "status": "timeout", "duration_ms": 120000}
                except Exception as exc:
                    return {
                        "tool": tool,
                        "status": "error",
                        "error": str(exc),
                        "duration_ms": round((_time.monotonic() - start) * 1000, 1),
                    }

            results = await asyncio.gather(*[_run_one(t) for t in task_list])
            total_ms = round((_time.monotonic() - batch_start) * 1000, 1)

            ok_count = sum(1 for r in results if r["status"] == "ok")
            logger.info(
                "Scanner batch complete: %d/%d succeeded in %.0fms",
                ok_count, len(results), total_ms,
            )

            return json.dumps(
                {
                    "session_id": session_id,
                    "total_tasks": len(results),
                    "succeeded": ok_count,
                    "total_duration_ms": total_ms,
                    "results": list(results),
                },
                indent=2,
                default=str,
            )
        finally:
            _release_session_rate(session_id)

    @mcp.tool(
        name="relay_credentials",
        description=(
            "Store a discovered credential or authentication token for use in "
            "subsequent authenticated testing. Call this after auth_test discovers "
            "default credentials, cracks a JWT secret, or extracts a session token. "
            "Stored tokens are available to get_auth_retest_plan for post-auth testing."
        ),
    )
    async def relay_credentials(
        session_id: str,
        credential_type: Literal["bearer", "cookie", "api_key", "password"] = "bearer",
        value: str = "",
        source: str = "",
        username: str = "",
        password: str = "",
    ) -> str:
        """Store discovered credentials for authenticated testing.

        Args:
            session_id:      Session ID from create_session (required).
            credential_type: Type of credential: bearer, cookie, api_key, password.
            value:           Token/cookie value (for bearer, cookie, api_key types).
            source:          Tool that discovered the credential (e.g., "auth_test").
            username:        Username (for password type).
            password:        Password (for password type).
        """
        from security_mcp.mcp._singletons import get_mcp_session_store

        _check_session_rate(session_id)
        try:
            store = get_mcp_session_store()
            try:
                await store.get_session(session_id)
            except KeyError:
                return json.dumps(
                    {"error": f"Session not found: {session_id}. Call create_session first."},
                    indent=2,
                )

            stored_item: dict[str, str] = {"type": credential_type, "source": source}
            if credential_type == "password":
                stored_item["username"] = username
                stored_item["password"] = password
            else:
                stored_item["value"] = value

            logger.info("Credential relayed: type=%s source=%s session=%s", credential_type, source, session_id)
            await store.add_event(session_id, "credential_relay", stored_item)

            auth_header: dict[str, str] = {}
            if credential_type == "bearer" and value:
                auth_header = {"Authorization": f"Bearer {value}"}
            elif credential_type == "cookie" and value:
                auth_header = {"Cookie": value}
            elif credential_type == "api_key" and value:
                auth_header = {"X-API-Key": value}

            return json.dumps(
                {
                    "status": "stored",
                    "session_id": session_id,
                    "credential_type": credential_type,
                    "source": source,
                    "auth_header": auth_header,
                    "message": (
                        "Credential stored. Pass the auth_header to subsequent tool calls "
                        "for authenticated testing. Call get_auth_retest_plan for a full "
                        "post-auth testing protocol."
                    ),
                },
                indent=2,
            )
        finally:
            _release_session_rate(session_id)
