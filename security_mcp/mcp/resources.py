"""MCP resources — findings, reports, and knowledge base.

Resources
---------
security_mcp://sessions/{session_id}/findings
    Current findings for a session (active or completed).

security_mcp://sessions/{session_id}/report/{format}
    Full report in sarif, markdown, html, or json format.

security_mcp://kb/{topic}
    Knowledge base article for a security topic (e.g., "sqli", "xss", "ssrf").
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("security_mcp.mcp.resources")


def register_resources(mcp: Any) -> None:
    """Register MCP resources for findings, reports, and knowledge base."""

    @mcp.resource("security_mcp://sessions/{session_id}/findings")
    async def get_findings(session_id: str) -> str:
        """Assessment findings for a session."""
        from security_mcp.mcp._singletons import get_mcp_session_store

        store = get_mcp_session_store()
        meta = await store.get_session(session_id)

        if meta is None:
            return json.dumps({"error": f"Session {session_id} not found"})

        try:
            findings = await store.get_findings(session_id)
        except KeyError:
            findings = []

        return json.dumps(
            {
                "session_id": session_id,
                "status": meta.get("status", "active"),
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
                    for f in findings
                ],
                "count": len(findings),
            },
            indent=2,
            default=str,
        )

    @mcp.resource("security_mcp://sessions/{session_id}/report/{format}")
    async def get_report(session_id: str, format: str = "sarif") -> str:
        """Report in sarif, html, json, or markdown format."""
        from security_mcp.mcp._singletons import get_mcp_session_store

        store = get_mcp_session_store()
        meta = await store.get_session(session_id)

        if meta is None:
            return json.dumps({"error": f"Session {session_id} not found"})

        try:
            findings = await store.get_findings(session_id)
        except KeyError:
            findings = []

        target = meta.get("target", "")
        fmt = format.lower()

        if fmt == "sarif":
            from security_mcp.reporting.sarif import generate_sarif_report

            return generate_sarif_report(findings)

        if fmt == "markdown":
            from security_mcp.reporting.markdown import generate_markdown_report

            return generate_markdown_report(findings, target=target)

        if fmt == "html":
            from security_mcp.reporting.html import generate_html_report

            return generate_html_report(findings, target=target)

        # Default: json
        return json.dumps(
            {
                "session_id": session_id,
                "format": "json",
                "target": target,
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        "url": f.url,
                        "cwe_id": f.cwe_id,
                        "evidence": f.evidence,
                        "description": f.description,
                    }
                    for f in findings
                ],
            },
            indent=2,
            default=str,
        )

    @mcp.resource("security_mcp://kb/{topic}")
    async def get_kb_article(topic: str) -> str:
        """Knowledge base article for a security topic.

        Topics: sqli, xss, ssrf, lfi, ssti, xxe, csrf, cors, idor, nosql,
                open_redirect, auth, jwt, rce, path_traversal, xxe
        """
        from security_mcp.mcp._singletons import get_kb

        kb = get_kb()
        results = kb.search(topic, top_k=3)

        if not results:
            return json.dumps({"error": f"No KB articles found for topic: {topic}"})

        return json.dumps(
            {
                "topic": topic,
                "articles": [
                    {
                        "content": chunk.content if hasattr(chunk, "content") else str(chunk),
                        "source": getattr(chunk, "source", ""),
                    }
                    for chunk in results
                ],
            },
            indent=2,
        )
