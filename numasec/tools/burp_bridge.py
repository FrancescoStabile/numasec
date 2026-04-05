"""Burp Suite XML import/export bridge.

Enables bidirectional exchange between numasec and Burp Suite:
- Import Burp XML issue exports into numasec findings
- Export numasec findings to Burp-compatible XML
- Import Burp sitemaps to discover endpoints for further testing
"""

from __future__ import annotations

import base64
import json
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any

from numasec.scanners._envelope import wrap_result

# ---------------------------------------------------------------------------
# Severity / confidence mappings
# ---------------------------------------------------------------------------

_BURP_SEVERITY_TO_NUMASEC: dict[str, str] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
}

_NUMASEC_SEVERITY_TO_BURP: dict[str, str] = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Information",
}

_BURP_CONFIDENCE_TO_FLOAT: dict[str, float] = {
    "certain": 1.0,
    "firm": 0.8,
    "tentative": 0.5,
}

_FLOAT_CONFIDENCE_TO_BURP: list[tuple[float, str]] = [
    (0.9, "Certain"),
    (0.6, "Firm"),
    (0.0, "Tentative"),
]


def _confidence_to_burp(value: float) -> str:
    """Map a 0.0–1.0 confidence float to the closest Burp label."""
    for threshold, label in _FLOAT_CONFIDENCE_TO_BURP:
        if value >= threshold:
            return label
    return "Tentative"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class BurpIssue:
    """A single issue parsed from Burp Suite XML export."""

    name: str
    host: str
    path: str
    severity: str  # High, Medium, Low, Information
    confidence: str  # Certain, Firm, Tentative
    detail: str = ""
    background: str = ""
    remediation: str = ""
    request: bytes = field(default_factory=bytes, repr=False)
    response: bytes = field(default_factory=bytes, repr=False)
    issue_type: str = ""

    # -- conversion helpers --------------------------------------------------

    def to_numasec_finding(self) -> dict[str, Any]:
        """Convert to a dict compatible with ``save_finding`` / ``Finding``."""
        sev = _BURP_SEVERITY_TO_NUMASEC.get(self.severity.lower(), "info")
        conf = _BURP_CONFIDENCE_TO_FLOAT.get(self.confidence.lower(), 0.5)
        url = self.host.rstrip("/") + "/" + self.path.lstrip("/") if self.path else self.host
        evidence_parts: list[str] = []
        if self.detail:
            evidence_parts.append(self.detail)
        if self.request:
            evidence_parts.append(f"Request:\n{self.request.decode('utf-8', errors='replace')}")
        if self.response:
            evidence_parts.append(f"Response:\n{self.response.decode('utf-8', errors='replace')}")
        return {
            "title": self.name,
            "severity": sev,
            "confidence": conf,
            "url": url,
            "description": self.background or self.detail,
            "evidence": "\n\n".join(evidence_parts),
            "remediation_summary": self.remediation,
            "tool_used": "burp_suite",
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialisable dict (bytes → base64 strings)."""
        d = asdict(self)
        d["request"] = base64.b64encode(self.request).decode() if self.request else ""
        d["response"] = base64.b64encode(self.response).decode() if self.response else ""
        return d


# ---------------------------------------------------------------------------
# Import: Burp issues XML → BurpIssue list
# ---------------------------------------------------------------------------


def _text(el: ET.Element | None, tag: str) -> str:
    """Safely extract text from a child element."""
    if el is None:
        return ""
    child = el.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _bytes_from_element(el: ET.Element | None, tag: str) -> bytes:
    """Extract optionally base64-encoded bytes from a child element."""
    if el is None:
        return b""
    child = el.find(tag)
    if child is None or child.text is None:
        return b""
    is_b64 = child.get("base64", "false").lower() == "true"
    raw = child.text
    if is_b64:
        try:
            return base64.b64decode(raw)
        except Exception:
            return raw.encode("utf-8", errors="replace")
    return raw.encode("utf-8", errors="replace")


def parse_burp_xml(xml_content: str) -> list[BurpIssue]:
    """Parse Burp Suite's ``<issues>`` XML export into :class:`BurpIssue` objects.

    Handles both base64-encoded and plain-text request/response bodies.
    Returns an empty list for empty or unparseable input rather than raising.
    """
    if not xml_content or not xml_content.strip():
        return []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return []

    issues: list[BurpIssue] = []
    # Root may be <issues> with <issue> children, or the root itself is <issue>
    issue_elements = root.findall("issue") if root.tag == "issues" else [root] if root.tag == "issue" else []
    for issue_el in issue_elements:
        # Host may have ip attribute and text content
        host_el = issue_el.find("host")
        host = host_el.text.strip() if host_el is not None and host_el.text else ""
        # Some exports nest request/response under <requestresponse>
        rr = issue_el.find("requestresponse")
        req_parent = rr if rr is not None else issue_el
        issues.append(
            BurpIssue(
                name=_text(issue_el, "name"),
                host=host,
                path=_text(issue_el, "path") or _text(issue_el, "location"),
                severity=_text(issue_el, "severity") or "Information",
                confidence=_text(issue_el, "confidence") or "Tentative",
                detail=_text(issue_el, "issueDetail"),
                background=_text(issue_el, "issueBackground"),
                remediation=_text(issue_el, "remediationDetail") or _text(issue_el, "remediationBackground"),
                request=_bytes_from_element(req_parent, "request"),
                response=_bytes_from_element(req_parent, "response"),
                issue_type=_text(issue_el, "type"),
            )
        )
    return issues


# ---------------------------------------------------------------------------
# Export: numasec findings → Burp XML string
# ---------------------------------------------------------------------------


def _cdata(text: str) -> str:
    """Wrap text in a CDATA section for XML embedding."""
    safe = text.replace("]]>", "]]]]><![CDATA[>")
    return f"<![CDATA[{safe}]]>"


def findings_to_burp_xml(findings: list[dict[str, Any]]) -> str:
    """Convert numasec findings to Burp Suite compatible XML.

    The output follows Burp's ``<issues>`` schema so it can be imported
    by tools that consume Burp XML (or round-tripped back through
    :func:`parse_burp_xml`).
    """
    root = ET.Element("issues", attrib={"burpVersion": "numasec-export", "exportTime": ""})

    for f in findings:
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "serialNumber").text = f.get("id", "")
        ET.SubElement(issue, "type").text = f.get("cwe_id", f.get("rule_id", ""))
        ET.SubElement(issue, "name").text = f.get("title", "Unknown")

        url = f.get("url", "")
        host_str = url.split("/")[2] if url.startswith(("http://", "https://")) and len(url.split("/")) > 2 else url
        host_el = ET.SubElement(issue, "host")
        host_el.text = f"{'https' if 'https' in url else 'http'}://{host_str}" if host_str else ""
        host_el.set("ip", "")

        path = "/" + "/".join(url.split("/")[3:]) if url.startswith(("http://", "https://")) else "/"
        ET.SubElement(issue, "path").text = path

        ET.SubElement(issue, "location").text = path

        sev_raw = f.get("severity", "info")
        if isinstance(sev_raw, str):
            ET.SubElement(issue, "severity").text = _NUMASEC_SEVERITY_TO_BURP.get(sev_raw.lower(), "Information")
        else:
            ET.SubElement(issue, "severity").text = _NUMASEC_SEVERITY_TO_BURP.get(str(sev_raw), "Information")

        conf_val = f.get("confidence", 0.5)
        if isinstance(conf_val, (int, float)):
            ET.SubElement(issue, "confidence").text = _confidence_to_burp(float(conf_val))
        else:
            ET.SubElement(issue, "confidence").text = "Tentative"

        ET.SubElement(issue, "issueBackground").text = f.get("description", "")
        ET.SubElement(issue, "issueDetail").text = f.get("evidence", "")
        ET.SubElement(issue, "remediationDetail").text = f.get("remediation_summary", "")

        # Embed request/response if present
        req_text = f.get("request_dump", "")
        if req_text:
            rr = ET.SubElement(issue, "requestresponse")
            req_el = ET.SubElement(rr, "request")
            req_el.set("base64", "true")
            req_el.text = base64.b64encode(req_text.encode("utf-8")).decode()

    return ET.tostring(root, encoding="unicode", xml_declaration=True)


# ---------------------------------------------------------------------------
# Import: Burp sitemap XML → endpoint list
# ---------------------------------------------------------------------------


def parse_burp_sitemap(xml_content: str) -> list[dict[str, Any]]:
    """Parse a Burp Suite sitemap XML export and return discovered endpoints.

    The sitemap format uses ``<item>`` elements each containing ``<url>``,
    ``<host>``, ``<port>``, ``<protocol>``, ``<path>``, ``<method>``,
    ``<status>``, and optionally ``<request>``/``<response>``.

    Returns a list of dicts suitable for feeding into ``mandatory_tests``
    or ``crawl`` results.
    """
    if not xml_content or not xml_content.strip():
        return []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return []

    endpoints: list[dict[str, Any]] = []
    items = root.findall("item") if root.tag in ("items", "map", "sitemap") else []
    # Also handle root being a single <item>
    if root.tag == "item":
        items = [root]
    for item in items:
        url = _text(item, "url")
        host = _text(item, "host")
        port = _text(item, "port")
        protocol = _text(item, "protocol")
        path = _text(item, "path")
        method = _text(item, "method") or "GET"
        status = _text(item, "status")
        mime = _text(item, "mimetype")
        # Build URL from components if not present
        if not url and host:
            scheme = protocol or "https"
            port_suffix = f":{port}" if port and port not in ("80", "443") else ""
            url = f"{scheme}://{host}{port_suffix}{path}"
        endpoints.append(
            {
                "url": url,
                "method": method,
                "host": host,
                "path": path,
                "port": int(port) if port and port.isdigit() else None,
                "protocol": protocol,
                "status_code": int(status) if status and status.isdigit() else None,
                "mimetype": mime,
            }
        )
    return endpoints


# ---------------------------------------------------------------------------
# MCP tool wrapper
# ---------------------------------------------------------------------------


async def python_burp_bridge(
    action: str,
    data: str = "",
    findings: str = "",
) -> str:
    """Import/export Burp Suite XML findings and sitemaps.

    Args:
        action: One of ``import_issues``, ``export_findings``, ``import_sitemap``.
        data: Raw XML string for import actions.
        findings: JSON array of finding dicts for the ``export_findings`` action.

    Returns:
        JSON string wrapped in the standard scanner envelope.
    """
    start = time.monotonic()

    if action == "import_issues":
        issues = parse_burp_xml(data)
        converted = [issue.to_numasec_finding() for issue in issues]
        result: dict[str, Any] = {
            "imported_count": len(converted),
            "findings": converted,
            "raw_issues": [issue.to_dict() for issue in issues],
        }
        return json.dumps(wrap_result("burp_bridge", "burp_import", result, start_time=start), indent=2)

    if action == "export_findings":
        finding_list: list[dict[str, Any]] = []
        if findings:
            try:
                finding_list = json.loads(findings)
            except json.JSONDecodeError as exc:
                result = {"error": f"Invalid JSON in findings parameter: {exc}"}
                return json.dumps(wrap_result("burp_bridge", "burp_export", result, start_time=start), indent=2)
        xml_str = findings_to_burp_xml(finding_list)
        result = {
            "exported_count": len(finding_list),
            "xml": xml_str,
        }
        return json.dumps(wrap_result("burp_bridge", "burp_export", result, start_time=start), indent=2)

    if action == "import_sitemap":
        endpoints = parse_burp_sitemap(data)
        result = {
            "endpoint_count": len(endpoints),
            "endpoints": endpoints,
        }
        return json.dumps(wrap_result("burp_bridge", "burp_sitemap", result, start_time=start), indent=2)

    result = {"error": f"Unknown action: {action!r}. Use import_issues, export_findings, or import_sitemap."}
    return json.dumps(wrap_result("burp_bridge", "burp_bridge", result, start_time=start), indent=2)
