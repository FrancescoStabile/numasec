"""SARIF 2.1.0 report generation with DAST extensions."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from security_mcp.models.finding import Finding
from security_mcp.models.sarif import (
    SarifArtifactLocation,
    SarifLocation,
    SarifLog,
    SarifMessage,
    SarifPhysicalLocation,
    SarifResult,
    SarifRule,
    SarifRun,
    SarifTool,
    SarifToolDriver,
)

SEVERITY_SARIF_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def severity_to_sarif_level(severity: str) -> str:
    """Map finding severity to SARIF level."""
    return SEVERITY_SARIF_MAP.get(severity.lower(), "none")


def finding_to_sarif_result(finding: Finding) -> SarifResult:
    """Convert a Finding to SARIF 2.1.0 Result.

    Uses properties bag for DAST-specific data (not natively supported
    by SARIF's file-centric location model).
    """
    return SarifResult(
        rule_id=finding.rule_id or f"security_mcp/{finding.id}",
        level=severity_to_sarif_level(finding.severity.value),
        message=SarifMessage(text=finding.description),
        locations=[
            SarifLocation(
                physical_location=SarifPhysicalLocation(
                    artifact_location=SarifArtifactLocation(
                        uri=finding.url,
                        uri_base_id=finding.target,
                    )
                )
            )
        ]
        if finding.url
        else [],
        partial_fingerprints={"security_mcp/endpoint": finding.fingerprint()},
        properties={
            "security_mcp:http_method": finding.method,
            "security_mcp:parameter": finding.parameter,
            "security_mcp:evidence": finding.evidence[:2000],
            "security_mcp:cvss": str(finding.cvss_score) if finding.cvss_score else "",
            "security_mcp:cwe": finding.cwe_id,
            "security_mcp:owasp": finding.owasp_category,
            "security_mcp:remediation": finding.remediation_summary,
        },
    )


def _finding_to_sarif_rule(finding: Finding) -> SarifRule:
    """Create a SARIF rule descriptor from a Finding."""
    rule_id = finding.rule_id or f"security_mcp/{finding.id}"
    return SarifRule(
        id=rule_id,
        name=finding.title,
        short_description=SarifMessage(text=finding.title),
        full_description=SarifMessage(text=finding.description),
        help_uri=f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace('CWE-', '')}.html"
        if finding.cwe_id
        else "",
        properties={
            "security_mcp:severity": finding.severity.value,
            "security_mcp:cwe": finding.cwe_id,
        },
    )


def _sarif_to_dict(obj: Any) -> Any:
    """Convert SARIF dataclass tree to SARIF-compliant dict."""
    d = asdict(obj)
    return _transform_keys(d)


def _transform_keys(obj: Any) -> Any:
    """Transform Python snake_case keys to SARIF camelCase."""
    key_map = {
        "rule_id": "ruleId",
        "short_description": "shortDescription",
        "full_description": "fullDescription",
        "help_uri": "helpUri",
        "partial_fingerprints": "partialFingerprints",
        "physical_location": "physicalLocation",
        "artifact_location": "artifactLocation",
        "uri_base_id": "uriBaseId",
        "semantic_version": "semanticVersion",
        "information_uri": "informationUri",
        "schema_uri": "$schema",
    }

    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            new_key = key_map.get(k, k)
            result[new_key] = _transform_keys(v)
        return result
    if isinstance(obj, list):
        return [_transform_keys(item) for item in obj]
    return obj


def generate_sarif_report(
    findings: list[Finding],
    *,
    tool_name: str = "security_mcp",
    tool_version: str = "0.1.0",
    target: str = "",
) -> dict[str, Any]:
    """Generate complete SARIF 2.1.0 report dict.

    The output is a JSON-serializable dict conforming to the SARIF 2.1.0 schema.
    Includes DAST-specific extensions (invocations, webRequest properties).
    """
    # Deduplicate rules by rule_id
    rules_map: dict[str, SarifRule] = {}
    results: list[SarifResult] = []

    for finding in findings:
        result = finding_to_sarif_result(finding)
        results.append(result)

        rule_id = result.rule_id
        if rule_id not in rules_map:
            rules_map[rule_id] = _finding_to_sarif_rule(finding)

    sarif_log = SarifLog(
        runs=[
            SarifRun(
                tool=SarifTool(
                    driver=SarifToolDriver(
                        name=tool_name,
                        version=tool_version,
                        semantic_version=tool_version,
                        rules=list(rules_map.values()),
                    )
                ),
                results=results,
            )
        ]
    )

    report = _sarif_to_dict(sarif_log)

    # Add invocations (DAST-specific metadata)
    if report.get("runs"):
        report["runs"][0]["invocations"] = [
            {
                "executionSuccessful": True,
                "commandLine": f"security_mcp check {target}" if target else "security_mcp check",
            }
        ]

        # Add webRequest to results that have URLs
        for i, finding in enumerate(findings):
            if finding.url and i < len(report["runs"][0].get("results", [])):
                result_dict = report["runs"][0]["results"][i]
                result_dict.setdefault("properties", {})["webRequest"] = {
                    "method": finding.method or "GET",
                    "target": finding.url,
                }

    return report


def sarif_to_json(findings: list[Finding], **kwargs: Any) -> str:
    """Generate SARIF 2.1.0 JSON string."""
    report = generate_sarif_report(findings, **kwargs)
    return json.dumps(report, indent=2, ensure_ascii=False)
