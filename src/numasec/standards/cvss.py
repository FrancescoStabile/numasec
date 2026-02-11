"""
NumaSec Standards — CVSS v3.1 Score Calculator

Implements CVSS v3.1 Base Score calculation from vector strings,
plus quick severity-to-score mapping for auto-enrichment.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
import re
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════
# CVSS v3.1 Constants
# ═══════════════════════════════════════════════════════════════════════════

# Metric values per CVSS v3.1 spec
METRIC_VALUES: dict[str, dict[str, float]] = {
    # Attack Vector
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    # Attack Complexity
    "AC": {"L": 0.77, "H": 0.44},
    # Privileges Required (Scope Unchanged)
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    # Privileges Required (Scope Changed)
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},
    # User Interaction
    "UI": {"N": 0.85, "R": 0.62},
    # Scope
    "S": {"U": False, "C": True},
    # Confidentiality Impact
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    # Integrity Impact
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    # Availability Impact
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}


def calculate_cvss_score(vector: str) -> dict[str, Any]:
    """Calculate CVSS v3.1 Base Score from a vector string.

    Args:
        vector: CVSS v3.1 vector string, e.g.
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        Dict with 'score' (float), 'severity' (str), 'vector' (str)

    Raises:
        ValueError: If vector is invalid or incomplete
    """
    # Parse vector string
    vector = vector.strip()
    if vector.startswith("CVSS:3.1/"):
        vector = vector[9:]
    elif vector.startswith("CVSS:3.0/"):
        vector = vector[9:]

    metrics: dict[str, str] = {}
    for component in vector.split("/"):
        if ":" in component:
            key, val = component.split(":", 1)
            metrics[key] = val

    # Validate required metrics
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(metrics.keys())
    if missing:
        raise ValueError(f"Missing CVSS metrics: {', '.join(sorted(missing))}")

    # Determine scope
    scope_changed = METRIC_VALUES["S"].get(metrics["S"])
    if scope_changed is None:
        raise ValueError(f"Invalid Scope value: {metrics['S']}")

    # Get metric values
    av = METRIC_VALUES["AV"].get(metrics["AV"])
    ac = METRIC_VALUES["AC"].get(metrics["AC"])
    pr_key = "PR_C" if scope_changed else "PR_U"
    pr = METRIC_VALUES[pr_key].get(metrics["PR"])
    ui = METRIC_VALUES["UI"].get(metrics["UI"])
    c = METRIC_VALUES["C"].get(metrics["C"])
    i = METRIC_VALUES["I"].get(metrics["I"])
    a = METRIC_VALUES["A"].get(metrics["A"])

    if any(v is None for v in (av, ac, pr, ui, c, i, a)):
        raise ValueError(f"Invalid metric value in vector: {vector}")

    # Calculate ISS (Impact Sub Score)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # Calculate Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Calculate Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Calculate Base Score
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    # Round up to nearest 0.1 (CVSS spec)
    score = math.ceil(score * 10) / 10

    return {
        "score": score,
        "severity": _score_to_severity(score),
        "vector": f"CVSS:3.1/{vector}" if not vector.startswith("CVSS:") else vector,
    }


def _score_to_severity(score: float) -> str:
    """Convert CVSS score to severity rating."""
    if score == 0.0:
        return "info"
    elif score <= 3.9:
        return "low"
    elif score <= 6.9:
        return "medium"
    elif score <= 8.9:
        return "high"
    else:
        return "critical"


# ═══════════════════════════════════════════════════════════════════════════
# Quick Severity-to-Score Mapping
# ═══════════════════════════════════════════════════════════════════════════

# Common CVSS vectors for auto-enrichment based on vuln type
COMMON_VECTORS: dict[str, str] = {
    # Critical
    "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1
    "file_upload": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 8.8
    "deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    # High
    "xss_stored": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",  # 5.4
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",  # 7.2
    "lfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # 6.5
    "jwt": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1
    # Medium
    "xss_reflected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1
    "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  # 4.3
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    # Low
    "info_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "missing_headers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3
}

# Default scores per severity (when no specific vector applies)
DEFAULT_SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.0,
    "info": 0.0,
}


def cvss_from_severity(severity: str) -> float:
    """Get a reasonable CVSS score from severity level.

    Used for auto-enrichment when no specific CVSS vector is available.

    Args:
        severity: "critical", "high", "medium", "low", or "info"

    Returns:
        CVSS score (0.0 - 10.0)
    """
    return DEFAULT_SEVERITY_SCORES.get(severity.lower(), 0.0)


def cvss_from_vuln_type(vuln_type: str) -> dict[str, Any] | None:
    """Get CVSS details from a known vulnerability type.

    Args:
        vuln_type: Vulnerability type key (e.g. "sqli", "xss_reflected")

    Returns:
        Dict with 'score', 'severity', 'vector' or None if unknown
    """
    vector = COMMON_VECTORS.get(vuln_type.lower())
    if vector:
        return calculate_cvss_score(vector)
    return None
