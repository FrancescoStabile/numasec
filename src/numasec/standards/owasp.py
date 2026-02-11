"""
NumaSec Standards — OWASP Top 10 (2021) Classification

Maps CWE-IDs to OWASP Top 10 2021 categories.
Reference: https://owasp.org/Top10/
"""

from __future__ import annotations

from typing import Any


# ═══════════════════════════════════════════════════════════════════════════
# OWASP Top 10 — 2021 Edition
# ═══════════════════════════════════════════════════════════════════════════

OWASP_TOP_10: list[dict[str, Any]] = [
    {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
        "cwe_ids": [
            "CWE-22", "CWE-23", "CWE-35", "CWE-59",
            "CWE-200", "CWE-201", "CWE-219",
            "CWE-264", "CWE-275", "CWE-276", "CWE-284",
            "CWE-285", "CWE-352", "CWE-359",
            "CWE-377", "CWE-402", "CWE-425", "CWE-441",
            "CWE-497", "CWE-538", "CWE-540", "CWE-548",
            "CWE-552", "CWE-566", "CWE-601", "CWE-639",
            "CWE-651", "CWE-668", "CWE-706",
            "CWE-862", "CWE-863", "CWE-913", "CWE-922",
            "CWE-1275",
        ],
    },
    {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure.",
        "cwe_ids": [
            "CWE-261", "CWE-296", "CWE-310", "CWE-312",
            "CWE-319", "CWE-321", "CWE-322", "CWE-323",
            "CWE-324", "CWE-325", "CWE-326", "CWE-327",
            "CWE-328", "CWE-329", "CWE-330", "CWE-331",
            "CWE-335", "CWE-336", "CWE-337", "CWE-338",
            "CWE-340", "CWE-345", "CWE-347",
            "CWE-523", "CWE-720", "CWE-757", "CWE-759",
            "CWE-760", "CWE-780", "CWE-818", "CWE-916",
        ],
    },
    {
        "id": "A03:2021",
        "name": "Injection",
        "description": "User-supplied data is sent to an interpreter as part of a command or query.",
        "cwe_ids": [
            "CWE-20", "CWE-74", "CWE-75", "CWE-77",
            "CWE-78", "CWE-79", "CWE-80", "CWE-83",
            "CWE-87", "CWE-88", "CWE-89", "CWE-90",
            "CWE-91", "CWE-93", "CWE-94", "CWE-95",
            "CWE-96", "CWE-97", "CWE-98",
            "CWE-113", "CWE-116", "CWE-138",
            "CWE-184", "CWE-470", "CWE-471",
            "CWE-564", "CWE-610", "CWE-643",
            "CWE-644", "CWE-652",
            "CWE-917", "CWE-943",
        ],
    },
    {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Missing or ineffective control design — different from implementation bugs.",
        "cwe_ids": [
            "CWE-73", "CWE-183", "CWE-209", "CWE-213",
            "CWE-235", "CWE-256", "CWE-257",
            "CWE-266", "CWE-269", "CWE-280",
            "CWE-311", "CWE-312", "CWE-313",
            "CWE-316", "CWE-419", "CWE-430",
            "CWE-434", "CWE-444", "CWE-451",
            "CWE-472", "CWE-501", "CWE-522",
            "CWE-525", "CWE-539", "CWE-579",
            "CWE-598", "CWE-602", "CWE-642",
            "CWE-646", "CWE-650", "CWE-653",
            "CWE-656", "CWE-657", "CWE-799",
            "CWE-807", "CWE-840", "CWE-841",
            "CWE-927", "CWE-362", "CWE-770",
            "CWE-804",
        ],
    },
    {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, unnecessary features, default accounts, exposed error handling.",
        "cwe_ids": [
            "CWE-2", "CWE-11", "CWE-13", "CWE-15",
            "CWE-16", "CWE-260", "CWE-315", "CWE-520",
            "CWE-526", "CWE-537", "CWE-541",
            "CWE-547", "CWE-611", "CWE-614",
            "CWE-693", "CWE-756", "CWE-776",
            "CWE-942", "CWE-1004", "CWE-1021",
            "CWE-1059", "CWE-1209", "CWE-209",
            "CWE-350", "CWE-548",
        ],
    },
    {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "cwe_ids": [
            "CWE-1104", "CWE-1395",
        ],
    },
    {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Application functions related to authentication and session management implemented incorrectly.",
        "cwe_ids": [
            "CWE-255", "CWE-259", "CWE-287", "CWE-288",
            "CWE-290", "CWE-294", "CWE-295",
            "CWE-297", "CWE-300", "CWE-302",
            "CWE-304", "CWE-306", "CWE-307",
            "CWE-346", "CWE-384",
            "CWE-521", "CWE-613",
            "CWE-620", "CWE-640", "CWE-798",
            "CWE-940", "CWE-1216",
        ],
    },
    {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations.",
        "cwe_ids": [
            "CWE-345", "CWE-353", "CWE-426",
            "CWE-494", "CWE-502", "CWE-565",
            "CWE-784", "CWE-829", "CWE-830",
            "CWE-913", "CWE-915",
        ],
    },
    {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Without logging and monitoring, breaches cannot be detected.",
        "cwe_ids": [
            "CWE-117", "CWE-223", "CWE-532",
            "CWE-778",
        ],
    },
    {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Application fetches a remote resource without validating the user-supplied URL.",
        "cwe_ids": [
            "CWE-918",
        ],
    },
]

# Build a lookup index: CWE-ID → OWASP category
_CWE_TO_OWASP: dict[str, dict[str, Any]] = {}
for category in OWASP_TOP_10:
    for cwe_id in category["cwe_ids"]:
        _CWE_TO_OWASP[cwe_id] = {
            "id": category["id"],
            "name": category["name"],
            "description": category["description"],
        }


def map_cwe_to_owasp(cwe_id: str) -> dict[str, Any] | None:
    """Map a CWE-ID to its OWASP Top 10 (2021) category.

    Args:
        cwe_id: CWE identifier (e.g. "CWE-89")

    Returns:
        Dict with 'id', 'name', 'description' or None if not mapped
    """
    cwe_id = cwe_id.upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    return _CWE_TO_OWASP.get(cwe_id)


def get_owasp_category(category_id: str) -> dict[str, Any] | None:
    """Look up an OWASP Top 10 category by its ID.

    Args:
        category_id: OWASP category ID (e.g. "A03:2021")

    Returns:
        Full category dict or None
    """
    for category in OWASP_TOP_10:
        if category["id"] == category_id:
            return category
    return None
