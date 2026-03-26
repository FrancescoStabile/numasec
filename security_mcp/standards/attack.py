"""MITRE ATT&CK technique mapping from CWE IDs.

Maps common web application CWE weakness identifiers to the most relevant
MITRE ATT&CK for Enterprise technique, providing tactic context for each
finding.  Covers ~40 of the most frequently observed CWE/technique pairings
in web application security testing.
"""

from __future__ import annotations

# CWE -> ATT&CK technique mapping
# Each value has: technique_id, technique_name, tactic
CWE_TO_ATTACK: dict[str, dict[str, str]] = {
    # -------------------------------------------------------------------
    # A01:2021 — Broken Access Control
    # -------------------------------------------------------------------
    "CWE-22": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "CWE-23": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "CWE-284": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
    "CWE-285": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
    "CWE-352": {
        "technique_id": "T1185",
        "technique_name": "Browser Session Hijacking",
        "tactic": "Collection",
    },
    "CWE-425": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "CWE-548": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "CWE-601": {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
    },
    "CWE-639": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
    },
    "CWE-862": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
    "CWE-863": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
    "CWE-269": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
    "CWE-942": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
    },
    # -------------------------------------------------------------------
    # A02:2021 — Cryptographic Failures
    # -------------------------------------------------------------------
    "CWE-295": {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
    },
    "CWE-319": {
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Credential Access",
    },
    "CWE-326": {
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "CWE-327": {
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "CWE-328": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "CWE-330": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
    },
    "CWE-347": {
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
    },
    # -------------------------------------------------------------------
    # A03:2021 — Injection
    # -------------------------------------------------------------------
    "CWE-20": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "CWE-77": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "CWE-78": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "CWE-79": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
    },
    "CWE-89": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "CWE-90": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "CWE-94": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "CWE-95": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "CWE-98": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    "CWE-611": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "CWE-643": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "CWE-917": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "CWE-1336": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    # -------------------------------------------------------------------
    # A07:2021 — Identification and Authentication Failures
    # -------------------------------------------------------------------
    "CWE-287": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
    },
    "CWE-288": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
    },
    "CWE-306": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
    },
    "CWE-307": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "CWE-384": {
        "technique_id": "T1185",
        "technique_name": "Browser Session Hijacking",
        "tactic": "Collection",
    },
    "CWE-521": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "CWE-798": {
        "technique_id": "T1078.001",
        "technique_name": "Valid Accounts: Default Accounts",
        "tactic": "Initial Access",
    },
    # -------------------------------------------------------------------
    # A08:2021 — Software and Data Integrity Failures
    # -------------------------------------------------------------------
    "CWE-434": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
    },
    "CWE-502": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "CWE-829": {
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "tactic": "Initial Access",
    },
    "CWE-915": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    # -------------------------------------------------------------------
    # A10:2021 — SSRF
    # -------------------------------------------------------------------
    "CWE-918": {
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "tactic": "Command and Control",
    },
}


def get_attack_technique(cwe_id: str) -> dict[str, str] | None:
    """Return ATT&CK technique for a CWE ID, or None.

    Args:
        cwe_id: CWE identifier string, e.g. ``"CWE-89"``.

    Returns:
        Dict with ``technique_id``, ``technique_name``, and ``tactic`` keys,
        or ``None`` when no mapping exists.
    """
    return CWE_TO_ATTACK.get(cwe_id)
