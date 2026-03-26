"""CVSS v3.1 base score calculator — FIRST.org specification compliant.

Implements the official CVSS v3.1 base score formula from
https://www.first.org/cvss/v3.1/specification-document (Section 7.1).

Provides:
- ``CVSSv31Vector`` — typed dataclass for the 8 base metrics
- ``calculate_base_score()`` — formula-correct base score
- ``format_vector_string()`` — canonical CVSS:3.1/AV:N/... notation
- ``CWE_VECTOR_MAP`` — default vectors for ~45 common CWE IDs
- ``derive_vector_from_cwe()`` — look up the default vector for a CWE
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------
# Metric value multipliers — CVSS v3.1 spec Table 14
# ---------------------------------------------------------------------------

_AV: dict[str, float] = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}
_AC: dict[str, float] = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}
# Privileges Required when Scope = Unchanged
_PR_U: dict[str, float] = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27,
}
# Privileges Required when Scope = Changed
_PR_C: dict[str, float] = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50,
}
_UI: dict[str, float] = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}
_IMP: dict[str, float] = {
    "N": 0.00,  # None
    "L": 0.22,  # Low
    "H": 0.56,  # High
}


# ---------------------------------------------------------------------------
# Vector dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CVSSv31Vector:
    """CVSS v3.1 base metric vector — all 8 metrics required."""

    AV: Literal["N", "A", "L", "P"]  # Attack Vector
    AC: Literal["L", "H"]  # Attack Complexity
    PR: Literal["N", "L", "H"]  # Privileges Required
    UI: Literal["N", "R"]  # User Interaction
    S: Literal["U", "C"]  # Scope
    C: Literal["N", "L", "H"]  # Confidentiality Impact
    I: Literal["N", "L", "H"]  # Integrity Impact  # noqa: E741
    A: Literal["N", "L", "H"]  # Availability Impact


# ---------------------------------------------------------------------------
# Formula
# ---------------------------------------------------------------------------


def _roundup(value: float) -> float:
    """Round up to the nearest 0.1 — CVSS v3.1 spec §7.1."""
    # Multiply by 10, take ceiling, divide by 10.
    # Use integer arithmetic to avoid floating-point drift.
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def calculate_base_score(v: CVSSv31Vector) -> float:
    """Calculate CVSS v3.1 base score using the official FIRST.org formula.

    Returns a float in [0.0, 10.0] rounded to one decimal place.
    """
    # Impact sub-scores
    isc_base = 1.0 - (1.0 - _IMP[v.C]) * (1.0 - _IMP[v.I]) * (1.0 - _IMP[v.A])

    if isc_base == 0.0:
        return 0.0

    impact = (  # noqa: SIM108
        6.42 * isc_base if v.S == "U" else 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    )

    pr_table = _PR_C if v.S == "C" else _PR_U
    exploitability = 8.22 * _AV[v.AV] * _AC[v.AC] * pr_table[v.PR] * _UI[v.UI]

    base = (  # noqa: SIM108
        min(impact + exploitability, 10.0) if v.S == "U" else min(1.08 * (impact + exploitability), 10.0)
    )

    return _roundup(base)


def format_vector_string(v: CVSSv31Vector) -> str:
    """Return canonical CVSS v3.1 vector string, e.g. ``CVSS:3.1/AV:N/AC:L/...``."""
    return f"CVSS:3.1/AV:{v.AV}/AC:{v.AC}/PR:{v.PR}/UI:{v.UI}/S:{v.S}/C:{v.C}/I:{v.I}/A:{v.A}"


# ---------------------------------------------------------------------------
# CWE → default vector mapping
# ---------------------------------------------------------------------------
# Vectors are chosen to reflect the typical exploitation scenario for each
# vulnerability class, following NIST NVD analyst guidance.  They are
# heuristic defaults — not derived from specific finding evidence — but are
# correct CVSS 3.1 vectors per spec, replacing the former fixed-score lookup.
# ---------------------------------------------------------------------------

CWE_VECTOR_MAP: dict[str, CVSSv31Vector] = {
    # ── Injection ────────────────────────────────────────────────────────────
    # CWE-89  SQL Injection — network, low complexity, no auth, no UI, unchanged
    #         scope, high C/I, no A → 9.1
    "CWE-89": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    # CWE-564 SQL Injection: Hibernate (same profile)
    "CWE-564": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    # CWE-78  OS Command Injection — full RCE → 9.8
    "CWE-78": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # CWE-77  Command Injection (generic)
    "CWE-77": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # CWE-917 Expression Language Injection
    "CWE-917": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # CWE-74  Injection (generic)
    "CWE-74": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    # ── XSS ─────────────────────────────────────────────────────────────────
    # CWE-79  Reflected/Stored XSS — user interaction required, changed scope → 6.1
    "CWE-79": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # CWE-80  Basic XSS
    "CWE-80": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # CWE-87  Failure to Sanitize Alternate XSS Syntax
    "CWE-87": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # ── Path Traversal / LFI ─────────────────────────────────────────────────
    # CWE-22  Path Traversal → high confidentiality → 7.5
    "CWE-22": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    "CWE-23": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    "CWE-35": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # ── SSRF ─────────────────────────────────────────────────────────────────
    # CWE-918 SSRF — changed scope (can reach internal resources) → 9.1
    "CWE-918": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
    # ── SSTI ─────────────────────────────────────────────────────────────────
    # CWE-94  Code Injection / SSTI → RCE → 9.8
    "CWE-94": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # CWE-95  Improper Neutralization of Directives in Dynamically Evaluated Code
    "CWE-95": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # ── XXE ──────────────────────────────────────────────────────────────────
    # CWE-611 XML External Entity — read files + potential SSRF → 7.5
    "CWE-611": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # ── Deserialization ───────────────────────────────────────────────────────
    # CWE-502 Deserialization of Untrusted Data → RCE → 9.8
    "CWE-502": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # ── Authentication & Session ──────────────────────────────────────────────
    # CWE-287 Improper Authentication → 8.1
    "CWE-287": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    # CWE-306 Missing Authentication for Critical Function → 9.1
    "CWE-306": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # CWE-798 Hard-coded Credentials → admin access risk → 9.8
    "CWE-798": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    # CWE-521 Weak Password Requirements
    "CWE-521": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    # CWE-384 Session Fixation → 7.5
    "CWE-384": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # CWE-613 Insufficient Session Expiration
    "CWE-613": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # CWE-345 Insufficient Verification of Data Authenticity (JWT) → 8.1
    "CWE-345": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    # ── Access Control ────────────────────────────────────────────────────────
    # CWE-284 Improper Access Control → 7.5
    "CWE-284": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # CWE-285 Improper Authorization
    "CWE-285": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # CWE-639 Authorization Bypass Through User-Controlled Key (IDOR) → 6.5
    "CWE-639": CVSSv31Vector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"),
    # ── Information Disclosure ────────────────────────────────────────────────
    # CWE-200 Information Exposure → 5.3
    "CWE-200": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    # CWE-209 Error Message Contains Sensitive Information
    "CWE-209": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    # ── Security Misconfiguration ─────────────────────────────────────────────
    # CWE-16 Configuration (generic misconfig) → 5.3
    "CWE-16": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    # CWE-942 Permissive CORS Policy (CORS misconfig) → 6.5
    "CWE-942": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="N", A="N"),
    # CWE-614 Sensitive Cookie Without Secure Flag → 5.3
    "CWE-614": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    # CWE-693 Protection Mechanism Failure (missing security headers) → 5.3
    "CWE-693": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    # ── Cryptographic ─────────────────────────────────────────────────────────
    # CWE-327 Use of Broken Algorithm → 7.5
    "CWE-327": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # CWE-326 Inadequate Encryption Strength
    "CWE-326": CVSSv31Vector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # CWE-311 Missing Encryption of Sensitive Data → 7.5
    "CWE-311": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # ── Software & Integrity ──────────────────────────────────────────────────
    # CWE-829 Inclusion of Functionality from Untrusted Control Sphere
    "CWE-829": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # ── Host Header Injection ─────────────────────────────────────────────────
    # CWE-20 Improper Input Validation (used for host header, open redirect) → 6.1
    "CWE-20": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # ── Open Redirect ─────────────────────────────────────────────────────────
    # CWE-601 URL Redirection to Untrusted Site → 6.1
    "CWE-601": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    # ── CSRF ──────────────────────────────────────────────────────────────────
    # CWE-352 Cross-Site Request Forgery → 8.8 (user interaction, changed scope for integrity)
    "CWE-352": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="H"),
    # ── Vulnerable Components ─────────────────────────────────────────────────
    # CWE-1035 Using Components with Known Vulnerabilities → 7.5 (conservative)
    "CWE-1035": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    # Additional vectors for expanded scanner coverage
    "CWE-434": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),   # File upload -> RCE
    "CWE-1321": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="N"),  # Prototype pollution
    "CWE-1385": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),  # WebSocket hijacking
    "CWE-444": CVSSv31Vector(AV="N", AC="H", PR="N", UI="N", S="C", C="H", I="H", A="N"),   # HTTP smuggling
    "CWE-942": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),   # CORS misconfig
    "CWE-614": CVSSv31Vector(AV="N", AC="H", PR="N", UI="R", S="U", C="H", I="N", A="N"),   # Insecure cookie
    "CWE-1022": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N"),  # Tabnabbing
    "CWE-693": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),   # Protection failure
    "CWE-384": CVSSv31Vector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),   # Session fixation
    "CWE-770": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="H"),   # Resource exhaustion
    "CWE-400": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="H"),   # Resource consumption
    "CWE-943": CVSSv31Vector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),   # NoSQL injection
}


def derive_vector_from_cwe(cwe_id: str) -> CVSSv31Vector | None:
    """Return the default CVSS v3.1 vector for a CWE ID, or ``None`` if unmapped.

    The returned vector is a heuristic default for the vulnerability class —
    not tailored to specific finding evidence — but is a valid, complete
    CVSS 3.1 vector suitable for report generation.
    """
    return CWE_VECTOR_MAP.get(cwe_id)
