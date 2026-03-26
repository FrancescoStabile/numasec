"""Shared payload encoding for WAF evasion.

Provides a library of encoding transformations that scanners can apply
to their payloads when WAF detection triggers evasion mode.  All methods
are pure functions -- no I/O, no state.

Usage::

    from security_mcp.scanners._encoder import PayloadEncoder

    variants = PayloadEncoder.all_variants("' OR 1=1--")
    for v in variants:
        # test each encoded variant against the target
        ...
"""

from __future__ import annotations

import re
from urllib.parse import quote


class PayloadEncoder:
    """Static methods producing WAF-bypass encoding variants."""

    # ------------------------------------------------------------------
    # Individual encoding strategies
    # ------------------------------------------------------------------

    @staticmethod
    def url_double_encode(payload: str) -> str:
        """Double URL encoding: ``'`` -> ``%27`` -> ``%2527``."""
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def url_encode(payload: str) -> str:
        """Standard URL encoding (no safe chars)."""
        return quote(payload, safe="")

    @staticmethod
    def hex_encode_sql(payload: str) -> str:
        """Hex-encode string literals for SQL context.

        ``' OR 1=1--`` -> ``0x27204f5220313d312d2d``
        """
        return "0x" + payload.encode().hex()

    @staticmethod
    def comment_injection_sql(payload: str) -> str:
        """Insert inline SQL comments between keywords.

        ``UNION SELECT`` -> ``UN/**/ION SEL/**/ECT``
        """
        keywords = ["UNION", "SELECT", "INSERT", "UPDATE", "DELETE",
                     "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP"]
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            if pattern.search(result):
                mid = len(kw) // 2
                replacement = kw[:mid] + "/**/" + kw[mid:]
                result = pattern.sub(replacement, result, count=1)
        return result

    @staticmethod
    def case_alternate(payload: str) -> str:
        """Alternate character casing: ``select`` -> ``SeLeCt``.

        Bypasses case-sensitive WAF rules.
        """
        out: list[str] = []
        upper = True
        for ch in payload:
            if ch.isalpha():
                out.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def unicode_normalize(payload: str) -> str:
        """Replace ASCII chars with full-width Unicode equivalents.

        ``<script>`` -> ``\uff1cscript\uff1e``
        Bypasses filters that only block ASCII ``<`` and ``>``.
        """
        mapping = {
            "<": "\uff1c",
            ">": "\uff1e",
            "'": "\uff07",
            '"': "\uff02",
            "(": "\uff08",
            ")": "\uff09",
        }
        return "".join(mapping.get(ch, ch) for ch in payload)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML numeric entity encoding for XSS context.

        ``<`` -> ``&#60;``, ``>`` -> ``&#62;``
        """
        return "".join(f"&#{ord(ch)};" if not ch.isalnum() else ch for ch in payload)

    @staticmethod
    def html_hex_entity_encode(payload: str) -> str:
        """HTML hex entity encoding.

        ``<`` -> ``&#x3c;``, ``>`` -> ``&#x3e;``
        """
        return "".join(f"&#x{ord(ch):x};" if not ch.isalnum() else ch for ch in payload)

    @staticmethod
    def null_byte_insert(payload: str) -> str:
        """Insert null bytes between characters.

        ``UNION`` -> ``U%00N%00I%00O%00N``
        Exploits filters that stop at null bytes.
        """
        return "%00".join(payload)

    @staticmethod
    def concat_split_sql(payload: str) -> str:
        """Split string literals using SQL concatenation.

        ``admin`` -> ``adm'+'in`` (MSSQL) or ``adm'||'in`` (Oracle/PG).
        Returns the ``+`` variant; caller can substitute ``||``.
        """
        if len(payload) < 4:
            return payload
        mid = len(payload) // 2
        return f"{payload[:mid]}'+'{ payload[mid:]}"

    # ------------------------------------------------------------------
    # Composite
    # ------------------------------------------------------------------

    @staticmethod
    def sql_variants(payload: str) -> list[str]:
        """Generate SQL-specific evasion variants.

        Returns the original plus up to 5 encoded versions.
        """
        seen: set[str] = {payload}
        variants: list[str] = [payload]
        for fn in (
            PayloadEncoder.comment_injection_sql,
            PayloadEncoder.case_alternate,
            PayloadEncoder.url_double_encode,
            PayloadEncoder.hex_encode_sql,
        ):
            v = fn(payload)
            if v not in seen:
                seen.add(v)
                variants.append(v)
        return variants

    @staticmethod
    def xss_variants(payload: str) -> list[str]:
        """Generate XSS-specific evasion variants."""
        seen: set[str] = {payload}
        variants: list[str] = [payload]
        for fn in (
            PayloadEncoder.case_alternate,
            PayloadEncoder.html_entity_encode,
            PayloadEncoder.html_hex_entity_encode,
            PayloadEncoder.url_double_encode,
        ):
            v = fn(payload)
            if v not in seen:
                seen.add(v)
                variants.append(v)
        return variants

    @staticmethod
    def all_variants(payload: str) -> list[str]:
        """Generate all encoding variants (max ~8).

        De-duplicated; original payload is always first.
        """
        seen: set[str] = {payload}
        variants: list[str] = [payload]
        for fn in (
            PayloadEncoder.url_encode,
            PayloadEncoder.url_double_encode,
            PayloadEncoder.case_alternate,
            PayloadEncoder.comment_injection_sql,
            PayloadEncoder.html_entity_encode,
            PayloadEncoder.hex_encode_sql,
            PayloadEncoder.unicode_normalize,
        ):
            v = fn(payload)
            if v not in seen:
                seen.add(v)
                variants.append(v)
        return variants
