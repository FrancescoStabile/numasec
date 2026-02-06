"""
NumaSec — Knowledge Base Loader (v2)

Intelligent, section-level knowledge retrieval for the pentesting agent.

Architecture
────────────
1. Markdown files are split into **section-level chunks** on ``## `` headers
   (cached after first load — zero repeated I/O).
2. ``KNOWLEDGE_MAP`` maps context keys to file references.  Entries may carry
   an optional *section hint* so that only the matching section of a broad
   file is loaded (e.g. only the "SQL Injection" section of web_cheatsheet).
3. **Fuzzy technology matching** normalises real-world version strings
   ("Apache/2.4.41 (Ubuntu)" → "apache").
4. **Implied technology graph** expands coverage automatically
   (WordPress → PHP + MySQL).
5. **Priority ordering**: confirmed vulns → hypotheses → technologies → phase.
6. **Phase-adaptive token budgets** give exploitation phases more room for
   deep payloads while keeping recon lean.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from numasec.target_profile import TargetProfile

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


# ═══════════════════════════════════════════════════════════════════════════
# Section-Level Chunking
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, slots=True)
class _Chunk:
    """An individual section extracted from a knowledge markdown file."""
    heading: str   # text after "## " (empty string for intro before first heading)
    content: str   # full section text including the heading line itself
    tokens: int    # estimated token count  (len // 4)


def _flush(out: list[_Chunk], heading: str, buf: list[str]) -> None:
    """Flush accumulated lines into a Chunk if the section is non-trivial."""
    content = "\n".join(buf).strip()
    if content and len(content) > 80:  # skip tiny fragments
        out.append(_Chunk(heading=heading, content=content, tokens=len(content) // 4))


def _split_sections(text: str) -> list[_Chunk]:
    """Split markdown into sections on ``## `` headers, respecting code fences."""
    lines = text.split("\n")
    sections: list[_Chunk] = []
    heading = ""
    buf: list[str] = []
    in_fence = False

    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence

        if not in_fence and line.startswith("## "):
            _flush(sections, heading, buf)
            heading = line.lstrip("#").strip()
            buf = [line]
        else:
            buf.append(line)

    _flush(sections, heading, buf)
    return sections


@lru_cache(maxsize=128)
def _load_chunks(rel_path: str) -> tuple[_Chunk, ...]:
    """Load a markdown file and split into section chunks.  Result is cached."""
    full_path = KNOWLEDGE_DIR / rel_path
    if not full_path.is_file():
        return ()
    try:
        text = full_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ()
    if not text.strip():
        return ()
    return tuple(_split_sections(text))


# ═══════════════════════════════════════════════════════════════════════════
# Technology Normalisation & Implied Graph
# ═══════════════════════════════════════════════════════════════════════════


def _normalize_tech(name: str) -> str:
    """Extract base technology name from versioned strings.

    >>> _normalize_tech("Apache/2.4.41 (Ubuntu)")
    'apache'
    >>> _normalize_tech("PHP/7.4.3")
    'php'
    >>> _normalize_tech("OpenSSH 8.2p1 Ubuntu-4ubuntu0.5")
    'openssh'
    """
    base = re.split(r"[/\s(]", name.strip(), maxsplit=1)[0].lower().rstrip(".")
    return base or name.lower().strip()


TECH_IMPLIES: dict[str, list[str]] = {
    "wordpress": ["php", "mysql"],
    "drupal":    ["php"],
    "joomla":    ["php", "mysql"],
    "laravel":   ["php"],
    "symfony":   ["php"],
    "django":    ["python"],
    "flask":     ["python"],
    "spring":    ["java"],
    "tomcat":    ["java"],
    "express":   ["node", "javascript"],
    "nextjs":    ["node", "javascript"],
    "react":     ["javascript"],
    "angular":   ["javascript"],
    "vue":       ["javascript"],
    "rails":     ["ruby"],
    "asp.net":   ["windows"],
    "iis":       ["windows"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Knowledge Map
#
# Each key maps to a list of *entries*.  An entry is either:
#   "file.md"                → load ALL sections from the file
#   ("file.md", "hint")     → load only sections whose heading contains *hint*
#                              (case-insensitive).  If nothing matches, the
#                              file is silently skipped for this key.
# ═══════════════════════════════════════════════════════════════════════════

_Entry = str | tuple[str, str]

KNOWLEDGE_MAP: dict[str, list[_Entry]] = {
    # ── Technologies ──────────────────────────────────────────────────────
    "linux":      ["linux_cheatsheet.md"],
    "windows":    ["windows/windows_cheatsheet.md", "windows/active_directory.md"],
    "php":        ["payloads/php_rce.md"],
    "python":     ["payloads/python_sandbox.md"],
    "java":       ["web/payloads_deserialization.md"],
    "node":       ["web/payloads_prototype_pollution.md"],
    "javascript": ["web/payloads_prototype_pollution.md"],
    "wordpress":  [("web_cheatsheet.md", "Reconnaissance"), "payloads/php_rce.md"],
    "apache":     [("linux_cheatsheet.md", "Initial Enumeration")],
    "nginx":      [("linux_cheatsheet.md", "Initial Enumeration")],
    "mysql":      ["attack_chains/sqli_to_rce.md"],
    "postgres":   ["attack_chains/sqli_to_rce.md"],
    "mssql":      ["attack_chains/sqli_to_rce.md"],
    "docker":     [("linux_cheatsheet.md", "Docker"), "cloud/cloud_exploitation.md"],
    "kubernetes": ["cloud/cloud_exploitation.md"],
    "aws":        ["cloud/cloud_exploitation.md"],
    "azure":      ["cloud/cloud_exploitation.md"],
    "gcp":        ["cloud/cloud_exploitation.md"],
    "redis":      ["web/payloads_ssrf.md"],
    "xml":        ["web/payloads_xxe.md"],
    "soap":       ["web/payloads_xxe.md"],
    "websocket":  ["web/payloads_websocket.md"],
    "socket_io":  ["web/payloads_websocket.md"],
    "solidity":   ["blockchain_cheatsheet.md"],

    # ── Vulnerability types ───────────────────────────────────────────────
    "sqli": [
        ("web_cheatsheet.md", "SQL Injection"),
        "attack_chains/sqli_to_rce.md",
    ],
    "xss": [("web_cheatsheet.md", "Cross-Site Scripting")],
    "ssti": [
        "ssti_advanced_bypasses.md",
        "attack_chains/ssti_to_rce.md",
    ],
    "lfi": [
        ("web_cheatsheet.md", "File Inclusion"),
        "attack_chains/lfi_to_rce.md",
    ],
    "rfi": ["attack_chains/lfi_to_rce.md"],
    "file_upload": [
        "web/payloads_file_upload.md",
        "attack_chains/upload_to_rce.md",
    ],
    "command_injection": [
        "payloads/command_injection.md",
        ("blind_injection_techniques.md", "Blind Command"),
    ],
    "ssrf": ["web/payloads_ssrf.md"],
    "xxe":  ["web/payloads_xxe.md"],
    "deserialization":     ["web/payloads_deserialization.md"],
    "jwt":                 ["web/payloads_jwt.md"],
    "graphql":             ["web/payloads_graphql.md"],
    "nosql": [
        "web/payloads_nosql.md",
        ("blind_injection_techniques.md", "Blind NoSQL"),
    ],
    "ldap": [
        "web/payloads_ldap.md",
        ("blind_injection_techniques.md", "Blind LDAP"),
    ],
    "xpath": [
        "web/payloads_xpath.md",
        ("blind_injection_techniques.md", "Blind XPath"),
    ],
    "race_condition":      ["web/race_conditions.md"],
    "http_smuggling":      ["web/payloads_http_smuggling.md"],
    "prototype_pollution":  ["web/payloads_prototype_pollution.md"],
    "privesc": [
        ("advanced_privesc.md", "Linux"),
        ("linux_cheatsheet.md", "SUID"),
    ],
    "crypto":     ["crypto_cheatsheet.md"],
    "blockchain": ["blockchain_cheatsheet.md"],
    "osint":      ["osint_cheatsheet.md"],
    "binary":     ["pwn_reverse_cheatsheet.md", "binary/heap_exploitation.md"],
    "volatility": ["volatility_cheatsheet.md"],

    # ── Phases ────────────────────────────────────────────────────────────
    "recon":        ["quick_wins.md", "attack_decision_matrix.md"],
    "enumeration":  [
        ("quick_wins.md", "Quick Vulnerability"),
        ("web_cheatsheet.md", "Reconnaissance"),
    ],
    "exploitation": ["attack_decision_matrix.md"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Phase-Adaptive Token Budgets
# ═══════════════════════════════════════════════════════════════════════════

_PHASE_BUDGETS: dict[str, int] = {
    "recon":                 1500,
    "reconnaissance":        1500,
    "enumeration":           2500,
    "vulnerability_testing": 4000,
    "exploitation":          5000,
    "reporting":              500,
}
_DEFAULT_BUDGET = 3000


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════


def load_knowledge(keys: list[str], max_total_tokens: int = 3000) -> str:
    """
    Load knowledge sections for a list of context keys within a token budget.

    Uses section-level granularity: broad files are filtered to include only
    the sections matching the requested key, packing *more* relevant content
    into the same token budget.
    """
    seen_sections: set[str] = set()   # "file::heading" dedup
    collected: list[str] = []
    budget_used = 0

    for key in keys:
        if budget_used >= max_total_tokens:
            break
        normalized = key.lower().strip().replace(" ", "_").replace("-", "_")
        entries = KNOWLEDGE_MAP.get(normalized, [])

        for entry in entries:
            if budget_used >= max_total_tokens:
                break

            # Parse entry
            if isinstance(entry, tuple):
                rel_path, section_hint = entry
            else:
                rel_path, section_hint = entry, None

            chunks = _load_chunks(rel_path)
            if not chunks:
                continue

            # Select relevant chunks
            if section_hint:
                hint_lower = section_hint.lower()
                selected = [c for c in chunks if hint_lower in c.heading.lower()]
                if not selected:
                    continue   # no matching section → skip this file for this key
            else:
                selected = list(chunks)

            for chunk in selected:
                dedup_key = f"{rel_path}::{chunk.heading}"
                if dedup_key in seen_sections:
                    continue
                seen_sections.add(dedup_key)

                if budget_used + chunk.tokens > max_total_tokens:
                    # Try to fit a truncated version
                    remaining_chars = (max_total_tokens - budget_used) * 4
                    if remaining_chars > 500:
                        text = chunk.content[:remaining_chars] + "\n\n[... truncated for context budget ...]"
                        label = f"### {rel_path}" + (f" — {chunk.heading}" if chunk.heading else "")
                        collected.append(f"{label}\n{text}")
                        budget_used += remaining_chars // 4
                    break   # budget exhausted for this file

                label = f"### {rel_path}" + (f" — {chunk.heading}" if chunk.heading else "")
                collected.append(f"{label}\n{chunk.content}")
                budget_used += chunk.tokens

    return "\n\n---\n\n".join(collected) if collected else ""


def get_relevant_knowledge(profile: TargetProfile, current_phase: str = "") -> str:
    """
    Auto-select and load relevant knowledge based on the TargetProfile
    and current attack phase.

    Priority ordering (most actionable first):
      1. Confirmed vulnerabilities — agent needs exploitation payloads
      2. Untested hypotheses — agent needs testing techniques
      3. Detected technologies — tech-specific cheatsheets
      4. OS detection from port banners
      5. Current phase — methodology guidance (lowest priority)

    Returns concatenated knowledge text within a phase-adaptive budget.
    """
    keys: list[str] = []

    # ── Priority 1: Confirmed vulns (need exploitation guidance NOW) ──
    for hyp in profile.get_confirmed_vulns():
        keys.append(hyp.vuln_type)

    # ── Priority 2: Untested hypotheses (need testing payloads) ──
    for hyp in profile.get_untested_hypotheses():
        keys.append(hyp.vuln_type)

    # ── Priority 3: Technologies (normalised + implied) ──
    for tech in profile.technologies:
        base = _normalize_tech(tech.name)
        keys.append(base)
        for implied in TECH_IMPLIES.get(base, []):
            keys.append(implied)

    # ── Priority 4: OS detection from port banners ──
    _detect_os(profile, keys)

    # ── Priority 5: Current phase (lowest priority) ──
    if current_phase:
        keys.append(current_phase)

    # Fallback
    if not keys:
        keys = ["recon"]

    # Dedup preserving priority order
    seen: set[str] = set()
    unique: list[str] = []
    for k in keys:
        n = k.lower().strip().replace(" ", "_").replace("-", "_")
        if n not in seen:
            seen.add(n)
            unique.append(n)

    # Phase-adaptive budget
    phase_key = current_phase.lower().strip().replace(" ", "_")
    budget = _PHASE_BUDGETS.get(phase_key, _DEFAULT_BUDGET)

    return load_knowledge(unique, max_total_tokens=budget)


def _detect_os(profile: TargetProfile, keys: list[str]) -> None:
    """Append OS keys based on port service banners."""
    linux_indicators = ("linux", "openssh", "ubuntu", "debian", "centos", "fedora")
    windows_indicators = ("windows", "microsoft", "iis")

    for p in profile.ports:
        combined = ((p.service or "") + " " + (p.version or "")).lower()
        if any(ind in combined for ind in linux_indicators):
            keys.append("linux")
            break

    for p in profile.ports:
        combined = ((p.service or "") + " " + (p.version or "")).lower()
        if any(ind in combined for ind in windows_indicators):
            keys.append("windows")
            break
