"""
NumaSec — MCP Resources

Exposes the 46+ knowledge base files as MCP Resources.
Claude/Cursor/VS Code can read numasec://kb/* to get security cheatsheets,
payloads, attack chains — the KILLER FEATURE no competitor has.

Architecture:
    - Iterates knowledge/ directory at import time
    - Registers each .md file as an MCP Resource template
    - Normalises paths: web_cheatsheet.md → numasec://kb/web-cheatsheet
    - Falls back to fuzzy search if exact match fails
    - Directory paths return a listing of available resources
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger("numasec.mcp.resources")

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


def _path_to_uri_key(rel_path: Path) -> str:
    """Convert a relative Path to a URI-friendly key.

    Examples:
        web_cheatsheet.md → web-cheatsheet
        attack_chains/sqli_to_rce.md → attack-chains/sqli-to-rce
        enterprise/README.md → enterprise/readme
    """
    # Remove .md extension
    s = str(rel_path).replace(".md", "")
    # Underscores → hyphens for URL-friendliness
    s = s.replace("_", "-")
    return s.lower()


def _uri_key_to_candidates(key: str) -> list[Path]:
    """Convert a URI key back to candidate file paths.

    Tries multiple forms to be lenient with user input.
    """
    # Normalise: hyphens → underscores (reverse of _path_to_uri_key)
    normalised = key.replace("-", "_")
    return [
        KNOWLEDGE_DIR / f"{normalised}.md",
        KNOWLEDGE_DIR / normalised / "README.md",
        KNOWLEDGE_DIR / f"{normalised}",
        # Also try the key as-is (in case they used underscores)
        KNOWLEDGE_DIR / f"{key}.md",
        KNOWLEDGE_DIR / key / "README.md",
    ]


@lru_cache(maxsize=1)
def discover_knowledge_files() -> dict[str, Path]:
    """Discover all .md files in knowledge/ and map URI keys → file paths.

    Returns:
        dict mapping URI key (e.g. "web-cheatsheet") to absolute Path
    """
    if not KNOWLEDGE_DIR.is_dir():
        logger.warning(f"Knowledge directory not found: {KNOWLEDGE_DIR}")
        return {}

    mapping: dict[str, Path] = {}
    for md_file in sorted(KNOWLEDGE_DIR.rglob("*.md")):
        rel = md_file.relative_to(KNOWLEDGE_DIR)
        # Skip templates and READMEs (except enterprise/README which has content)
        if rel.name == "TEMPLATE.md":
            continue
        # For README.md files, use the parent dir name
        if rel.name == "README.md" and rel.parent != Path("."):
            uri_key = _path_to_uri_key(rel.parent / "overview")
        else:
            uri_key = _path_to_uri_key(rel)
        mapping[uri_key] = md_file

    return mapping


def read_knowledge(path: str) -> str:
    """Read a knowledge resource by URI path.

    Args:
        path: The URI path component (e.g. "web-cheatsheet", "attack-chains/sqli-to-rce")

    Returns:
        The markdown content, or an error/listing message
    """
    path = path.strip("/")

    # 1. Try exact candidate resolution (with path traversal guard)
    _knowledge_root = KNOWLEDGE_DIR.resolve()
    for candidate in _uri_key_to_candidates(path):
        resolved = candidate.resolve()
        if resolved.is_file() and str(resolved).startswith(str(_knowledge_root)):
            return resolved.read_text(encoding="utf-8")

    # 2. Try as directory listing
    normalised = path.replace("-", "_")
    dir_path = KNOWLEDGE_DIR / normalised
    if dir_path.is_dir():
        files = sorted(dir_path.rglob("*.md"))
        if files:
            lines = [f"# Knowledge: {path}\n\nAvailable topics:\n"]
            for f in files:
                if f.name == "TEMPLATE.md":
                    continue
                rel = f.relative_to(KNOWLEDGE_DIR)
                key = _path_to_uri_key(rel)
                lines.append(f"- `numasec://kb/{key}`")
            return "\n".join(lines)

    # 3. Fuzzy search across all files
    all_files = discover_knowledge_files()
    normalised_lower = normalised.lower()
    matches = [
        (key, fpath) for key, fpath in all_files.items()
        if normalised_lower in key or normalised_lower in str(fpath.stem).lower()
    ]
    if matches:
        # Return first match
        return matches[0][1].read_text(encoding="utf-8")

    # 4. Not found — return helpful listing
    topics = sorted(all_files.keys())
    topic_list = "\n".join(f"- `numasec://kb/{t}`" for t in topics[:30])
    return (
        f"Knowledge topic '{path}' not found.\n\n"
        f"Available topics ({len(topics)} total):\n{topic_list}\n"
        f"{'...' if len(topics) > 30 else ''}"
    )


def list_knowledge_topics() -> list[dict[str, str]]:
    """List all available knowledge topics with descriptions.

    Returns:
        List of dicts with 'uri', 'name', 'description' keys
    """
    all_files = discover_knowledge_files()
    topics = []
    for key, fpath in sorted(all_files.items()):
        # Read first line as description
        try:
            first_line = fpath.read_text(encoding="utf-8").split("\n")[0]
            # Strip markdown heading
            desc = first_line.lstrip("#").strip()
            if not desc or len(desc) < 5:
                desc = f"Security knowledge: {key.replace('-', ' ')}"
        except Exception:
            desc = f"Security knowledge: {key.replace('-', ' ')}"

        topics.append({
            "uri": f"numasec://kb/{key}",
            "name": key.replace("-", " ").title(),
            "description": desc[:200],
        })
    return topics
