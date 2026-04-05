"""Smart security shell — structured wrappers for common security tools."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any

from numasec.scanners._envelope import wrap_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known security tools and their output parsers
# ---------------------------------------------------------------------------

KNOWN_TOOLS: dict[str, dict[str, Any]] = {
    "nmap": {
        "binary": "nmap",
        "default_args": ["-sV", "-oX", "-"],
        "parser": "_parse_nmap_xml",
        "description": "Port scan and service detection",
    },
    "ffuf": {
        "binary": "ffuf",
        "default_args": ["-o", "/dev/stdout", "-of", "json", "-s"],
        "parser": "_parse_ffuf_json",
        "description": "Web fuzzer for directories and parameters",
    },
    "subfinder": {
        "binary": "subfinder",
        "default_args": ["-silent"],
        "parser": "_parse_line_list",
        "description": "Subdomain enumeration",
    },
    "nuclei": {
        "binary": "nuclei",
        "default_args": ["-jsonl", "-silent"],
        "parser": "_parse_nuclei_jsonl",
        "description": "Template-based vulnerability scanner",
    },
    "sqlmap": {
        "binary": "sqlmap",
        "default_args": ["--batch", "--output-dir=/dev/null"],
        "parser": "_parse_sqlmap_output",
        "description": "SQL injection detection and exploitation",
    },
    "gobuster": {
        "binary": "gobuster",
        "default_args": ["dir", "--no-progress", "-q"],
        "parser": "_parse_line_list",
        "description": "Directory/file brute-forcing",
    },
    "nikto": {
        "binary": "nikto",
        "default_args": ["-Format", "json", "-output", "/dev/stdout"],
        "parser": "_parse_nikto_json",
        "description": "Web server scanner",
    },
    "httpx": {
        "binary": "httpx",
        "default_args": ["-silent", "-json"],
        "parser": "_parse_httpx_json",
        "description": "HTTP probing and tech detection",
    },
}

# Patterns considered unsafe targets
_UNSAFE_TARGET_RE = re.compile(
    r"^(file://|/|\\\\|\.\.)"  # file URIs, absolute/UNC paths, traversal
    r"|^(127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|::1|\[::1\])"  # loopback
    r"|^(10\.\d+\.\d+\.\d+)"  # 10.x private
    r"|^(172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)"  # 172.16-31 private
    r"|^(192\.168\.\d+\.\d+)"  # 192.168 private
    r"|^(169\.254\.\d+\.\d+)",  # link-local
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Tool availability detection
# ---------------------------------------------------------------------------


def detect_available_tools() -> dict[str, bool]:
    """Return a mapping of tool name → whether the binary is on ``$PATH``."""
    return {name: shutil.which(info["binary"]) is not None for name, info in KNOWN_TOOLS.items()}


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------


def _validate_target(target: str) -> bool:
    """Return ``True`` if *target* looks like a safe remote host/URL.

    Rejects local paths, loopback addresses, and RFC-1918 private ranges.
    """
    if not target or not target.strip():
        return False

    stripped = target.strip()

    # Strip common URL schemes for the regex check
    for scheme in ("https://", "http://"):
        if stripped.lower().startswith(scheme):
            stripped = stripped[len(scheme) :]
            break

    # Strip user:pass@ prefix if present
    if "@" in stripped.split("/")[0]:
        stripped = stripped.split("@", 1)[1]

    return _UNSAFE_TARGET_RE.search(stripped) is None


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------


def _parse_nmap_xml(output: str) -> dict[str, Any]:
    """Parse nmap XML (``-oX -``) into structured host/port data."""
    hosts: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return {"hosts": [], "raw": output[:2000], "parse_error": "Invalid XML"}

    for host_el in root.findall(".//host"):
        addr_el = host_el.find("address")
        ip = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

        ports: list[dict[str, Any]] = []
        for port_el in host_el.findall(".//port"):
            port_id = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            svc_el = port_el.find("service")
            service = svc_el.get("name", "") if svc_el is not None else ""
            version = ""
            if svc_el is not None:
                product = svc_el.get("product", "")
                ver = svc_el.get("version", "")
                version = f"{product} {ver}".strip()
            ports.append({"port": port_id, "protocol": proto, "state": state, "service": service, "version": version})

        hosts.append({"ip": ip, "ports": ports})

    return {"hosts": hosts}


def _parse_ffuf_json(output: str) -> dict[str, Any]:
    """Parse ffuf JSON output into a results list."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"results": [], "raw": output[:2000], "parse_error": "Invalid JSON"}

    results: list[dict[str, Any]] = []
    for entry in data.get("results", []):
        results.append(
            {
                "url": entry.get("url", ""),
                "status": entry.get("status", 0),
                "length": entry.get("length", 0),
                "words": entry.get("words", 0),
                "lines": entry.get("lines", 0),
            }
        )
    return {"results": results}


def _parse_line_list(output: str) -> dict[str, Any]:
    """Parse line-delimited output (subfinder, gobuster, etc.)."""
    items = [line.strip() for line in output.splitlines() if line.strip()]
    return {"items": items}


def _parse_nuclei_jsonl(output: str) -> dict[str, Any]:
    """Parse nuclei JSONL output into structured findings."""
    findings: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append(
                {
                    "template": data.get("template-id", ""),
                    "severity": data.get("info", {}).get("severity", "info"),
                    "matched": data.get("matched-at", ""),
                    "name": data.get("info", {}).get("name", ""),
                }
            )
        except json.JSONDecodeError:
            continue
    return {"findings": findings}


def _parse_sqlmap_output(output: str) -> dict[str, Any]:
    """Parse sqlmap batch output for injectable parameters and DB info."""
    injectable_params: list[str] = []
    dbms = ""
    tables: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if "injectable" in lower:
            # Try to extract the parameter name from surrounding quotes
            match = re.search(r"['\"](\w+)['\"]", stripped)
            if match:
                param = match.group(1)
                if param not in injectable_params:
                    injectable_params.append(param)
        if lower.startswith("back-end dbms:") or lower.startswith("web application technology:"):
            dbms = stripped.split(":", 1)[1].strip()
        if lower.startswith("| ") and not lower.startswith("| table"):
            table = stripped.strip("| ").strip()
            if table:
                tables.append(table)

    return {"injectable_params": injectable_params, "dbms": dbms, "tables": tables}


def _parse_nikto_json(output: str) -> dict[str, Any]:
    """Parse nikto JSON output into a vulnerability list."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"vulnerabilities": [], "raw": output[:2000], "parse_error": "Invalid JSON"}

    vulns: list[dict[str, Any]] = []
    # Nikto JSON wraps results in various shapes
    items: list[dict[str, Any]] = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("vulnerabilities", data.get("items", [])) or []

    for item in items:
        vulns.append(
            {
                "id": str(item.get("id", item.get("OSVDB", ""))),
                "msg": item.get("msg", item.get("message", "")),
                "method": item.get("method", "GET"),
            }
        )
    return {"vulnerabilities": vulns}


def _parse_httpx_json(output: str) -> dict[str, Any]:
    """Parse httpx JSONL output into probe results."""
    probes: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            probes.append(
                {
                    "url": data.get("url", data.get("input", "")),
                    "status": data.get("status_code", data.get("status-code", 0)),
                    "tech": data.get("tech", data.get("technologies", [])),
                    "title": data.get("title", ""),
                    "content_length": data.get("content_length", data.get("content-length", 0)),
                }
            )
        except json.JSONDecodeError:
            continue
    return {"probes": probes}


# ---------------------------------------------------------------------------
# Parser dispatch
# ---------------------------------------------------------------------------

_PARSERS: dict[str, Any] = {
    "_parse_nmap_xml": _parse_nmap_xml,
    "_parse_ffuf_json": _parse_ffuf_json,
    "_parse_line_list": _parse_line_list,
    "_parse_nuclei_jsonl": _parse_nuclei_jsonl,
    "_parse_sqlmap_output": _parse_sqlmap_output,
    "_parse_nikto_json": _parse_nikto_json,
    "_parse_httpx_json": _parse_httpx_json,
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def security_shell(
    tool: str,
    target: str,
    options: str = "",
    timeout: int = 120,
) -> dict[str, Any]:
    """Run an external security tool with structured output parsing.

    Parameters
    ----------
    tool:
        Tool name — must be one of :data:`KNOWN_TOOLS`.
    target:
        Target URL or hostname to scan.
    options:
        Additional CLI flags as a single string (split on whitespace).
    timeout:
        Maximum execution time in seconds (default 120).

    Returns
    -------
    dict
        Wrapped result envelope with parsed output.
    """
    import time

    start = time.monotonic()

    # 1. Validate tool name
    if tool not in KNOWN_TOOLS:
        available = ", ".join(sorted(KNOWN_TOOLS))
        return wrap_result(
            "security_shell",
            target,
            {
                "error": f"Unknown tool '{tool}'. Supported: {available}",
                "success": False,
            },
            start,
        )

    tool_info = KNOWN_TOOLS[tool]

    # 2. Check binary availability
    if not shutil.which(tool_info["binary"]):
        return wrap_result(
            "security_shell",
            target,
            {
                "error": f"Tool '{tool}' ({tool_info['binary']}) is not installed or not on $PATH. Install it first.",
                "success": False,
                "available_tools": {k: shutil.which(v["binary"]) is not None for k, v in KNOWN_TOOLS.items()},
            },
            start,
        )

    # 3. Validate target safety
    if not _validate_target(target):
        return wrap_result(
            "security_shell",
            target,
            {
                "error": f"Target '{target}' is not allowed. Only remote hosts/URLs are permitted.",
                "success": False,
            },
            start,
        )

    # 4. Build command as a list (no shell=True)
    cmd: list[str] = [tool_info["binary"]]
    cmd.extend(tool_info["default_args"])

    # Append extra options (split on whitespace, no shell interpretation)
    if options:
        cmd.extend(options.split())

    # Append target (most tools take it as the last positional arg)
    cmd.append(target)

    logger.info("security_shell: running %s → %s", tool, " ".join(cmd))

    # 5. Execute with timeout
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        try:
            proc.kill()  # type: ignore[union-attr]
            await proc.wait()  # type: ignore[union-attr]
        except ProcessLookupError:
            pass
        return wrap_result(
            "security_shell",
            target,
            {
                "error": f"Command timed out after {timeout}s",
                "success": False,
                "tool": tool,
            },
            start,
        )
    except OSError as exc:
        return wrap_result(
            "security_shell",
            target,
            {
                "error": f"Failed to execute '{tool_info['binary']}': {exc}",
                "success": False,
            },
            start,
        )

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    # 6. Parse output
    parser_name = tool_info["parser"]
    parser_fn = _PARSERS.get(parser_name)

    parsed = parser_fn(stdout) if parser_fn is not None else {"raw": stdout[:50_000]}

    # 7. Build result
    result: dict[str, Any] = {
        "success": proc.returncode == 0,
        "tool": tool,
        "exit_code": proc.returncode,
        **parsed,
    }

    if stderr.strip():
        result["stderr"] = stderr[:10_000]

    return wrap_result("security_shell", target, result, start)
