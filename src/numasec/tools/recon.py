"""
NumaSec v3 - Reconnaissance Tools

Simplified recon tools: nmap, httpx, subfinder
~160 lines total vs 1000+ in v1
"""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════
# Helper: Run Command
# ═══════════════════════════════════════════════════════════════════════════


async def _run_command(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    """
    Run command with timeout.
    
    Returns: (stdout, stderr, exit_code)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )
        
        return (
            stdout.decode('utf-8', errors='ignore'),
            stderr.decode('utf-8', errors='ignore'),
            process.returncode or 0
        )
    except asyncio.TimeoutError:
        if process:
            process.kill()
            await process.wait()
        return ("", f"Command timed out after {timeout}s", 124)
    except Exception as e:
        return ("", f"Command failed: {e}", 1)


def _cap_port_range(ports: str, max_width: int = 1024) -> str:
    """
    Sanitise user-supplied port spec so a single range
    never exceeds *max_width* ports.  Lists ("80,443,8080")
    pass through unchanged; only dash-ranges are capped.

    Examples:
      "1-10000"  → "1-1024"   (capped)
      "80,443"   → "80,443"   (unchanged)
      "3000"     → "3000"     (unchanged)
      "1-100"    → "1-100"    (within limit)
    """
    parts = [p.strip() for p in ports.split(",")]
    result = []
    for part in parts:
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
                if hi_i - lo_i + 1 > max_width:
                    hi_i = lo_i + max_width - 1
                result.append(f"{lo_i}-{hi_i}")
            except (ValueError, TypeError):
                result.append(part)  # pass through malformed
        else:
            result.append(part)
    return ",".join(result)


# ═══════════════════════════════════════════════════════════════════════════
# Nmap - Port Scanner
# ═══════════════════════════════════════════════════════════════════════════


async def nmap(
    target: str,
    ports: str = "top100",
    scan_type: str = "quick"
) -> str:
    """
    Run nmap port scan.
    
    Args:
        target: IP/hostname/CIDR to scan
        ports: Port spec ("80,443", "1-1000", "top100", "all")
        scan_type: "quick", "full", "service", "vuln"
    
    Returns:
        JSON string with scan results
    """
    # Build command
    cmd = ["nmap", "-oX", "-"]  # XML output to stdout
    
    # Scan presets
    if scan_type == "quick":
        cmd.extend(["-sT", "-T4"])
    elif scan_type == "full":
        cmd.extend(["-sT", "-sV", "-sC", "-p-"])
    elif scan_type == "service":
        cmd.extend(["-sT", "-sV"])
    elif scan_type == "vuln":
        cmd.extend(["-sT", "--script", "vuln"])
    else:
        cmd.extend(["-sT", "-T4"])
    
    # Port specification (with safety cap)
    if ports == "top100":
        cmd.extend(["--top-ports", "100"])
    elif ports == "all":
        cmd.extend(["-p-"])
    else:
        # Validate and cap port ranges to prevent 142s+ scans
        sanitised = _cap_port_range(ports, max_width=1024)
        cmd.extend(["-p", sanitised])
    
    cmd.append(target)
    
    # Adaptive timeout: small scans fast, full scans slow
    effective_timeout = 120  # default
    if ports == "all" or scan_type in ("full", "vuln"):
        effective_timeout = 600
    
    # Execute
    stdout, stderr, code = await _run_command(cmd, timeout=effective_timeout)
    
    if code != 0:
        return json.dumps({
            "error": stderr or "nmap failed",
            "target": target
        })
    
    # Parse XML
    try:
        root = ET.fromstring(stdout)
        results = {
            "target": target,
            "hosts": []
        }
        
        for host in root.findall(".//host"):
            # Get IP
            addr = host.find("address[@addrtype='ipv4']")
            if addr is None:
                addr = host.find("address[@addrtype='ipv6']")
            if addr is None:
                continue
            
            ip = addr.get("addr", "")
            
            # Get status
            status = host.find("status")
            state = status.get("state", "unknown") if status is not None else "unknown"
            
            if state != "up":
                continue
            
            # Get ports
            ports_data = []
            for port in host.findall(".//port"):
                port_id = port.get("portid")
                protocol = port.get("protocol", "tcp")
                
                port_state = port.find("state")
                if port_state is None or port_state.get("state") != "open":
                    continue
                
                service_elem = port.find("service")
                service = service_elem.get("name", "") if service_elem is not None else ""
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""
                
                ports_data.append({
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service,
                    "product": product,
                    "version": version
                })
            
            if ports_data:
                results["hosts"].append({
                    "ip": ip,
                    "state": state,
                    "ports": ports_data
                })
        
        return json.dumps(results, indent=2)
    
    except Exception as e:
        return json.dumps({
            "error": f"Failed to parse nmap output: {e}",
            "target": target,
            "raw_output": stdout[:500]  # First 500 chars
        })


# ═══════════════════════════════════════════════════════════════════════════
# Httpx - HTTP Probe
# ═══════════════════════════════════════════════════════════════════════════


def _find_pd_httpx() -> str | None:
    """Find ProjectDiscovery httpx binary, avoiding Python httpx CLI collision.
    
    Cached after first call — avoids blocking subprocess.run on every httpx probe.
    """
    import shutil
    # Prefer known container path
    for candidate in ("/usr/local/bin/httpx", shutil.which("httpx")):
        if not candidate:
            continue
        try:
            # ProjectDiscovery httpx prints version like "Current Version: ..."
            import subprocess
            out = subprocess.run(
                [candidate, "-version"],
                capture_output=True, text=True, timeout=5,
            )
            combined = out.stdout + out.stderr
            # PD httpx contains "projectdiscovery" or "Current Version"
            if "projectdiscovery" in combined.lower() or "current version" in combined.lower():
                return candidate
        except Exception:
            continue
    return None


# Cache the result so we only probe once per process
from functools import lru_cache
_find_pd_httpx = lru_cache(maxsize=1)(_find_pd_httpx)


async def _httpx_probe_python(url: str) -> str:
    """Pure-Python fallback: probe URL using the httpx *library* (no binary needed)."""
    import re
    import httpx as httpx_lib

    # Normalise: add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    try:
        async with httpx_lib.AsyncClient(
            timeout=15, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(url)

        # Extract <title>
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text or "", re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:120]

        # Basic tech fingerprinting from headers
        tech: list[str] = []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        powered = headers_lower.get("x-powered-by", "")
        if powered:
            tech.append(powered)
        if "express" in headers_lower.get("x-powered-by", "").lower():
            tech.append("Express")
        if "asp.net" in (headers_lower.get("x-aspnet-version", "") + powered).lower():
            tech.append("ASP.NET")
        ct = headers_lower.get("content-type", "")
        if "json" in ct:
            tech.append("JSON-API")

        return json.dumps([{
            "url": str(resp.url),
            "status_code": resp.status_code,
            "title": title,
            "server": headers_lower.get("server", ""),
            "tech": tech,
            "content_length": int(headers_lower.get("content-length", 0)),
            "headers": dict(resp.headers),
        }], indent=2)

    except Exception as e:
        return json.dumps({"error": f"httpx probe failed: {e}", "url": url})


async def httpx_probe(url: str) -> str:
    """
    Probe URL for status, title, server, tech stack.

    Tries ProjectDiscovery httpx binary first (richer output);
    falls back to a pure-Python probe via the httpx library so the
    tool *always* returns useful data.
    """
    httpx_bin = _find_pd_httpx()

    # ── Fast path: PD binary available ──────────────────────────
    if httpx_bin:
        cmd = [
            httpx_bin,
            "-silent", "-json",
            "-status-code", "-title",
            "-tech-detect", "-server",
            "-u", url,
        ]

        stdout, stderr, code = await _run_command(cmd, timeout=60)

        if code == 0 and stdout.strip():
            try:
                lines = [l.strip() for l in stdout.split("\n") if l.strip()]
                results = []
                for line in lines:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", url),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "server": data.get("webserver", ""),
                        "tech": data.get("tech", []),
                        "content_length": data.get("content_length", 0),
                    })
                if results:
                    return json.dumps(results, indent=2)
            except Exception:
                pass  # fall through to Python fallback

    # ── Fallback: pure-Python probe ─────────────────────────────
    return await _httpx_probe_python(url)


# ═══════════════════════════════════════════════════════════════════════════
# Subfinder - Subdomain Enumeration
# ═══════════════════════════════════════════════════════════════════════════


async def subfinder(domain: str) -> str:
    """
    Find subdomains with subfinder.
    
    Args:
        domain: Domain to enumerate (e.g., "example.com")
    
    Returns:
        JSON string with subdomains
    """
    cmd = [
        "subfinder",
        "-d", domain,
        "-silent",
        "-all"
    ]
    
    stdout, stderr, code = await _run_command(cmd, timeout=120)
    
    if code != 0 and not stdout:
        return json.dumps({
            "error": stderr or "subfinder failed",
            "domain": domain
        })
    
    # Parse output (one subdomain per line)
    subdomains = [
        line.strip()
        for line in stdout.split('\n')
        if line.strip() and '.' in line
    ]
    
    return json.dumps({
        "domain": domain,
        "subdomains": subdomains,
        "count": len(subdomains)
    }, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# ffuf - Web Fuzzer
# ═══════════════════════════════════════════════════════════════════════════


async def ffuf(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    extensions: str = "",
    headers: str = "",
    filter_codes: str = "404",
    match_codes: str = "",
    timeout: int = 300,
) -> str:
    """
    Directory/file fuzzing with ffuf.

    Args:
        url: Target URL with FUZZ placeholder (e.g., "http://target.com/FUZZ")
        wordlist: Path to wordlist (default: dirb/common.txt)
        method: HTTP method (GET, POST)
        extensions: Comma-separated extensions to append (e.g., ".php,.html,.txt")
        headers: Additional headers in "Name: Value" format, separated by ;;
        filter_codes: Status codes to filter out (e.g., "404,403")
        match_codes: Status codes to match (e.g., "200,301")
        timeout: Timeout in seconds

    Returns:
        JSON string with found endpoints
    """
    # Ensure FUZZ keyword is present
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    # Resolve wordlist — check existence, fallback to alternatives
    import shutil
    from pathlib import Path
    _WORDLIST_CANDIDATES = [
        wordlist,
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]
    resolved_wl = wordlist
    for candidate in _WORDLIST_CANDIDATES:
        if Path(candidate).is_file():
            resolved_wl = candidate
            break
    else:
        # No wordlist found — check if ffuf is even installed
        if not shutil.which("ffuf"):
            return json.dumps({"error": "ffuf not installed", "url": url})
        return json.dumps({"error": f"No wordlist found (tried {wordlist})", "url": url})

    cmd = [
        "ffuf",
        "-u", url,
        "-w", resolved_wl,
        "-json",        # JSON output to stdout (ffuf v2.x)
        "-s",           # Silent mode (no banner/progress)
        "-t", "50",
        "-timeout", "10",
    ]

    if method.upper() != "GET":
        cmd.extend(["-X", method.upper()])

    if extensions:
        cmd.extend(["-e", extensions])

    if filter_codes:
        cmd.extend(["-fc", filter_codes])

    if match_codes:
        cmd.extend(["-mc", match_codes])
    else:
        cmd.extend(["-mc", "all"])

    if headers:
        for h in headers.split(";;"):
            h = h.strip()
            if h:
                cmd.extend(["-H", h])

    stdout, stderr, code = await _run_command(cmd, timeout=timeout)

    # ffuf v2.x with -json outputs one JSON object per line (NDJSON)
    # Collect all valid JSON lines
    if code != 0:
        # Try to extract useful info from whatever output exists
        hint = stderr.strip() or stdout.strip()[:200] or "unknown error"
        return json.dumps({
            "error": f"ffuf exited with code {code}: {hint}",
            "url": url,
        })

    try:
        results = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                r = json.loads(line)
                # ffuf v2 NDJSON: each line is a result object
                results.append({
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "lines": r.get("lines", 0),
                    "input": r.get("input", {}).get("FUZZ", "") if isinstance(r.get("input"), dict) else str(r.get("input", "")),
                    "redirect_location": r.get("redirectlocation", ""),
                })
            except (json.JSONDecodeError, TypeError):
                continue

        return json.dumps({
            "url": url,
            "results": results,
            "count": len(results),
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "error": f"Failed to parse ffuf output: {e}",
            "url": url,
            "raw": stdout[:300],
        })


# ═══════════════════════════════════════════════════════════════════════════
# Tool Schemas (for LLM)
# ═══════════════════════════════════════════════════════════════════════════


TOOL_SCHEMAS = {
    "nmap": {
        "name": "nmap",
        "description": (
            "Network port scanner — discovers open ports, running services, and their versions on a target. "
            "The foundation of every assessment: tells you what's exposed before you test it. "
            "**When to use**: First step in any assessment to map the attack surface. Use 'quick' scan "
            "for initial discovery (top 100 ports, ~5s), 'service' for version detection (top 1000 ports, "
            "~15s), 'vuln' to run NSE vulnerability scripts (~30s). Use 'full' only when you suspect "
            "services on non-standard ports (scans all 65535, ~2min). "
            "**When NOT to use**: To check if a web URL is alive (use httpx — it's faster). For web-layer "
            "vulnerabilities (use nuclei or http tool). "
            "**Performance tip**: ALWAYS start with scan_type='quick'. Only escalate to 'service' or 'vuln' "
            "if you need version info or NSE scripts. Wide port ranges are automatically capped to prevent "
            "excessive scan times. "
            "**Output**: JSON with open ports, services, versions, and any NSE script results. "
            "**Common mistake**: Using scan_type='full' as the first scan — it's slow and usually unnecessary."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, hostname, or CIDR to scan (e.g., '192.168.1.1', 'example.com', '10.0.0.0/24')"
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to scan: 'top100' (default, RECOMMENDED, fastest), a short list '80,443,3000,8080', or 'all' (slow). Ranges wider than 1024 ports are automatically capped.",
                    "default": "top100"
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "full", "service", "vuln"],
                    "description": "Scan depth: 'quick' (top 100, ~5s), 'service' (version detection, ~15s), 'vuln' (NSE scripts, ~30s), 'full' (all 65535 ports, ~2min). Start with 'quick', escalate if needed.",
                    "default": "quick"
                }
            },
            "required": ["target"]
        }
    },
    "httpx": {
        "name": "httpx",
        "description": (
            "HTTP probe (ProjectDiscovery) — fast technology fingerprinting and liveness check. "
            "Detects web server, framework, status code, page title, TLS info, and technology stack "
            "in a single request. Much faster than a full nmap service scan for web targets. "
            "**When to use**: As the first probe on any web target to detect what's running "
            "(Express, Django, WordPress, etc.), get the HTTP status code, check TLS certificate info, "
            "and identify the tech stack for targeted vulnerability testing. "
            "**When NOT to use**: For making custom HTTP requests with specific headers, POST bodies, "
            "or payloads (use the 'http' tool). For non-HTTP services (use nmap). "
            "**Output**: JSON with status_code, title, tech stack array, webserver, TLS info, content_length. "
            "**Workflow**: httpx first (what's running?) → nmap (what ports?) → nuclei (any known CVEs?)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL or host to probe (e.g., 'https://example.com', 'http://localhost:3000')"
                }
            },
            "required": ["url"]
        }
    },
    "subfinder": {
        "name": "subfinder",
        "description": (
            "Subdomain enumeration — discovers subdomains of a domain using passive sources "
            "(certificate transparency logs, search engines, DNS datasets). "
            "**When to use**: When assessing a domain (not an IP) and you want to discover "
            "additional attack surface — staging servers, admin panels, API endpoints, forgotten "
            "subdomains that may be less secured than the main site. "
            "**When NOT to use**: When testing a single IP or localhost. When the scope is limited "
            "to a specific URL (subdomains would be out of scope). "
            "**Output**: JSON array of discovered subdomains. "
            "**Workflow**: subfinder → httpx (check which are alive) → nmap + nuclei on live hosts."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Root domain to enumerate (e.g., 'example.com' — NOT a URL, just the domain)"
                }
            },
            "required": ["domain"]
        }
    },
    "ffuf": {
        "name": "ffuf",
        "description": (
            "Web fuzzer for directory and file discovery — bruteforces paths on a web server to find "
            "hidden endpoints, admin panels, backup files, configuration files, and API routes. "
            "Uses the FUZZ keyword as a placeholder in the URL that gets replaced with each wordlist entry. "
            "**When to use**: After initial recon to discover hidden content — admin panels (/admin, "
            "/dashboard), backup files (.bak, .old, .zip), config files (.env, .git/config, web.config), "
            "API endpoints (/api/v1, /graphql), sensitive directories (/debug, /status, /metrics). "
            "**When NOT to use**: When you already know the URL structure. For testing parameters "
            "(use http tool with payloads). For known CVE detection (use nuclei). "
            "**Performance**: Uses 100 threads by default. Filters 404s automatically. Add extensions "
            "like '.php,.bak,.old' to find backup files. "
            "**Output**: JSON array of discovered paths with status codes and response sizes. "
            "**Common mistake**: Forgetting to include FUZZ in the URL. If omitted, /FUZZ is appended automatically."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with FUZZ keyword (e.g., 'http://target.com/FUZZ'). If FUZZ is missing, /FUZZ is appended automatically."
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file. Default: /usr/share/wordlists/dirb/common.txt (~4600 entries, good general purpose).",
                    "default": "/usr/share/wordlists/dirb/common.txt"
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method: GET (default) or POST (for fuzzing API endpoints)",
                    "default": "GET"
                },
                "extensions": {
                    "type": "string",
                    "description": "Comma-separated file extensions to append to each word (e.g., '.php,.html,.bak,.old,.txt,.env'). Empty = directories only.",
                    "default": ""
                },
                "headers": {
                    "type": "string",
                    "description": "Additional headers, separated by ;; (e.g., 'Cookie: session=abc;; Authorization: Bearer token123')",
                    "default": ""
                },
                "filter_codes": {
                    "type": "string",
                    "description": "HTTP status codes to EXCLUDE from results (e.g., '404,403' to hide not-found and forbidden)",
                    "default": "404"
                },
                "match_codes": {
                    "type": "string",
                    "description": "HTTP status codes to INCLUDE exclusively (overrides filter). E.g., '200,301,302' to only show successful hits.",
                    "default": ""
                }
            },
            "required": ["url"]
        }
    },
}
