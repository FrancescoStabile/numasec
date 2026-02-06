"""
NumaSec — Result Extractors

After every tool call, the appropriate extractor runs to populate
the TargetProfile with structured data. This is the key architectural
piece: it converts raw tool output into structured knowledge.

Design principles:
1. Never crash — extractors catch all exceptions
2. Be permissive in parsing — tools return messy output
3. Extract ALL useful information, not just the obvious
4. Generate hypotheses when patterns suggest vulnerabilities
"""

import json
import re
import hashlib
import logging
from typing import Any
from urllib.parse import urlparse

from numasec.target_profile import (
    TargetProfile, Port, Endpoint, Technology, Credential, VulnHypothesis
)

logger = logging.getLogger("numasec.extractors")


# ═══════════════════════════════════════════════════════════════════════════
# SPA (Single Page Application) Detection
# ═══════════════════════════════════════════════════════════════════════════

# Strong indicators — a single match is enough to confirm SPA framework
_SPA_STRONG_INDICATORS = (
    "<app-root",             # Angular
    "ng-version=",           # Angular compiled output
    "__NEXT_DATA__",         # Next.js
    'id="__nuxt"',           # Nuxt
    "data-reactroot",        # React
    "ng-app=",               # AngularJS (legacy)
    "window.__remixContext", # Remix
    "/_nuxt/",               # Nuxt (script src)
)

# Paths that should NEVER legitimately return the application’s HTML shell.
# If a 200 text/html response on one of these contains the app title/hash
# → it is a SPA catch-all, NOT a real exposed file.
_SENSITIVE_PATH_FRAGMENTS = (
    "/.git", "/.env", "/.svn", "/.hg", "/.DS_Store",
    "/.htaccess", "/.htpasswd", "/.config",
    "/web.config", "/wp-config",
    "/server-status", "/server-info", "/phpinfo",
)
_SENSITIVE_EXTENSIONS = (
    ".bak", ".sql", ".log", ".key", ".pem", ".conf",
    ".xml", ".yml", ".yaml", ".ini", ".cfg",
    ".zip", ".tar", ".gz", ".rar",
    ".pyc", ".class", ".jar", ".kdbx",
)


def _compute_body_hash(body: str) -> str:
    """Compute a normalised MD5 hash of the first 3 KB of an HTML body.

    Strips dynamic tokens (CSRF nonces, timestamps) and collapses whitespace
    so that minor per-request variations do not defeat the comparison.
    """
    normalised = re.sub(
        r'(?:nonce|csrf|token|timestamp|cachebust)[=\-]["\'][^"\']*["\']',
        "", body[:3000], flags=re.IGNORECASE,
    )
    normalised = re.sub(r"\s+", " ", normalised).strip()
    return hashlib.md5(normalised.encode(errors="replace")).hexdigest()


def _has_spa_indicators(body: str) -> bool:
    """Return *True* if the HTML body contains strong SPA framework markers."""
    sample = body[:15000].lower()
    return any(ind.lower() in sample for ind in _SPA_STRONG_INDICATORS)


def _update_spa_fingerprint(
    profile: TargetProfile, url: str, status: int,
    h_lower: dict, body: str,
) -> None:
    """Store SPA shell fingerprint from the root page.

    Called for every HTTP 200 response.  Only stores data when the
    response is the root path ("/" or "") so we get a reliable baseline.
    """
    if status != 200 or not body:
        return
    content_type = h_lower.get("content-type", "")
    if "text/html" not in content_type:
        return

    path = urlparse(url).path.rstrip("/")
    if path not in ("", "/"):
        return  # only fingerprint the root page

    if not profile.spa_shell_hash:
        profile.spa_shell_hash = _compute_body_hash(body)

    if not profile.spa_shell_title:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            profile.spa_shell_title = m.group(1).strip()[:120]

    if not profile.spa_detected:
        profile.spa_detected = _has_spa_indicators(body)


def _is_spa_catchall(
    profile: TargetProfile, url: str, status: int,
    h_lower: dict, body: str,
) -> bool:
    """Return *True* if this 200 response is a SPA catch-all.

    Detection strategy:
    1. Only applies to ``200 text/html`` responses on *sensitive* paths.
    2. If the response body contains the known SPA page title → catch-all.
    3. If the response body hash matches the root shell hash → catch-all.
    """
    if status != 200 or not body:
        return False
    content_type = h_lower.get("content-type", "")
    if "text/html" not in content_type:
        return False

    path = urlparse(url).path.lower().rstrip("/")
    if path in ("", "/"):
        return False  # the root IS the shell — that’s expected

    # Is this a path where an HTML response is suspicious?
    is_suspicious = (
        any(path.startswith(frag) or frag.lstrip("/") == path.lstrip("/")
            for frag in _SENSITIVE_PATH_FRAGMENTS)
        or any(path.endswith(ext) for ext in _SENSITIVE_EXTENSIONS)
    )
    if not is_suspicious:
        return False

    # Title match (most reliable, works even before body hash is stored)
    if profile.spa_shell_title and len(profile.spa_shell_title) > 2:
        if profile.spa_shell_title.lower() in body[:5000].lower():
            return True

    # Body hash match (catches edge cases where title appears differently)
    if profile.spa_shell_hash:
        if _compute_body_hash(body) == profile.spa_shell_hash:
            return True

    return False


def _safe_json(result: str) -> dict | list | None:
    """Safely parse JSON from tool result."""
    try:
        return json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return None


def extract_nmap(profile: TargetProfile, result: str, args: dict):
    """Extract ports, services, OS from nmap result."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return
    if "error" in data and "hosts" not in data:
        return

    for host in data.get("hosts", []):
        for port_data in host.get("ports", []):
            port = Port(
                number=port_data.get("port", 0),
                protocol=port_data.get("protocol", "tcp"),
                state="open",
                service=port_data.get("service", ""),
                product=port_data.get("product", ""),
                version=port_data.get("version", ""),
            )
            profile.add_port(port)

            # Auto-detect technologies from service info
            product = port_data.get("product", "")
            version = port_data.get("version", "")
            if product:
                category = "server"
                prod_lower = product.lower()
                if any(w in prod_lower for w in ("apache", "nginx", "iis", "lighttpd", "caddy")):
                    category = "server"
                elif any(w in prod_lower for w in ("openssh", "dropbear")):
                    category = "ssh"
                elif any(w in prod_lower for w in ("mysql", "postgres", "mariadb", "mssql", "mongodb", "redis")):
                    category = "database"
                elif any(w in prod_lower for w in ("php", "python", "node", "java", "ruby")):
                    category = "language"
                profile.add_technology(Technology(name=product, version=version, category=category))

        # OS detection
        os_info = host.get("os", "")
        if os_info:
            profile.os_guess = os_info


def extract_http(profile: TargetProfile, result: str, args: dict):
    """Extract endpoint info, technologies, WAF detection from HTTP result."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return
    if "error" in data and "status_code" not in data:
        return

    url = args.get("url", "")
    method = args.get("method", "GET")
    status = data.get("status_code")
    headers = data.get("headers", {})
    h_lower = {k.lower(): v for k, v in headers.items()} if isinstance(headers, dict) else {}
    body = str(data.get("body", ""))

    # ── SPA shell fingerprinting (root page only) ──
    _update_spa_fingerprint(profile, url, status, h_lower, body)

    # Build endpoint
    endpoint = Endpoint(
        url=url,
        method=method,
        status_code=status,
        content_type=h_lower.get("content-type", ""),
        auth_required=(status in (401, 403)),
    )

    # Extract URL parameters
    if "?" in url:
        query = url.split("?", 1)[1]
        params = [p.split("=")[0] for p in query.split("&") if "=" in p]
        endpoint.parameters = params
        endpoint.interesting = True

    # Detect interesting status codes
    if status in (200, 301, 302, 401, 403, 500):
        endpoint.interesting = True

    # ── SPA catch-all detection ──
    # If this 200 text/html response is just the app shell served for a
    # sensitive path, record the endpoint but skip all hypothesis generation.
    if _is_spa_catchall(profile, url, status, h_lower, body):
        profile.spa_detected = True
        endpoint.notes = "SPA catch-all (app shell HTML, NOT the real resource)"
        endpoint.interesting = False
        profile.add_endpoint(endpoint)
        return

    profile.add_endpoint(endpoint)

    # Server header -> technology
    server = h_lower.get("server", "")
    if server:
        profile.server_header = server
        profile.add_technology(Technology(name=server, category="server"))

    x_powered = h_lower.get("x-powered-by", "")
    if x_powered:
        profile.add_technology(Technology(name=x_powered, category="framework"))

    # WAF detection from headers/body
    if status == 403:
        waf_signatures = [
            ("cloudflare", "Cloudflare"),
            ("akamai", "Akamai"),
            ("incapsula", "Incapsula"),
            ("sucuri", "Sucuri"),
            ("barracuda", "Barracuda"),
            ("modsecurity", "ModSecurity"),
            ("f5", "F5 BIG-IP"),
        ]
        combined = str(headers).lower() + str(data.get("body", "")).lower()
        for sig, name in waf_signatures:
            if sig in combined:
                profile.waf_detected = True
                profile.waf_type = name
                break

    # Auto-hypothesize based on response patterns
    body = str(data.get("body", ""))
    if endpoint.parameters and status == 200:
        for param in endpoint.parameters:
            profile.add_hypothesis(VulnHypothesis(
                vuln_type="sqli",
                location=f"{url} (param: {param})",
                evidence="Parameter found in URL, untested",
                confidence=0.2,
            ))

    # Detect error messages that suggest vulnerabilities
    error_patterns = {
        "sqli": [r"sql syntax", r"mysql_", r"pg_query", r"sqlite3\.", r"ORA-\d{5}", r"ODBC.*Driver", r"mysql_fetch"],
        "lfi": [r"include\(", r"failed to open stream", r"No such file", r"Warning.*file_get_contents"],
        "ssti": [r"\$\{.*\}", r"\{\{.*\}\}", r"<%.*%>"],
        "info_leak": [r"stack trace", r"traceback", r"debug.*true", r"PHPSESSID"],
    }
    for vuln_type, patterns in error_patterns.items():
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                profile.add_hypothesis(VulnHypothesis(
                    vuln_type=vuln_type,
                    location=url,
                    evidence=f"Pattern '{pattern}' found in response body",
                    confidence=0.6,
                ))
                break  # One match per vuln_type is enough


def extract_nuclei(profile: TargetProfile, result: str, args: dict):
    """Extract vulnerability findings from nuclei."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return
    if "error" in data and "findings" not in data:
        return

    confidence_map = {"critical": 0.95, "high": 0.9, "medium": 0.7, "low": 0.5, "info": 0.3}

    for finding in data.get("findings", []):
        severity = finding.get("severity", "info")
        profile.add_hypothesis(VulnHypothesis(
            vuln_type=finding.get("template", "unknown"),
            location=finding.get("matched_at", args.get("url", "")),
            evidence=f"Nuclei template: {finding.get('name', '')} [{severity}]",
            confidence=confidence_map.get(severity, 0.5),
            tested=True,
            confirmed=(severity in ("critical", "high")),
            tool_used="nuclei",
        ))


def extract_httpx(profile: TargetProfile, result: str, args: dict):
    """Extract tech stack from httpx probe."""
    data = _safe_json(result)
    if not data:
        return

    items = data if isinstance(data, list) else [data]

    # Known SPA frameworks (lowercase for comparison)
    _spa_frameworks = {
        "angular", "react", "vue", "vue.js", "nuxt", "nuxt.js",
        "next.js", "svelte", "ember", "ember.js", "gatsby",
    }

    for item in items:
        if not isinstance(item, dict):
            continue

        # Technologies
        for tech in item.get("tech", []):
            profile.add_technology(Technology(name=tech, category="detected"))
            # Detect SPA framework from httpx tech fingerprinting
            if tech.lower() in _spa_frameworks:
                profile.spa_detected = True

        # Server
        server = item.get("server", "")
        if server:
            profile.add_technology(Technology(name=server, category="server"))

        # Store main page title for SPA catch-all detection
        title = item.get("title", "")
        if title and not profile.spa_shell_title:
            profile.spa_shell_title = title

        # Endpoint
        url = item.get("url", args.get("url", ""))
        if url:
            profile.add_endpoint(Endpoint(
                url=url,
                status_code=item.get("status_code", None),
                content_type=item.get("content_type", ""),
                interesting=True,
            ))


def extract_subfinder(profile: TargetProfile, result: str, args: dict):
    """Extract subdomains."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return

    for sub in data.get("subdomains", []):
        if sub and sub not in profile.subdomains:
            profile.subdomains.append(sub)
            if sub not in profile.scope:
                profile.scope.append(sub)


def extract_sqlmap(profile: TargetProfile, result: str, args: dict):
    """Extract SQLi findings from sqlmap."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return

    url = args.get("url", data.get("url", ""))
    vulnerable = data.get("vulnerable", False)
    dbms = data.get("dbms", "")

    if vulnerable:
        profile.add_hypothesis(VulnHypothesis(
            vuln_type="sqli",
            location=url,
            evidence=f"SQLMap confirmed. DBMS: {dbms}. Params: {data.get('injectable_parameters', [])}",
            confidence=1.0,
            tested=True,
            confirmed=True,
            tool_used="sqlmap",
        ))

        if dbms:
            profile.add_technology(Technology(name=dbms, category="database"))
    else:
        # Mark existing hypothesis as tested-not-confirmed
        for h in profile.hypotheses:
            if h.vuln_type == "sqli" and url in h.location and not h.tested:
                h.tested = True
                h.confirmed = False
                h.tool_used = "sqlmap"
                break


def extract_browser(profile: TargetProfile, result: str, tool_name: str, args: dict):
    """Extract endpoint info from browser navigation."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return

    url = args.get("url", "")
    if url:
        status = data.get("status_code", data.get("status", None))
        profile.add_endpoint(Endpoint(
            url=url,
            status_code=status,
            notes=f"Visited via {tool_name}",
            interesting=True,
        ))

    # Detect technologies from page content
    tech_indicators = {
        "WordPress": "cms", "Joomla": "cms", "Drupal": "cms",
        "Django": "framework", "Laravel": "framework", "Express": "framework",
        "Flask": "framework", "Rails": "framework", "Spring": "framework",
        "React": "frontend", "Angular": "frontend", "Vue": "frontend",
        "jQuery": "frontend", "Bootstrap": "frontend",
    }
    content_str = str(data).lower()
    for tech, cat in tech_indicators.items():
        if tech.lower() in content_str:
            profile.add_technology(Technology(name=tech, category=cat))


def extract_ffuf(profile: TargetProfile, result: str, args: dict):
    """Extract discovered directories/files from ffuf."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return

    for item in data.get("results", []):
        url = item.get("url", "")
        status = item.get("status", 0)
        if url:
            endpoint = Endpoint(
                url=url,
                status_code=status,
                interesting=(status in (200, 301, 302, 401, 403)),
            )
            profile.add_endpoint(endpoint)


def extract_run_command(profile: TargetProfile, result: str, args: dict):
    """Extract useful info from generic command output."""
    data = _safe_json(result)
    if not data or not isinstance(data, dict):
        return

    stdout = data.get("stdout", "")
    if not stdout:
        return

    # Detect credential patterns in command output
    cred_patterns = [
        (r'(?:user(?:name)?|login)\s*[=:]\s*["\']?(\S+)["\']?', r'(?:pass(?:word)?|pwd)\s*[=:]\s*["\']?(\S+)["\']?'),
    ]
    for user_pat, pass_pat in cred_patterns:
        users = re.findall(user_pat, stdout, re.IGNORECASE)
        passwords = re.findall(pass_pat, stdout, re.IGNORECASE)
        for u, p in zip(users, passwords):
            if u and p and len(u) < 50 and len(p) < 100:
                profile.add_credential(Credential(
                    username=u, password=p, source="run_command output"
                ))


# ═══════════════════════════════════════════════════════════════════════════
# Dispatcher
# ═══════════════════════════════════════════════════════════════════════════

EXTRACTORS: dict[str, Any] = {
    "nmap": lambda profile, result, args: extract_nmap(profile, result, args),
    "http": lambda profile, result, args: extract_http(profile, result, args),
    "nuclei": lambda profile, result, args: extract_nuclei(profile, result, args),
    "httpx": lambda profile, result, args: extract_httpx(profile, result, args),
    "subfinder": lambda profile, result, args: extract_subfinder(profile, result, args),
    "sqlmap": lambda profile, result, args: extract_sqlmap(profile, result, args),
    "run_command": lambda profile, result, args: extract_run_command(profile, result, args),
    "ffuf": lambda profile, result, args: extract_ffuf(profile, result, args),
}

# Browser tools
for _bt in ("browser_navigate", "browser_fill", "browser_click",
            "browser_screenshot", "browser_login", "browser_get_cookies"):
    EXTRACTORS[_bt] = lambda profile, result, args, tn=_bt: extract_browser(profile, result, tn, args)


def run_extractor(tool_name: str, profile: TargetProfile, result: str, args: dict):
    """
    Run the appropriate extractor for a tool result.
    Never raises — all errors are caught and logged.
    """
    extractor = EXTRACTORS.get(tool_name)
    if not extractor:
        return

    try:
        extractor(profile, result, args)
    except Exception as e:
        logger.warning(f"Extractor failed for {tool_name}: {e}", exc_info=True)
