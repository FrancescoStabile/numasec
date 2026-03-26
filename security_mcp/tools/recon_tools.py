"""Reconnaissance tools: subdomain enum, DNS."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import socket
from typing import Any

from security_mcp.security.sandbox import ToolSandbox

logger = logging.getLogger("security_mcp.tools.recon")

_sandbox = ToolSandbox()


async def subfinder_scan(domain: str) -> dict[str, Any]:
    """Run subfinder for subdomain enumeration.

    Falls back to DNS brute-force of common prefixes if subfinder is not installed.
    """
    if shutil.which("subfinder"):
        logger.info("Running subfinder for %s", domain)
        cmd = ["subfinder", "-d", domain, "-silent", "-json"]
        try:
            output = await _sandbox.run(cmd, timeout=120)
        except Exception as exc:
            return {"success": False, "error": str(exc), "domain": domain, "subdomains": []}

        subdomains = []
        for line in output.stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", line)
            except json.JSONDecodeError:
                host = line
            if host and host not in subdomains:
                subdomains.append(host)

        return {"success": True, "domain": domain, "subdomains": subdomains, "tool": "subfinder"}

    # Fallback: resolve common prefixes via DNS
    logger.info("subfinder not found, using DNS fallback for %s", domain)
    prefixes = [
        "www",
        "mail",
        "ftp",
        "api",
        "dev",
        "staging",
        "admin",
        "test",
        "blog",
        "shop",
        "app",
        "cdn",
        "ns1",
        "ns2",
        "mx",
        "vpn",
    ]
    subdomains = []
    for prefix in prefixes:
        fqdn = f"{prefix}.{domain}"
        try:
            await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, fqdn)
            subdomains.append(fqdn)
        except socket.gaierror:
            continue

    return {"success": True, "domain": domain, "subdomains": subdomains, "tool": "dns_fallback"}


async def dns_lookup(domain: str, record_type: str = "A") -> dict[str, Any]:
    """DNS lookup for the given domain and record type.

    Supports A, AAAA, CNAME, MX, NS, TXT, SOA record types.
    Uses system resolver via socket for A/AAAA, nslookup fallback for others.
    """
    logger.info("DNS lookup: %s %s", record_type, domain)
    record_type = record_type.upper()

    # For A/AAAA, use socket (no external dependency)
    if record_type in ("A", "AAAA"):
        family = socket.AF_INET if record_type == "A" else socket.AF_INET6
        try:
            results = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM),
            )
            records = sorted({r[4][0] for r in results})
        except socket.gaierror as exc:
            return {"success": False, "error": str(exc), "domain": domain, "record_type": record_type, "records": []}

        return {
            "success": True,
            "domain": domain,
            "record_type": record_type,
            "records": records,
        }

    # For other record types, use nslookup (available on all platforms)
    cmd = ["nslookup", f"-type={record_type}", domain]
    try:
        output = await _sandbox.run(cmd, timeout=15)
    except Exception as exc:
        return {"success": False, "error": str(exc), "domain": domain, "record_type": record_type, "records": []}

    stdout = output.stdout.decode("utf-8", errors="replace")

    # Parse nslookup output
    records = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Server:") or line.startswith("Address:") and not records:
            continue
        if "=" in line or "address" in line.lower() or "mail exchanger" in line.lower():
            records.append(line)

    return {
        "success": output.rc == 0,
        "domain": domain,
        "record_type": record_type,
        "records": records,
        "raw": stdout,
    }
