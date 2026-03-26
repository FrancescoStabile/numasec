"""Python-native subdomain discovery scanner.

Multi-source subdomain enumeration:
1. DNS brute-force: Resolve common prefixes with asyncio + dnspython.
2. Certificate Transparency: Query crt.sh API for CT log entries.

Designed as a zero-external-binary fallback for subfinder.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("security_mcp.scanners.subdomain_scanner")

# ---------------------------------------------------------------------------
# Common subdomain prefixes — top ~500 by frequency
# ---------------------------------------------------------------------------

COMMON_PREFIXES: list[str] = [
    # Tier 1: almost universal
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "blog",
    "shop",
    "app",
    "cdn",
    "ns1",
    "ns2",
    "mx",
    "vpn",
    # Tier 2: very common
    "m",
    "mobile",
    "www2",
    "portal",
    "secure",
    "web",
    "intranet",
    "beta",
    "demo",
    "qa",
    "uat",
    "prod",
    "production",
    "pre",
    "img",
    "images",
    "static",
    "assets",
    "media",
    "video",
    "docs",
    "doc",
    "wiki",
    "help",
    "support",
    "kb",
    "smtp",
    "pop",
    "imap",
    "webmail",
    "email",
    "mx1",
    "mx2",
    "ns3",
    "ns4",
    "dns",
    "dns1",
    "dns2",
    "db",
    "database",
    "mysql",
    "postgres",
    "mongo",
    "redis",
    "elastic",
    "git",
    "gitlab",
    "github",
    "bitbucket",
    "svn",
    "repo",
    "ci",
    "cd",
    "jenkins",
    "bamboo",
    "drone",
    "build",
    "monitor",
    "monitoring",
    "grafana",
    "prometheus",
    "kibana",
    "nagios",
    "log",
    "logs",
    "syslog",
    "logstash",
    "elk",
    # Tier 3: common in enterprise
    "auth",
    "sso",
    "login",
    "oauth",
    "identity",
    "idp",
    "ldap",
    "ad",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "s3",
    "proxy",
    "gateway",
    "lb",
    "balancer",
    "edge",
    "search",
    "solr",
    "elasticsearch",
    "cache",
    "memcached",
    "varnish",
    "queue",
    "rabbit",
    "rabbitmq",
    "kafka",
    "mq",
    "storage",
    "backup",
    "archive",
    "nfs",
    "san",
    "voip",
    "sip",
    "pbx",
    "phone",
    "tel",
    "vpn1",
    "vpn2",
    "remote",
    "rdp",
    "ssh",
    "bastion",
    "jump",
    "crm",
    "erp",
    "hr",
    "finance",
    "billing",
    "invoice",
    "analytics",
    "stats",
    "tracking",
    "pixel",
    "cms",
    "wordpress",
    "wp",
    "drupal",
    "joomla",
    "forum",
    "community",
    "social",
    "chat",
    "slack",
    "teams",
    "status",
    "health",
    "uptime",
    "ping",
    "api1",
    "api2",
    "api-v1",
    "api-v2",
    "rest",
    "graphql",
    "download",
    "downloads",
    "files",
    "upload",
    "uploads",
    "service",
    "services",
    "srv",
    "svc",
    "internal",
    "private",
    "corp",
    "corporate",
    "staging1",
    "staging2",
    "dev1",
    "dev2",
    "test1",
    "test2",
    "sandbox",
    "playground",
    "lab",
    "labs",
    # Tier 4: less common but valuable
    "news",
    "press",
    "ir",
    "investor",
    "career",
    "careers",
    "jobs",
    "recruit",
    "partners",
    "partner",
    "affiliate",
    "affiliates",
    "customer",
    "clients",
    "client",
    "vendor",
    "vendors",
    "supplier",
    "suppliers",
    "training",
    "learn",
    "academy",
    "education",
    "marketing",
    "promo",
    "campaign",
    "ads",
    "payment",
    "pay",
    "checkout",
    "order",
    "orders",
    "report",
    "reports",
    "dashboard",
    "ticket",
    "tickets",
    "helpdesk",
    "jira",
    "confluence",
    "notion",
    "sharepoint",
    "exchange",
    "owa",
    "autodiscover",
    "relay",
    "smtp2",
    "postfix",
    "sendgrid",
    "waf",
    "firewall",
    "ids",
    "ips",
    "scan",
    "scanner",
    "pentest",
    "stg",
    "prd",
    "tst",
    "acc",
    "acceptance",
    "preview",
    "canary",
    "alpha",
    "rc",
    "release",
    "origin",
    "backend",
    "frontend",
    "ui",
    "ws",
    "websocket",
    "wss",
    "socket",
    "feed",
    "rss",
    "atom",
    "xml",
    "legacy",
    "old",
    "archive",
    "v1",
    "v2",
    "v3",
    "node",
    "node1",
    "node2",
    "cluster",
    "master",
    "slave",
    "primary",
    "replica",
    "data",
    "bigdata",
    "hadoop",
    "spark",
    "ml",
    "ai",
    "model",
    "predict",
    "docker",
    "k8s",
    "kubernetes",
    "rancher",
    "consul",
    "vault",
    "nomad",
    "terraform",
    "go",
    "java",
    "python",
    "ruby",
    "php",
    "new",
    "next",
    "beta2",
    "preview2",
    "www1",
    "www3",
    "site",
    "sites",
    "host",
    "hosted",
    "hosting",
    "local",
    "localhost",
    "loopback",
    "temp",
    "tmp",
    "scratch",
    "extra",
    "misc",
    "util",
    "tools",
    "tool",
    "info",
    "about",
    "contact",
    "en",
    "es",
    "fr",
    "de",
    "it",
    "pt",
    "ja",
    "zh",
    "ko",
    "ru",
    # Catch remaining common patterns
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "x",
    "y",
    "z",
    "www-dev",
    "www-staging",
    "www-test",
    "api-dev",
    "api-staging",
    "api-test",
    "app-dev",
    "app-staging",
    "app-test",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SubdomainEntry:
    """A discovered subdomain."""

    name: str
    ip: str = ""
    source: str = ""  # "dns" | "ct"


@dataclass
class SubdomainResult:
    """Complete subdomain scan result."""

    domain: str
    subdomains: list[SubdomainEntry] = field(default_factory=list)
    total_found: int = 0
    dns_checked: int = 0
    ct_found: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "domain": self.domain,
            "subdomains": [{"name": s.name, "ip": s.ip, "source": s.source} for s in self.subdomains],
            "total_found": self.total_found,
            "dns_checked": self.dns_checked,
            "ct_found": self.ct_found,
            "duration_ms": round(self.duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Subdomain scanner engine
# ---------------------------------------------------------------------------


class PythonSubdomainScanner:
    """Multi-source subdomain enumerator.

    Parameters
    ----------
    dns_concurrency:
        Max concurrent DNS resolution tasks.
    timeout:
        Per-query timeout in seconds.
    """

    def __init__(self, dns_concurrency: int = 100, timeout: float = 5.0) -> None:
        self.dns_concurrency = dns_concurrency
        self.timeout = timeout
        self._sem = asyncio.Semaphore(dns_concurrency)

    async def scan(
        self,
        domain: str,
        sources: list[str] | None = None,
        prefixes: list[str] | None = None,
    ) -> SubdomainResult:
        """Enumerate subdomains using multiple sources.

        Args:
            domain: Base domain to enumerate (e.g. ``"example.com"``).
            sources: Sources to use. Options: ``"dns"``, ``"ct"``.
                ``None`` uses all available.
            prefixes: Custom prefix list for DNS brute-force. ``None``
                uses the built-in ``COMMON_PREFIXES`` list.

        Returns:
            ``SubdomainResult`` with all discovered subdomains.
        """
        start = time.monotonic()
        result = SubdomainResult(domain=domain)
        active_sources = sources or ["dns", "ct"]

        # Deduplicate via a set of seen FQDNs
        seen: set[str] = set()
        tasks: list[asyncio.Task[list[SubdomainEntry]]] = []

        if "dns" in active_sources:
            tasks.append(
                asyncio.create_task(
                    self._dns_brute_force(domain, prefixes or COMMON_PREFIXES),
                )
            )
        if "ct" in active_sources:
            tasks.append(
                asyncio.create_task(
                    self._ct_lookup(domain),
                )
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in results:
            if isinstance(batch, BaseException):
                logger.warning("Subdomain source failed: %s", batch)
                continue
            for entry in batch:
                fqdn = entry.name.lower().rstrip(".")
                if fqdn not in seen:
                    seen.add(fqdn)
                    entry.name = fqdn
                    result.subdomains.append(entry)
                    if entry.source == "dns":
                        result.dns_checked += 1
                    elif entry.source == "ct":
                        result.ct_found += 1

        result.total_found = len(result.subdomains)
        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Subdomain scan complete: %s — %d found (dns=%d, ct=%d), %.0fms",
            domain,
            result.total_found,
            result.dns_checked,
            result.ct_found,
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Source 1: DNS brute-force
    # ------------------------------------------------------------------

    async def _dns_brute_force(
        self,
        domain: str,
        prefixes: list[str],
    ) -> list[SubdomainEntry]:
        """Resolve common subdomain prefixes via DNS.

        Uses dnspython's async resolver for parallel resolution.
        """
        import dns.asyncresolver
        import dns.exception

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        entries: list[SubdomainEntry] = []

        async def _resolve(prefix: str) -> SubdomainEntry | None:
            fqdn = f"{prefix}.{domain}"
            async with self._sem:
                try:
                    answers = await resolver.resolve(fqdn, "A")
                    ip = str(answers[0]) if answers else ""
                    return SubdomainEntry(name=fqdn, ip=ip, source="dns")
                except (
                    dns.asyncresolver.NXDOMAIN,
                    dns.asyncresolver.NoAnswer,
                    dns.asyncresolver.NoNameservers,
                    dns.exception.Timeout,
                    dns.exception.DNSException,
                ):
                    return None

        tasks = [_resolve(prefix) for prefix in prefixes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, SubdomainEntry):
                entries.append(r)

        logger.info(
            "DNS brute-force: %d/%d prefixes resolved for %s",
            len(entries),
            len(prefixes),
            domain,
        )
        return entries

    # ------------------------------------------------------------------
    # Source 2: Certificate Transparency (crt.sh)
    # ------------------------------------------------------------------

    async def _ct_lookup(self, domain: str) -> list[SubdomainEntry]:
        """Query crt.sh Certificate Transparency API.

        Returns unique subdomain names found in CT logs.
        """
        entries: list[SubdomainEntry] = []
        ct_url = f"https://crt.sh/?q=%25.{domain}&output=json"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(ct_url)
                if resp.status_code != 200:
                    logger.warning("crt.sh returned %d for %s", resp.status_code, domain)
                    return entries

                data = resp.json()
                seen: set[str] = set()

                for entry in data:
                    name_value = entry.get("name_value", "")
                    # crt.sh can return multiline entries
                    for name in name_value.split("\n"):
                        name = name.strip().lower().rstrip(".")
                        # Filter wildcards and non-matching domains
                        if name.startswith("*."):
                            name = name[2:]
                        if not name.endswith(f".{domain}") and name != domain:
                            continue
                        if name not in seen:
                            seen.add(name)
                            entries.append(
                                SubdomainEntry(
                                    name=name,
                                    ip="",
                                    source="ct",
                                )
                            )

        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.warning("crt.sh lookup failed for %s: %s", domain, exc)

        logger.info("CT lookup: %d subdomains found for %s", len(entries), domain)
        return entries


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_subdomain_scan(
    domain: str,
    sources: str | None = None,
) -> str:
    """Enumerate subdomains for a domain.

    Args:
        domain: Target domain (e.g. ``"example.com"``).
        sources: Comma-separated sources: ``"dns"``, ``"ct"``.
            ``None`` uses all.

    Returns:
        JSON string with subdomain scan results.
    """
    source_list = [s.strip() for s in sources.split(",")] if sources else None
    scanner = PythonSubdomainScanner()
    result = await scanner.scan(domain, sources=source_list)
    return json.dumps(result.to_dict(), indent=2)
