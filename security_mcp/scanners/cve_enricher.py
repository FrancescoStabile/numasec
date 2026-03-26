"""CVE enrichment for discovered service versions.

Two-layer lookup:
1. Local KB template (cve-service-mappings.yaml) -- instant, offline, covers top 100 services
2. NVD API (optional, when SECMCP_NVD_API_KEY is set) -- covers everything else, cached 7 days
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Cache lives under ~/.security_mcp/cache/ as a standalone JSON file.
# We deliberately avoid importing CheckpointStore to prevent circular imports
# (scanners -> storage -> models -> scanners).
_CACHE_DIR = Path.home() / ".security_mcp" / "cache"
_CACHE_FILE = _CACHE_DIR / "cve_cache.json"
_CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days

# NVD API v2.0 endpoint
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_TIMEOUT = 10.0
_NVD_MAX_RESULTS = 10

# Retry configuration for 429 responses
_NVD_MAX_RETRIES = 3
_NVD_BACKOFF_BASE = 2.0  # seconds; exponential: 2, 4, 8

# Maps common service names to CPE vendor:product pairs.
# CPE 2.3 format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
_CPE_VENDOR_MAP: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "iis": ("microsoft", "internet_information_services"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "tomcat": ("apache", "tomcat"),
    "nodejs": ("nodejs", "node.js"),
    "openssl": ("openssl", "openssl"),
    "php": ("php", "php"),
    "proftpd": ("proftpd_project", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "mongodb": ("mongodb", "mongodb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "memcached": ("memcached", "memcached"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "jenkins": ("jenkins", "jenkins"),
    "grafana": ("grafana", "grafana"),
    "gitlab": ("gitlab", "gitlab"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "express": ("expressjs", "express"),
    "flask": ("palletsprojects", "flask"),
    "django": ("djangoproject", "django"),
    "spring": ("vmware", "spring_framework"),
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-software", "varnish_cache"),
    "squid": ("squid-cache", "squid"),
    "bind": ("isc", "bind"),
    "samba": ("samba", "samba"),
    "mariadb": ("mariadb", "mariadb"),
    "mssql": ("microsoft", "sql_server"),
    "oracle_db": ("oracle", "database_server"),
}

# Regex patterns for extracting service + version from banner strings.
# Order matters: more specific patterns first.
_BANNER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"OpenSSH[_/]\s*(\d+\.\d+(?:\.\d+)?(?:p\d+)?)"), "openssh"),
    (re.compile(r"Apache[/\s]+(\d+\.\d+(?:\.\d+)?)"), "apache"),
    (re.compile(r"nginx[/\s]+(\d+\.\d+(?:\.\d+)?)"), "nginx"),
    (re.compile(r"Microsoft-IIS[/\s]+(\d+\.\d+)"), "iis"),
    (re.compile(r"MySQL\s+(\d+\.\d+(?:\.\d+)?)"), "mysql"),
    (re.compile(r"MariaDB[- ]+(\d+\.\d+(?:\.\d+)?)"), "mariadb"),
    (re.compile(r"PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)"), "postgresql"),
    (re.compile(r"Redis[/ ]v?=?(\d+\.\d+(?:\.\d+)?)"), "redis"),
    (re.compile(r"ProFTPD\s+(\d+\.\d+(?:\.\d+)?)"), "proftpd"),
    (re.compile(r"vsftpd\s+(\d+\.\d+(?:\.\d+)?)"), "vsftpd"),
    (re.compile(r"Postfix"), "postfix"),
    (re.compile(r"Exim\s+(\d+\.\d+(?:\.\d+)?)"), "exim"),
    (re.compile(r"Dovecot"), "dovecot"),
    (re.compile(r"LiteSpeed[/\s]+(\d+\.\d+(?:\.\d+)?)"), "litespeed"),
    (re.compile(r"lighttpd[/\s]+(\d+\.\d+(?:\.\d+)?)"), "lighttpd"),
    (re.compile(r"Apache[- ]Tomcat[/\s]+(\d+\.\d+(?:\.\d+)?)"), "tomcat"),
    (re.compile(r"Elasticsearch[/\s]+(\d+\.\d+(?:\.\d+)?)"), "elasticsearch"),
    (re.compile(r"MongoDB\s+(\d+\.\d+(?:\.\d+)?)"), "mongodb"),
    (re.compile(r"Jenkins[/\s]+(\d+\.\d+(?:\.\d+)?)"), "jenkins"),
    (re.compile(r"PHP[/\s]+(\d+\.\d+(?:\.\d+)?)"), "php"),
    (re.compile(r"OpenSSL[/\s]+(\d+\.\d+(?:\.\d+)?[a-z]?)"), "openssl"),
    (re.compile(r"Express[/\s]*$", re.IGNORECASE), "express"),
]

# Service name normalization aliases
_SERVICE_ALIASES: dict[str, str] = {
    "openssh": "openssh",
    "ssh": "openssh",
    "apache": "apache",
    "apache httpd": "apache",
    "apache http server": "apache",
    "httpd": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "microsoft-iis": "iis",
    "microsoft iis": "iis",
    "internet information services": "iis",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "proftpd": "proftpd",
    "vsftpd": "vsftpd",
    "postfix": "postfix",
    "exim": "exim",
    "lighttpd": "lighttpd",
    "litespeed": "litespeed",
    "elasticsearch": "elasticsearch",
    "mongodb": "mongodb",
    "memcached": "memcached",
    "openssl": "openssl",
    "php": "php",
    "nodejs": "nodejs",
    "node.js": "nodejs",
    "node": "nodejs",
    "express": "express",
    "jenkins": "jenkins",
    "grafana": "grafana",
    "gitlab": "gitlab",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "haproxy": "haproxy",
    "varnish": "varnish",
    "squid": "squid",
    "bind": "bind",
    "samba": "samba",
    "mssql": "mssql",
    "microsoft sql server": "mssql",
    "sql server": "mssql",
    "dovecot": "dovecot",
    "rabbitmq": "rabbitmq",
    "flask": "flask",
    "django": "django",
    "spring": "spring",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CVEMatch:
    """A CVE correlated with a discovered service version."""

    cve_id: str
    cvss_score: float
    severity: str  # critical / high / medium / low
    summary: str  # one-line description
    exploit_available: bool  # public exploit exists?
    source: str  # "kb" or "nvd"


# ---------------------------------------------------------------------------
# CVE enrichment engine
# ---------------------------------------------------------------------------


class CVEEnricher:
    """Correlate discovered service versions with known CVEs.

    Uses a two-layer strategy:
    1. **Local KB** -- parsed from ``cve-service-mappings`` knowledge template.
       Instant, offline, covers the top ~100 services and their critical CVEs.
    2. **NVD API v2.0** -- queried only when ``SECMCP_NVD_API_KEY`` is set and
       the local KB has no matches.  Results are cached for 7 days in a
       standalone JSON file under ``~/.security_mcp/cache/``.
    """

    def __init__(self) -> None:
        # dict[normalized_service, list[dict]] where each dict has keys:
        #   version, cve_id, cvss_score, exploit, summary
        self._kb_entries: dict[str, list[dict[str, Any]]] = {}
        self._kb_loaded = False
        self._load_kb()

    # ------------------------------------------------------------------
    # KB loading
    # ------------------------------------------------------------------

    def _load_kb(self) -> None:
        """Load the cve-service-mappings template from the knowledge base.

        Parses the markdown tables embedded in each section's content field
        into the internal ``_kb_entries`` lookup dict.
        """
        try:
            from security_mcp.knowledge import KnowledgeLoader

            loader = KnowledgeLoader()
            templates = loader.load_all()
            template = templates.get("cve-service-mappings")

            if template is None:
                logger.debug("KB template 'cve-service-mappings' not found -- KB layer disabled")
                return

            sections = template.get("sections", [])
            for section in sections:
                title = section.get("title", "")
                content = section.get("content", "")
                normalized = self._normalize_service(title)
                if not normalized:
                    continue
                entries = self._parse_markdown_table(content)
                if entries:
                    if normalized not in self._kb_entries:
                        self._kb_entries[normalized] = []
                    self._kb_entries[normalized].extend(entries)

            self._kb_loaded = True
            total = sum(len(v) for v in self._kb_entries.values())
            logger.info("CVE KB loaded: %d services, %d entries", len(self._kb_entries), total)

        except Exception as exc:
            logger.warning("Failed to load CVE KB template: %s", exc)

    @staticmethod
    def _parse_markdown_table(content: str) -> list[dict[str, Any]]:
        """Parse a markdown table into a list of CVE entry dicts.

        Expected columns: Version | CVE | CVSS | Exploit | Description
        The separator row (``|---|---|...``) is skipped automatically.
        """
        entries: list[dict[str, Any]] = []
        lines = content.strip().splitlines()

        for line in lines:
            line = line.strip()
            if not line.startswith("|") or not line.endswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 5:
                continue
            # Skip header and separator rows
            if cells[0].lower() in ("version", "") or re.match(r"^-+$", cells[0]):
                continue

            version_str = cells[0].strip()
            cve_id = cells[1].strip()
            if not cve_id.startswith("CVE-"):
                continue

            try:
                cvss = float(cells[2].strip())
            except (ValueError, IndexError):
                cvss = 0.0

            exploit_raw = cells[3].strip().lower()
            exploit = exploit_raw in ("true", "yes", "1")
            summary = cells[4].strip() if len(cells) > 4 else ""

            entries.append(
                {
                    "version": version_str,
                    "cve_id": cve_id,
                    "cvss_score": cvss,
                    "exploit": exploit,
                    "summary": summary,
                }
            )

        return entries

    # ------------------------------------------------------------------
    # Service / version normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_service(service: str) -> str:
        """Normalize a service name to a canonical lowercase key.

        Handles common aliases: ``OpenSSH`` -> ``openssh``,
        ``Apache httpd`` -> ``apache``, ``Microsoft-IIS`` -> ``iis``, etc.
        """
        if not service:
            return ""
        cleaned = service.strip().lower().replace("-", " ").replace("_", " ")
        # Try exact alias lookup first
        if cleaned in _SERVICE_ALIASES:
            return _SERVICE_ALIASES[cleaned]
        # Try partial match: first word
        first_word = cleaned.split()[0] if cleaned.split() else cleaned
        if first_word in _SERVICE_ALIASES:
            return _SERVICE_ALIASES[first_word]
        # Return cleaned name as-is (allows KB entries for unlisted services)
        return re.sub(r"\s+", "", cleaned)

    @staticmethod
    def _parse_version(version_string: str) -> tuple[str, str]:
        """Extract service name and version number from a banner string.

        Examples:
            ``OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`` -> ``("openssh", "8.2")``
            ``Apache/2.4.49 (Unix)`` -> ``("apache", "2.4.49")``
            ``nginx/1.18.0`` -> ``("nginx", "1.18.0")``
            ``MySQL 5.7.38`` -> ``("mysql", "5.7.38")``

        Returns:
            Tuple of ``(normalized_service, version)``; both empty if no pattern matches.
        """
        if not version_string:
            return ("", "")

        for pattern, service_key in _BANNER_PATTERNS:
            m = pattern.search(version_string)
            if m:
                ver = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                # Strip trailing patch qualifiers like "p1" for comparison
                ver_clean = re.match(r"(\d+\.\d+(?:\.\d+)?)", ver)
                return (service_key, ver_clean.group(1) if ver_clean else ver)

        # Fallback: try generic "product/version" or "product version" pattern
        generic = re.match(r"([A-Za-z][\w.-]*)[/\s]+(\d+\.\d+(?:\.\d+)?)", version_string)
        if generic:
            svc = CVEEnricher._normalize_service(generic.group(1))
            return (svc, generic.group(2))

        return ("", "")

    @staticmethod
    def _version_in_range(version: str, range_spec: str) -> bool:
        """Check if *version* satisfies *range_spec*.

        Supported formats:
            ``2.4.49``          -- exact match
            ``< 2.4.51``        -- strictly less than
            ``<= 2.4.51``       -- less than or equal
            ``>= 5.8, < 5.17``  -- inclusive range
            ``2.4.x``           -- major.minor wildcard (any patch)

        Version components are compared numerically.
        """
        if not version or not range_spec:
            return False

        def _vtuple(v: str) -> tuple[int, ...]:
            """Convert ``"2.4.49"`` to ``(2, 4, 49)``."""
            parts: list[int] = []
            for seg in v.strip().split("."):
                m = re.match(r"(\d+)", seg)
                if m:
                    parts.append(int(m.group(1)))
            return tuple(parts)

        spec = range_spec.strip()
        vtarget = _vtuple(version)

        if not vtarget:
            return False

        # Wildcard: "2.4.x" means any version starting with 2.4
        if spec.endswith(".x"):
            prefix = _vtuple(spec[:-2])
            return vtarget[: len(prefix)] == prefix

        # Range: ">= 5.8, < 5.17"
        if "," in spec:
            parts = [p.strip() for p in spec.split(",")]
            return all(CVEEnricher._version_in_range(version, p) for p in parts)

        # Comparison operators
        for op, cmp_fn in [
            ("<=", lambda a, b: a <= b),
            (">=", lambda a, b: a >= b),
            ("<", lambda a, b: a < b),
            (">", lambda a, b: a > b),
        ]:
            if spec.startswith(op):
                ref = _vtuple(spec[len(op) :])
                return cmp_fn(vtarget, ref) if ref else False

        # Exact match
        return vtarget == _vtuple(spec)

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """Map a CVSS 3.1 score to a severity label."""
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # Main lookup
    # ------------------------------------------------------------------

    async def lookup(self, service: str, version: str) -> list[CVEMatch]:
        """Look up known CVEs for a service/version pair.

        Fast path: checks local KB first.  If no KB matches and the
        ``SECMCP_NVD_API_KEY`` environment variable is set, queries the
        NVD API (with 7-day caching).

        Returns:
            List of ``CVEMatch`` sorted by CVSS score descending (highest first).
        """
        normalized = self._normalize_service(service)
        if not normalized:
            return []

        # Layer 1: local KB
        matches = self._lookup_kb(normalized, version)
        if matches:
            matches.sort(key=lambda m: m.cvss_score, reverse=True)
            return matches

        # Layer 2: NVD API (optional)
        api_key = os.environ.get("SECMCP_NVD_API_KEY", "")
        if not api_key:
            return []

        cache_key = f"cve:{normalized}:{version}"

        # Check file cache
        cached = await self._cache_get(cache_key)
        if cached is not None:
            return cached

        # Query NVD
        nvd_matches = await self._query_nvd(normalized, version)
        await self._cache_set(cache_key, nvd_matches)

        nvd_matches.sort(key=lambda m: m.cvss_score, reverse=True)
        return nvd_matches

    def _lookup_kb(self, service: str, version: str) -> list[CVEMatch]:
        """Check local KB entries for matching CVEs."""
        entries = self._kb_entries.get(service, [])
        if not entries:
            return []

        matches: list[CVEMatch] = []
        for entry in entries:
            range_spec = entry.get("version", "")
            if self._version_in_range(version, range_spec):
                matches.append(
                    CVEMatch(
                        cve_id=entry["cve_id"],
                        cvss_score=entry.get("cvss_score", 0.0),
                        severity=self._cvss_to_severity(entry.get("cvss_score", 0.0)),
                        summary=entry.get("summary", ""),
                        exploit_available=entry.get("exploit", False),
                        source="kb",
                    )
                )
        return matches

    # ------------------------------------------------------------------
    # NVD API
    # ------------------------------------------------------------------

    async def _query_nvd(self, service: str, version: str) -> list[CVEMatch]:
        """Query the NVD REST API v2.0 for CVEs matching a service/version.

        Constructs a CPE 2.3 match string and searches for vulnerabilities.
        Handles rate-limiting (HTTP 429) with exponential backoff.

        Returns:
            Up to ``_NVD_MAX_RESULTS`` matches sorted by CVSS score descending.
            Empty list on any network or parsing error (never raises).
        """
        import asyncio

        import httpx

        vendor_product = _CPE_VENDOR_MAP.get(service)
        if vendor_product:
            vendor, product = vendor_product
        else:
            # Best-effort: use service name as both vendor and product
            vendor, product = service, service

        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        api_key = os.environ.get("SECMCP_NVD_API_KEY", "")

        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key

        params = {"cpeName": cpe}

        for attempt in range(_NVD_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=_NVD_TIMEOUT, verify=True) as client:
                    resp = await client.get(_NVD_API_URL, params=params, headers=headers)

                if resp.status_code == 429:
                    delay = _NVD_BACKOFF_BASE * (2**attempt)
                    logger.warning(
                        "NVD rate-limited (429), retrying in %.1fs (attempt %d/%d)",
                        delay,
                        attempt + 1,
                        _NVD_MAX_RETRIES,
                    )
                    await asyncio.sleep(delay)
                    continue

                if resp.status_code != 200:
                    logger.warning("NVD API returned HTTP %d for CPE %s", resp.status_code, cpe)
                    return []

                return self._parse_nvd_response(resp.json())

            except httpx.TimeoutException:
                logger.warning("NVD API timeout for CPE %s (attempt %d/%d)", cpe, attempt + 1, _NVD_MAX_RETRIES)
            except httpx.HTTPError as exc:
                logger.warning("NVD API request failed: %s", exc)
                return []
            except Exception as exc:
                logger.warning("Unexpected error querying NVD: %s", exc)
                return []

        logger.warning("NVD API: exhausted retries for CPE %s", cpe)
        return []

    def _parse_nvd_response(self, data: dict[str, Any]) -> list[CVEMatch]:
        """Parse NVD API v2.0 JSON response into CVEMatch list.

        Extracts CVE ID, CVSS v3.1 score, English description, and
        known-exploit status from the ``vulnerabilities`` array.
        """
        matches: list[CVEMatch] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln_wrapper in vulnerabilities:
            cve_data = vuln_wrapper.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # CVSS v3.1 score (prefer primary metric)
            cvss_score = 0.0
            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0)
            else:
                # Fallback to v3.0
                cvss_v30 = metrics.get("cvssMetricV30", [])
                if cvss_v30:
                    cvss_score = cvss_v30[0].get("cvssData", {}).get("baseScore", 0.0)

            # English description
            summary = ""
            descriptions = cve_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value", "")[:200]
                    break

            # Known exploit -- NVD v2 uses "cisaExploitAdd" or references tagged "Exploit"
            exploit_available = False
            if cve_data.get("cisaExploitAdd"):
                exploit_available = True
            else:
                for ref in cve_data.get("references", []):
                    tags = ref.get("tags", [])
                    if "Exploit" in tags:
                        exploit_available = True
                        break

            matches.append(
                CVEMatch(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=self._cvss_to_severity(cvss_score),
                    summary=summary,
                    exploit_available=exploit_available,
                    source="nvd",
                )
            )

        # Sort by CVSS descending and cap at max results
        matches.sort(key=lambda m: m.cvss_score, reverse=True)
        return matches[:_NVD_MAX_RESULTS]

    # ------------------------------------------------------------------
    # File-based cache (standalone, no CheckpointStore dependency)
    # ------------------------------------------------------------------

    async def _cache_get(self, key: str) -> list[CVEMatch] | None:
        """Read cached CVE results from the JSON file cache.

        Returns ``None`` on cache miss or expired entry.
        """
        try:
            if not _CACHE_FILE.exists():
                return None

            raw = _CACHE_FILE.read_text(encoding="utf-8")
            cache: dict[str, Any] = json.loads(raw)

            entry = cache.get(key)
            if entry is None:
                return None

            # Check TTL
            stored_at = entry.get("timestamp", 0)
            if (time.time() - stored_at) > _CACHE_TTL_SECONDS:
                logger.debug("Cache expired for key %s", key)
                return None

            # Deserialize matches
            matches: list[CVEMatch] = []
            for item in entry.get("results", []):
                matches.append(
                    CVEMatch(
                        cve_id=item["cve_id"],
                        cvss_score=item["cvss_score"],
                        severity=item["severity"],
                        summary=item["summary"],
                        exploit_available=item["exploit_available"],
                        source=item["source"],
                    )
                )
            logger.debug("Cache hit for %s (%d results)", key, len(matches))
            return matches

        except (json.JSONDecodeError, KeyError, OSError) as exc:
            logger.debug("Cache read failed for %s: %s", key, exc)
            return None

    async def _cache_set(self, key: str, results: list[CVEMatch]) -> None:
        """Write CVE results to the JSON file cache."""
        try:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)

            # Load existing cache (or start fresh)
            cache: dict[str, Any] = {}
            if _CACHE_FILE.exists():
                try:
                    raw = _CACHE_FILE.read_text(encoding="utf-8")
                    cache = json.loads(raw)
                except (json.JSONDecodeError, OSError):
                    cache = {}

            # Evict expired entries opportunistically (keep cache file bounded)
            now = time.time()
            expired_keys = [
                k
                for k, v in cache.items()
                if isinstance(v, dict) and (now - v.get("timestamp", 0)) > _CACHE_TTL_SECONDS
            ]
            for k in expired_keys:
                del cache[k]

            # Store new entry
            cache[key] = {
                "timestamp": now,
                "results": [asdict(m) for m in results],
            }

            _CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
            logger.debug("Cached %d results for %s", len(results), key)

        except OSError as exc:
            logger.warning("Cache write failed for %s: %s", key, exc)

    # ------------------------------------------------------------------
    # Convenience: enrich port scan results
    # ------------------------------------------------------------------

    async def enrich_ports(self, ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Add CVE data to port scan results.

        Accepts the ``services`` dict values from ``PythonConnectScanner.scan_with_banners()``,
        or any list of dicts with ``product``/``version`` or ``banner`` keys.

        Each port dict is augmented in-place with a ``cves`` key containing
        a list of matched CVE dicts.  The original dict is returned (not copied).

        Args:
            ports: List of port-info dicts.  Expected keys:
                - ``product`` and ``version`` (preferred), or
                - ``banner`` (fallback -- will be parsed for service/version).

        Returns:
            The same list with ``cves`` added to each entry.
        """
        for port_info in ports:
            product = port_info.get("product", "")
            version = port_info.get("version", "")

            # If product/version not directly available, parse from banner
            if not product or not version:
                banner = port_info.get("banner", "")
                if banner:
                    product, version = self._parse_version(banner)

            if not product or not version:
                port_info["cves"] = []
                continue

            try:
                matches = await self.lookup(product, version)
                port_info["cves"] = [asdict(m) for m in matches]
            except Exception as exc:
                logger.warning("CVE lookup failed for %s/%s: %s", product, version, exc)
                port_info["cves"] = []

        return ports
