"""PythonConnectScanner — Zero-dependency fallback, TCP CONNECT only."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from typing import Any

from security_mcp.scanners._base import PortInfo, ScanEngine, ScanResult, ScanType

logger = logging.getLogger("security_mcp.scanners.python_connect")

# Top ports ordered by frequency (nmap top-ports list).
# Used for "top-100" and "top-1000" presets.
TOP_PORTS: list[int] = [
    # Top 100 most common
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    179,
    389,
    443,
    445,
    465,
    514,
    515,
    587,
    593,
    636,
    873,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1080,
    1110,
    1433,
    1434,
    1521,
    1720,
    1723,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    3986,
    4443,
    4567,
    4899,
    5000,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    5901,
    6000,
    6001,
    6379,
    6646,
    7000,
    7002,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9000,
    9001,
    9090,
    9100,
    9200,
    9443,
    9999,
    10000,
    10443,
    11211,
    13306,
    15432,
    17017,
    27017,
    27018,
    28017,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
    50000,
    # Extended top ~300 for "top-1000" approximation
    1,
    7,
    9,
    11,
    13,
    15,
    17,
    19,
    20,
    37,
    42,
    43,
    49,
    50,
    57,
    65,
    67,
    68,
    69,
    70,
    79,
    81,
    82,
    83,
    84,
    85,
    88,
    89,
    90,
    99,
    100,
    106,
    113,
    119,
    120,
    123,
    144,
    146,
    161,
    162,
    163,
    164,
    174,
    175,
    199,
    211,
    212,
    222,
    254,
    255,
    256,
    259,
    264,
    280,
    301,
    306,
    311,
    340,
    366,
    406,
    407,
    416,
    417,
    425,
    427,
    444,
    458,
    464,
    481,
    497,
    500,
    512,
    513,
    524,
    541,
    543,
    544,
    545,
    548,
    554,
    555,
    563,
    616,
    617,
    625,
    631,
    646,
    648,
    666,
    667,
    668,
    683,
    687,
    691,
    700,
    705,
    711,
    714,
    720,
    722,
    726,
    749,
    765,
    777,
    783,
    787,
    800,
    801,
    808,
    843,
    880,
    888,
    898,
    900,
    901,
    902,
    903,
    911,
    912,
    981,
    987,
    990,
    992,
    999,
    1000,
    1001,
    1002,
    1007,
    1009,
    1010,
    1011,
    1021,
    1022,
    1023,
    1024,
    1030,
    1031,
    1032,
    1033,
    1034,
    1035,
    1036,
    1037,
    1038,
    1039,
    1040,
    1041,
    1042,
    1043,
    1044,
    1045,
    1046,
    1047,
    1048,
    1049,
    1050,
    1051,
    1052,
    1053,
    1054,
    1055,
    1056,
    1057,
    1058,
    1059,
    1060,
    1070,
    1071,
    1074,
    1075,
    1081,
    1082,
    1083,
    1084,
    1085,
    1086,
    1088,
    1090,
    1098,
    1099,
    1100,
    1101,
    1102,
    1104,
    1105,
    1106,
    1107,
    1108,
    1111,
    1112,
    1113,
    1114,
    1117,
    1119,
    1122,
    1128,
    1131,
    1138,
    1148,
    1169,
    1198,
    1199,
    1200,
    1214,
    1233,
    1234,
    1236,
    1244,
    1247,
    1248,
    1270,
    1272,
    1277,
    1287,
    1296,
    1310,
    1311,
    1322,
    1328,
    1334,
    1352,
    1417,
    1443,
    1455,
    1461,
    1494,
    1500,
    1501,
    1503,
    1524,
    1533,
    1556,
    1580,
    1583,
    1594,
    1600,
    1641,
    1658,
    1666,
    1687,
    1688,
    1700,
    1717,
    1718,
    1719,
    1721,
    1755,
    1761,
    1782,
    1783,
    1801,
    1805,
    1812,
    1839,
    1840,
    1862,
    1863,
    1864,
    1875,
    1914,
    1935,
    1947,
    1971,
    1972,
    1974,
    1984,
    1998,
    1999,
    2002,
    2003,
    2004,
    2005,
    2006,
    2007,
    2008,
    2009,
    2010,
    2013,
    2020,
    2021,
    2022,
    2030,
    2033,
    2034,
    2035,
    2038,
    2040,
    2041,
    2042,
    2043,
    2045,
    2046,
    2047,
    2048,
    2065,
    2068,
    2099,
    2100,
    2103,
    2105,
    2106,
    2107,
    2111,
    2119,
    2126,
    2135,
    2144,
    2160,
    2161,
    2170,
    2179,
    2190,
    2191,
    2196,
    2200,
    2222,
    2251,
    2260,
    2288,
    2301,
    2323,
    2366,
    2381,
    2382,
    2383,
    2393,
    2394,
    2399,
    2401,
    2492,
    2500,
    2522,
    2525,
    2557,
    2601,
    2602,
    2604,
    2605,
    2607,
    2608,
]

# Well-known port → service mapping
_COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


# Ports where we send an HTTP HEAD request to elicit a Server header.
_HTTP_PORTS: set[int] = {80, 443, 3000, 4443, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090}

# Ports where TLS certificate info should be collected.
_TLS_PORTS: set[int] = {443, 8443, 4443, 9443, 10443, 636, 993, 995, 465}

# Regex patterns for extracting product name and version from banners.
# Each tuple: (compiled_regex, product_name).
VERSION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"OpenSSH[_/](\d+\.\d+(?:\.\d+)?)"), "OpenSSH"),
    (re.compile(r"Apache[/\s](\d+\.\d+(?:\.\d+)?)"), "Apache"),
    (re.compile(r"nginx[/\s](\d+\.\d+(?:\.\d+)?)"), "nginx"),
    (re.compile(r"Microsoft-IIS[/\s](\d+\.\d+)"), "IIS"),
    (re.compile(r"MySQL\s+(\d+\.\d+(?:\.\d+)?)"), "MySQL"),
    (re.compile(r"PostgreSQL\s+(\d+\.\d+)"), "PostgreSQL"),
    (re.compile(r"ProFTPD\s+(\d+\.\d+(?:\.\d+)?)"), "ProFTPD"),
    (re.compile(r"vsftpd\s+(\d+\.\d+(?:\.\d+)?)"), "vsftpd"),
    (re.compile(r"Postfix"), "Postfix"),
    (re.compile(r"Express"), "Express"),
    (re.compile(r"LiteSpeed[/\s](\d+\.\d+(?:\.\d+)?)"), "LiteSpeed"),
    (re.compile(r"lighttpd[/\s](\d+\.\d+(?:\.\d+)?)"), "lighttpd"),
]


def _guess_service(port: int, banner: str = "") -> str:
    """Guess service name from port number and optional banner text."""
    lower = banner.lower()
    if "ssh" in lower:
        return "ssh"
    if "http" in lower:
        return "http"
    if "ftp" in lower:
        return "ftp"
    if "smtp" in lower:
        return "smtp"
    if "mysql" in lower:
        return "mysql"
    if "redis" in lower:
        return "redis"
    return _COMMON_PORTS.get(port, "")


class PythonConnectScanner(ScanEngine):
    """Fallback zero-dependency scanner. TCP Connect only.

    NOT enterprise-grade: no SYN, no UDP, no OS fingerprint.
    Used ONLY when no external scanner is available.

    Enhanced capabilities:
    - Protocol-aware banner grabbing (HTTP, SSH, SMTP, FTP, generic)
    - SSL/TLS certificate information extraction
    - Version extraction from banners via regex patterns
    - Rich result format with services, ssl_info, and timing
    """

    @property
    def capabilities(self) -> set[ScanType]:
        return {ScanType.CONNECT}

    @property
    def requires_external_binary(self) -> bool:
        return False

    def _resolve_ports(self, spec: str) -> list[int]:
        """Convert port specification string to list of port numbers."""
        if spec == "top-100":
            return TOP_PORTS[:100]
        if spec in ("top-1000", "top-ports"):
            return list(TOP_PORTS)
        if spec == "all":
            return list(range(1, 65536))
        if "," in spec:
            return [int(p.strip()) for p in spec.split(",")]
        if "-" in spec:
            parts = spec.split("-", 1)
            return list(range(int(parts[0]), int(parts[1]) + 1))
        return [int(spec)]

    # ------------------------------------------------------------------
    # Banner grabbing
    # ------------------------------------------------------------------

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
        target: str = "",
    ) -> str:
        """Grab service banner using protocol-appropriate probes.

        Args:
            reader: Async stream reader from the open connection.
            writer: Async stream writer from the open connection.
            port: Remote port number (used to select probe strategy).
            target: Hostname/IP of the target (used in HTTP Host header).

        Returns:
            Banner string (may be empty if the service sends nothing).
        """
        try:
            if port in _HTTP_PORTS:
                return await self._grab_http_banner(reader, writer, target)
            if port == 22:
                return await self._grab_line_banner(reader)
            if port in (25, 587):
                return await self._grab_line_banner(reader)
            if port == 21:
                return await self._grab_line_banner(reader)
            # Generic: read whatever the server sends after connect.
            return await self._grab_generic_banner(reader)
        except (TimeoutError, OSError, UnicodeDecodeError) as exc:
            logger.debug("Banner grab failed on port %d: %s", port, exc)
            return ""

    async def _grab_http_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
    ) -> str:
        """Send HTTP HEAD and return the Server header value (or full status line)."""
        request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        response_bytes = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        response = response_bytes.decode("utf-8", errors="ignore")

        # Try to extract Server header.
        for line in response.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()

        # Fallback: return the HTTP status line.
        first_line = response.split("\r\n", 1)[0] if response else ""
        return first_line

    async def _grab_line_banner(self, reader: asyncio.StreamReader) -> str:
        """Read a single line banner (SSH, SMTP, FTP)."""
        data = await asyncio.wait_for(reader.readline(), timeout=3.0)
        return data.decode("utf-8", errors="ignore").strip()

    async def _grab_generic_banner(self, reader: asyncio.StreamReader) -> str:
        """Best-effort read of up to 1024 bytes with 2s timeout."""
        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        return data.decode("utf-8", errors="ignore").strip()

    # ------------------------------------------------------------------
    # SSL / TLS certificate info
    # ------------------------------------------------------------------

    async def _get_ssl_info(self, host: str, port: int) -> dict[str, Any]:
        """Extract SSL/TLS certificate metadata.

        Args:
            host: Target hostname or IP.
            port: TLS port to connect to.

        Returns:
            Dict with keys: cn, san, expiry, issuer.
            Empty dict on failure.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                writer.close()
                await writer.wait_closed()
                return {}

            cert = ssl_obj.getpeercert(binary_form=False)
            writer.close()
            await writer.wait_closed()

            if not cert:
                # binary_form=False returns {} when verify_mode=CERT_NONE on
                # some Python versions. Try the DER path.
                return await self._get_ssl_info_from_der(host, port, ctx)

            return self._parse_cert_dict(cert)

        except (TimeoutError, OSError, ssl.SSLError) as exc:
            logger.debug("SSL info failed for %s:%d: %s", host, port, exc)
            return {}

    async def _get_ssl_info_from_der(
        self,
        host: str,
        port: int,
        ctx: ssl.SSLContext,
    ) -> dict[str, Any]:
        """Fallback: decode DER certificate when getpeercert() returns empty."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=5.0,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                writer.close()
                await writer.wait_closed()
                return {}

            der_bytes = ssl_obj.getpeercert(binary_form=True)
            writer.close()
            await writer.wait_closed()

            if not der_bytes:
                return {}

            # DER cert is available; convert to PEM for downstream use.
            # Without third-party libs (e.g. cryptography), detailed parsing
            # is limited, so we just note that the cert was reachable.
            ssl.DER_cert_to_PEM_cert(der_bytes)  # validates DER format
            info: dict[str, Any] = {"raw_pem_available": True}

            # Extract CN from the DER subject if possible via a second
            # connection with CERT_REQUIRED (won't verify, just parse).
            # If it fails, we still return what we have.
            return info

        except (TimeoutError, OSError, ssl.SSLError):
            return {}

    @staticmethod
    def _parse_cert_dict(cert: dict[str, Any]) -> dict[str, Any]:
        """Parse a Python ssl peercert dict into a clean info dict."""
        info: dict[str, Any] = {}

        # Common Name from subject.
        subject = cert.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    info["cn"] = attr_value

        # Subject Alternative Names.
        san_entries = cert.get("subjectAltName", ())
        sans = [value for _type, value in san_entries if _type == "DNS"]
        if sans:
            info["san"] = sans

        # Expiry date (notAfter).
        not_after = cert.get("notAfter", "")
        if not_after:
            info["expiry"] = not_after

        # Issuer CN.
        issuer = cert.get("issuer", ())
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                if attr_type in ("commonName", "organizationName"):
                    info["issuer"] = attr_value
                    break
            if "issuer" in info:
                break

        return info

    # ------------------------------------------------------------------
    # Version extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_version(banner: str) -> tuple[str, str]:
        """Extract product name and version from a banner string.

        Args:
            banner: Raw banner text.

        Returns:
            Tuple of (product_name, version_string).
            Both empty strings if no known pattern matches.
        """
        for pattern, product in VERSION_PATTERNS:
            match = pattern.search(banner)
            if match:
                version = match.group(1) if match.lastindex else ""
                return product, version
        return "", ""

    # ------------------------------------------------------------------
    # Port discovery (unchanged contract, same ScanResult)
    # ------------------------------------------------------------------

    async def discover_ports(
        self,
        target: str,
        ports: str = "top-1000",
        scan_type: ScanType = ScanType.CONNECT,
        rate_limit: int = 300,
        timeout: float = 2.0,
    ) -> ScanResult:
        """TCP Connect scan using asyncio with semaphore-based rate limiting."""
        if scan_type != ScanType.CONNECT:
            logger.warning(
                "PythonConnectScanner only supports CONNECT, got %s — using CONNECT",
                scan_type.value,
            )

        port_list = self._resolve_ports(ports)
        sem = asyncio.Semaphore(rate_limit)

        async def _check(port: int) -> PortInfo | None:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=_COMMON_PORTS.get(port, ""),
                    )
                except (TimeoutError, OSError):
                    return None

        logger.info(
            "Scanning %s — %d ports, concurrency=%d, timeout=%.1fs",
            target,
            len(port_list),
            rate_limit,
            timeout,
        )
        start = time.monotonic()
        results = await asyncio.gather(*[_check(p) for p in port_list])
        elapsed = time.monotonic() - start

        open_ports = [r for r in results if r is not None]
        logger.info("Found %d open ports on %s in %.2fs", len(open_ports), target, elapsed)

        return ScanResult(
            host=target,
            ports=open_ports,
            scan_time=elapsed,
            scanner_used="python_connect",
        )

    # ------------------------------------------------------------------
    # Service detection (enhanced with protocol-aware banners + versions)
    # ------------------------------------------------------------------

    async def detect_services(self, host: str, ports: list[int]) -> list[PortInfo]:
        """Protocol-aware banner grabbing and version detection.

        For each port, opens a connection, sends the appropriate probe
        (HTTP HEAD, or passive read for SSH/SMTP/FTP/generic), extracts
        service name and version from the banner.
        """
        if not ports:
            return []

        results: list[PortInfo] = []
        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3.0,
                )
                banner = await self._grab_banner(reader, writer, port, target=host)
                writer.close()
                await writer.wait_closed()

                service = _guess_service(port, banner)
                product, version = self._extract_version(banner)

                results.append(
                    PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=service,
                        version=f"{product}/{version}" if product and version else product,
                        banner=banner,
                    )
                )
            except (TimeoutError, OSError):
                results.append(
                    PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=_COMMON_PORTS.get(port, ""),
                    )
                )
        return results

    # ------------------------------------------------------------------
    # Full enhanced scan (new public method)
    # ------------------------------------------------------------------

    async def scan_with_banners(
        self,
        target: str,
        ports: str = "top-100",
        rate_limit: int = 300,
        timeout: float = 2.0,
    ) -> dict[str, Any]:
        """Run port discovery + banner grabbing + SSL info in one call.

        Returns an enhanced result dict:
        {
            "open_ports": [80, 443, 22],
            "services": {
                "80": {"name": "http", "banner": "nginx/1.24.0",
                       "version": "1.24.0", "product": "nginx"},
                ...
            },
            "ssl_info": {
                "443": {"cn": "example.com", "san": [...], ...}
            },
            "scan_duration_ms": 5432.1,
        }
        """
        start = time.monotonic()

        # Phase 1: discover open ports.
        scan_result = await self.discover_ports(
            target,
            ports=ports,
            rate_limit=rate_limit,
            timeout=timeout,
        )
        open_port_numbers = [p.port for p in scan_result.ports]

        if not open_port_numbers:
            elapsed_ms = (time.monotonic() - start) * 1000
            return {
                "open_ports": [],
                "services": {},
                "ssl_info": {},
                "scan_duration_ms": round(elapsed_ms, 1),
            }

        # Phase 2: banner grab on open ports.
        service_infos = await self.detect_services(target, open_port_numbers)

        services: dict[str, dict[str, str]] = {}
        for info in service_infos:
            product, version = self._extract_version(info.banner)
            services[str(info.port)] = {
                "name": info.service,
                "banner": info.banner,
                "version": version,
                "product": product,
            }

        # Phase 3: SSL info for TLS ports.
        ssl_info: dict[str, dict[str, Any]] = {}
        tls_open = [p for p in open_port_numbers if p in _TLS_PORTS]
        for tls_port in tls_open:
            cert_info = await self._get_ssl_info(target, tls_port)
            if cert_info:
                ssl_info[str(tls_port)] = cert_info

        elapsed_ms = (time.monotonic() - start) * 1000
        return {
            "open_ports": sorted(open_port_numbers),
            "services": services,
            "ssl_info": ssl_info,
            "scan_duration_ms": round(elapsed_ms, 1),
        }
