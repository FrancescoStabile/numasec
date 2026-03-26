"""NaabuScanner — Primary scanner backend (ProjectDiscovery, MIT, 5.6K stars)."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
import xml.etree.ElementTree as ET
from asyncio.subprocess import PIPE

from security_mcp.scanners._base import PortInfo, ScanEngine, ScanResult, ScanType

logger = logging.getLogger("security_mcp.scanners.naabu")

# Well-known port → service mapping for banner-grab fallback
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
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
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


def _parse_nmap_service_xml(xml_str: str) -> list[PortInfo]:
    """Parse nmap XML output into PortInfo list for service detection."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return []

    results: list[PortInfo] = []
    for port_elem in root.findall(".//port"):
        state = port_elem.find("state")
        if state is not None and state.get("state") != "open":
            continue
        svc = port_elem.find("service")
        service = svc.get("name", "") if svc is not None else ""
        product = svc.get("product", "") if svc is not None else ""
        version = svc.get("version", "") if svc is not None else ""
        version_str = f"{product} {version}".strip()
        results.append(
            PortInfo(
                port=int(port_elem.get("portid", 0)),
                protocol=port_elem.get("protocol", "tcp"),
                state="open",
                service=service,
                version=version_str,
            )
        )
    return results


class NaabuScanner(ScanEngine):
    """Primary scanner. Naabu 2.3+, ProjectDiscovery.

    JSON output, configurable rate, dedup IP, CDN/WAF detection.
    For service detection: delegates to nmap via subprocess if available,
    otherwise falls back to banner grabbing.
    """

    @property
    def capabilities(self) -> set[ScanType]:
        return {ScanType.CONNECT, ScanType.SYN, ScanType.UDP}

    @property
    def requires_external_binary(self) -> bool:
        return True

    async def discover_ports(
        self,
        target: str,
        ports: str = "top-1000",
        scan_type: ScanType = ScanType.CONNECT,
        rate_limit: int = 200,
        timeout: float = 2.0,
    ) -> ScanResult:
        """Run naabu port scan via subprocess."""
        if not shutil.which("naabu"):
            raise FileNotFoundError(
                "naabu binary not found in PATH. Install from https://github.com/projectdiscovery/naabu"
            )

        cmd = [
            "naabu",
            "-host",
            target,
            "-rate",
            str(rate_limit),
            "-timeout",
            str(int(timeout * 1000)),
            "-json",
            "-silent",
        ]

        # Port specification
        if ports.startswith("top-"):
            n = ports.split("-", 1)[1]
            cmd.extend(["-top-ports", n])
        elif ports != "all":
            cmd.extend(["-p", ports])

        # SYN scan flag
        if scan_type == ScanType.SYN:
            cmd.append("-s")

        logger.info("Running: %s", " ".join(cmd))
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=300,
            )
        except TimeoutError:
            logger.error("Naabu timed out scanning %s", target)
            return ScanResult(host=target, scanner_used="naabu")
        except OSError as exc:
            raise FileNotFoundError(f"Failed to execute naabu: {exc}") from exc

        elapsed = time.monotonic() - start
        stdout = stdout_bytes.decode("utf-8", errors="ignore")
        stderr = stderr_bytes.decode("utf-8", errors="ignore")

        if proc.returncode != 0:
            logger.warning("Naabu exited %d: %s", proc.returncode, stderr[:500])

        result = self._parse_json_output(stdout, target)
        result.scan_time = elapsed
        result.raw_output = stdout
        return result

    async def detect_services(self, host: str, ports: list[int]) -> list[PortInfo]:
        """Use nmap for service detection if available, otherwise banner grab."""
        if not ports:
            return []

        if shutil.which("nmap"):
            return await self._nmap_service_detect(host, ports)
        return await self._banner_grab(host, ports)

    # -- internal helpers ----------------------------------------------------

    def _parse_json_output(self, stdout: str, target: str = "") -> ScanResult:
        """Parse naabu JSON-lines output into ScanResult."""
        found_ports: list[PortInfo] = []
        host = target

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON line: %s", line[:100])
                continue

            host = data.get("host", host) or data.get("ip", host)
            port_num = data.get("port")
            if port_num is None:
                continue

            found_ports.append(
                PortInfo(
                    port=int(port_num),
                    protocol=data.get("protocol", "tcp"),
                    state="open",
                    service=_COMMON_PORTS.get(int(port_num), ""),
                )
            )

        logger.info("Naabu found %d open ports on %s", len(found_ports), host)
        return ScanResult(host=host, ports=found_ports, scanner_used="naabu")

    async def _nmap_service_detect(self, host: str, ports: list[int]) -> list[PortInfo]:
        """Run nmap -sV on specific ports for service detection."""
        port_str = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-sV", "-p", port_str, host, "-oX", "-"]
        logger.info("Service detection: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=120,
            )
        except (TimeoutError, OSError) as exc:
            logger.warning("Nmap service detection failed: %s", exc)
            return await self._banner_grab(host, ports)

        xml_str = stdout_bytes.decode("utf-8", errors="ignore")
        results = _parse_nmap_service_xml(xml_str)
        if not results:
            return await self._banner_grab(host, ports)
        return results

    async def _banner_grab(self, host: str, ports: list[int]) -> list[PortInfo]:
        """Fallback banner grab when nmap is not available."""
        results: list[PortInfo] = []
        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3.0,
                )
                banner_bytes = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=3.0,
                )
                writer.close()
                await writer.wait_closed()
                banner = banner_bytes.decode("utf-8", errors="ignore")
                service = _guess_service(port, banner)
                results.append(
                    PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=service,
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
