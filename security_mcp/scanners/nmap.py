"""NmapScanner — Optional advanced scanner via nmap subprocess."""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
import xml.etree.ElementTree as ET
from asyncio.subprocess import PIPE

from security_mcp.scanners._base import PortInfo, ScanEngine, ScanResult, ScanType

logger = logging.getLogger("security_mcp.scanners.nmap")


class NmapScanner(ScanEngine):
    """Advanced scanner using nmap binary via subprocess.

    Supports SYN, UDP, OS fingerprint, full service detection.
    Requires nmap binary and optionally root for SYN scan.
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
        """Run nmap scan via subprocess with XML output."""
        if not shutil.which("nmap"):
            raise FileNotFoundError("nmap binary not found in PATH. Install from https://nmap.org/")

        cmd = ["nmap"]

        # Scan type
        if scan_type == ScanType.SYN:
            cmd.append("-sS")
        elif scan_type == ScanType.UDP:
            cmd.append("-sU")
        else:
            cmd.append("-sT")

        # Port specification
        if ports.startswith("top-"):
            n = ports.split("-", 1)[1]
            cmd.extend(["--top-ports", n])
        elif ports == "all":
            cmd.append("-p-")
        else:
            cmd.extend(["-p", ports])

        # Rate limiting
        cmd.extend(["--min-rate", str(rate_limit)])
        cmd.extend(["--max-rate", str(rate_limit * 2)])

        # XML output to stdout
        cmd.extend(["-oX", "-", target])

        # Adaptive timeout
        effective_timeout = 600 if ports in ("all", "-") else 120

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
                timeout=effective_timeout,
            )
        except TimeoutError:
            logger.error("Nmap timed out scanning %s", target)
            return ScanResult(host=target, scanner_used="nmap")
        except OSError as exc:
            raise FileNotFoundError(f"Failed to execute nmap: {exc}") from exc

        elapsed = time.monotonic() - start
        stdout = stdout_bytes.decode("utf-8", errors="ignore")
        stderr = stderr_bytes.decode("utf-8", errors="ignore")

        if proc.returncode != 0:
            logger.warning("Nmap exited %d: %s", proc.returncode, stderr[:500])

        result = self._parse_xml_output(stdout, target)
        result.scan_time = elapsed
        result.raw_output = stdout
        return result

    async def detect_services(self, host: str, ports: list[int]) -> list[PortInfo]:
        """Full nmap service detection (-sV) on specific ports."""
        if not ports:
            return []
        if not shutil.which("nmap"):
            return [PortInfo(port=p) for p in ports]

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
            return [PortInfo(port=p) for p in ports]

        stdout = stdout_bytes.decode("utf-8", errors="ignore")
        result = self._parse_xml_output(stdout, host)
        return result.ports if result.ports else [PortInfo(port=p) for p in ports]

    # -- XML parsing ---------------------------------------------------------

    def _parse_xml_output(self, xml_str: str, target: str) -> ScanResult:
        """Parse nmap XML output into ScanResult."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            logger.warning("Failed to parse nmap XML output")
            return ScanResult(host=target, scanner_used="nmap")

        found_ports: list[PortInfo] = []
        os_guess: str | None = None

        for host_elem in root.findall(".//host"):
            # Skip hosts that are not up
            status = host_elem.find("status")
            if status is not None and status.get("state") != "up":
                continue

            # OS detection
            os_match = host_elem.find(".//osmatch")
            if os_match is not None:
                os_guess = os_match.get("name", "")

            # Ports
            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                svc = port_elem.find("service")
                service_name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                version_str = f"{product} {version}".strip()

                found_ports.append(
                    PortInfo(
                        port=int(port_elem.get("portid", 0)),
                        protocol=port_elem.get("protocol", "tcp"),
                        state="open",
                        service=service_name,
                        version=version_str,
                    )
                )

        logger.info("Nmap found %d open ports on %s", len(found_ports), target)
        return ScanResult(
            host=target,
            ports=found_ports,
            os_guess=os_guess,
            scanner_used="nmap",
        )
