"""ScanEngine ABC — validated by Scantron (Rackspace) pattern."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class ScanType(Enum):
    """Scan protocol types."""

    CONNECT = "connect"  # TCP Connect — no root
    SYN = "syn"  # TCP SYN — root required
    UDP = "udp"  # UDP scan
    PASSIVE = "passive"  # API-based, zero traffic


@dataclass
class PortInfo:
    """Information about a discovered port."""

    port: int
    protocol: str = "tcp"  # "tcp" | "udp"
    state: str = "open"  # "open" | "filtered" | "closed"
    service: str = ""  # "http", "ssh", etc.
    version: str = ""  # "Apache/2.4.41", "OpenSSH 8.2p1"
    banner: str = ""


@dataclass
class ScanResult:
    """Result of a port scan."""

    host: str
    ports: list[PortInfo] = field(default_factory=list)
    os_guess: str | None = None
    scan_time: float = 0.0
    scanner_used: str = ""
    raw_output: str = ""


class ScanEngine(ABC):
    """
    Abstract scan engine interface.
    Validated by Scantron (Rackspace) pattern.
    """

    @abstractmethod
    async def discover_ports(
        self,
        target: str,
        ports: str = "top-1000",
        scan_type: ScanType = ScanType.CONNECT,
        rate_limit: int = 200,
        timeout: float = 2.0,
    ) -> ScanResult:
        """Discover open ports on target."""
        ...

    @abstractmethod
    async def detect_services(self, host: str, ports: list[int]) -> list[PortInfo]:
        """Detect services on discovered ports."""
        ...

    @property
    @abstractmethod
    def capabilities(self) -> set[ScanType]:
        """Supported scan types."""
        ...

    @property
    @abstractmethod
    def requires_external_binary(self) -> bool:
        """Whether this engine needs an external binary."""
        ...


class ScanEngineFactory:
    """
    Auto-selects the best available scanner backend.
    Pattern validated by Scantron (scan_binary field) and JFScan.
    """

    @staticmethod
    def create(preference: str = "auto") -> ScanEngine:
        if preference == "naabu":
            from security_mcp.scanners.naabu import NaabuScanner

            return NaabuScanner()
        if preference == "nmap":
            from security_mcp.scanners.nmap import NmapScanner

            return NmapScanner()
        if preference == "python":
            from security_mcp.scanners.python_connect import PythonConnectScanner

            return PythonConnectScanner()
        if preference == "shodan":
            from security_mcp.scanners.shodan import ShodanPassiveScanner

            return ShodanPassiveScanner()

        # Auto: best available
        if shutil.which("naabu"):
            from security_mcp.scanners.naabu import NaabuScanner

            return NaabuScanner()
        if shutil.which("nmap"):
            from security_mcp.scanners.nmap import NmapScanner

            return NmapScanner()
        from security_mcp.scanners.python_connect import PythonConnectScanner

        return PythonConnectScanner()
