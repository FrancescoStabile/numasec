"""ShodanPassiveScanner — Zero-traffic passive scanning via Shodan API."""

from __future__ import annotations

import logging

import httpx

from security_mcp.scanners._base import PortInfo, ScanEngine, ScanResult, ScanType

logger = logging.getLogger(__name__)

SHODAN_API_BASE = "https://api.shodan.io"


class ShodanError(Exception):
    """Raised when Shodan API returns an error."""


class ShodanPassiveScanner(ScanEngine):
    """
    Zero traffic. Queries Shodan API for exposed hosts.
    Essential for production targets where active scanning is prohibited.
    """

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key

    @property
    def capabilities(self) -> set[ScanType]:
        return {ScanType.PASSIVE}

    @property
    def requires_external_binary(self) -> bool:
        return False

    async def discover_ports(
        self,
        target: str,
        ports: str = "top-1000",
        scan_type: ScanType = ScanType.PASSIVE,
        rate_limit: int = 200,
        timeout: float = 10.0,
    ) -> ScanResult:
        """Query Shodan /shodan/host/{ip} for host information.

        Parameters
        ----------
        target:
            IP address or hostname to query.
        ports:
            Ignored for Shodan (returns all known ports).
        scan_type:
            Must be PASSIVE — Shodan doesn't generate traffic.
        rate_limit:
            Ignored (Shodan has its own rate limits).
        timeout:
            HTTP timeout in seconds.
        """
        if not self._api_key:
            raise ShodanError("Shodan API key required — set SHODAN_API_KEY")

        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{SHODAN_API_BASE}/shodan/host/{target}",
                params={"key": self._api_key, "minify": "false"},
            )

        if resp.status_code == 404:
            logger.info("Shodan: no data for %s", target)
            return ScanResult(host=target, ports=[], scanner_used="shodan")

        if resp.status_code != 200:
            raise ShodanError(f"Shodan API error {resp.status_code}: {resp.text[:200]}")

        data = resp.json()

        port_infos = [
            PortInfo(
                port=svc["port"],
                protocol=svc.get("transport", "tcp"),
                state="open",
                service=svc.get("product", ""),
                version=svc.get("version", ""),
                banner=svc.get("data", "")[:500],
            )
            for svc in data.get("data", [])
        ]

        return ScanResult(
            host=target,
            ports=port_infos,
            os_guess=data.get("os"),
            scanner_used="shodan",
            raw_output=resp.text[:5000],
        )

    async def detect_services(self, host: str, ports: list[int]) -> list[PortInfo]:
        """Service info is already available from discover_ports.

        For Shodan, discover_ports returns full service details.
        This method re-queries for specific ports if needed.
        """
        result = await self.discover_ports(host)
        if not ports:
            return result.ports
        return [p for p in result.ports if p.port in ports]
