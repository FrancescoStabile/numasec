"""Tests for composite_recon.py — service probing and CVE enrichment integration."""

from __future__ import annotations

from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_mcp.scanners._base import PortInfo
from security_mcp.scanners.service_prober import ServiceProbeResult


# ---------------------------------------------------------------------------
# Helper: mock port scan data
# ---------------------------------------------------------------------------


def _mock_port_scan_data() -> dict:
    """Realistic port scan dict matching PythonConnectScanner.scan_with_banners output."""
    return {
        "open_ports": {
            "22": {"service": "ssh", "version": "OpenSSH_8.2p1", "banner": "SSH-2.0-OpenSSH_8.2p1"},
            "80": {"service": "http", "version": "Apache/2.4.49", "banner": ""},
            "6379": {"service": "redis", "version": "", "banner": ""},
        },
        "host": "10.0.0.1",
    }


# ---------------------------------------------------------------------------
# Service probing dispatch
# ---------------------------------------------------------------------------


class TestReconServicesCheckDispatchesToProber:
    @pytest.mark.asyncio
    async def test_services_check_invokes_prober(self):
        """checks='services' creates a ServiceProber and calls probe_all."""
        from security_mcp.tools.composite_recon import recon

        probe_results = [
            ServiceProbeResult(port=22, protocol="tcp", service="ssh", version="OpenSSH_8.2p1"),
            ServiceProbeResult(port=6379, protocol="tcp", service="redis", version="7.0.11"),
        ]

        mock_scanner = AsyncMock()
        mock_scanner.scan_with_banners = AsyncMock(return_value=_mock_port_scan_data())

        mock_prober = AsyncMock()
        mock_prober.probe_all = AsyncMock(return_value=probe_results)

        mock_enricher = MagicMock()
        mock_enricher.lookup = AsyncMock(return_value=[])

        with patch("security_mcp.scanners.python_connect.PythonConnectScanner", return_value=mock_scanner):
            with patch("security_mcp.scanners.service_prober.ServiceProber", return_value=mock_prober):
                with patch("security_mcp.scanners.cve_enricher.CVEEnricher", return_value=mock_enricher):
                    result = await recon("10.0.0.1", checks="services", timeout=2.0)

        assert "services" in result
        mock_prober.probe_all.assert_called_once()
        assert isinstance(result["services"], dict)


# ---------------------------------------------------------------------------
# CVE enrichment runs automatically
# ---------------------------------------------------------------------------


class TestReconCveEnrichmentRunsAutomatically:
    @pytest.mark.asyncio
    async def test_cve_enrichment_after_port_scan(self):
        """CVE enrichment runs automatically after port scanning discovers services."""
        from security_mcp.tools.composite_recon import recon

        mock_scanner = AsyncMock()
        mock_scanner.scan_with_banners = AsyncMock(return_value=_mock_port_scan_data())

        mock_enricher = MagicMock()
        # The recon function calls enricher.enrich_ports(port_list)
        mock_enricher.enrich_ports = AsyncMock(return_value=[])

        with patch("security_mcp.scanners.python_connect.PythonConnectScanner", return_value=mock_scanner):
            with patch("security_mcp.scanners.cve_enricher.CVEEnricher", return_value=mock_enricher):
                result = await recon("10.0.0.1", checks="ports", timeout=2.0)

        # enrich_ports should have been called with the port list
        mock_enricher.enrich_ports.assert_called_once()


# ---------------------------------------------------------------------------
# Services check without ports triggers port scan
# ---------------------------------------------------------------------------


class TestReconServicesWithoutPortsTriggersScan:
    @pytest.mark.asyncio
    async def test_services_check_triggers_port_scan(self):
        """Requesting 'services' check also triggers port scanning as a prerequisite."""
        from security_mcp.tools.composite_recon import recon

        mock_scanner = AsyncMock()
        mock_scanner.scan_with_banners = AsyncMock(return_value=_mock_port_scan_data())

        mock_prober = AsyncMock()
        mock_prober.probe_all = AsyncMock(return_value=[])

        mock_enricher = MagicMock()
        mock_enricher.lookup = AsyncMock(return_value=[])

        with patch("security_mcp.scanners.python_connect.PythonConnectScanner", return_value=mock_scanner):
            with patch("security_mcp.scanners.service_prober.ServiceProber", return_value=mock_prober):
                with patch("security_mcp.scanners.cve_enricher.CVEEnricher", return_value=mock_enricher):
                    # Only request 'services', not 'ports' explicitly
                    result = await recon("10.0.0.1", checks="services", timeout=2.0)

        # Port scanner should still be called as a prerequisite
        mock_scanner.scan_with_banners.assert_called_once()
        assert "ports" in result


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestReconBackwardCompatible:
    @pytest.mark.asyncio
    async def test_existing_checks_still_work(self):
        """Legacy checks (ports, tech) continue to work unchanged."""
        from security_mcp.tools.composite_recon import recon

        mock_scanner = AsyncMock()
        mock_scanner.scan_with_banners = AsyncMock(return_value={"open_ports": {}, "host": "10.0.0.1"})

        mock_fp_result = MagicMock()
        mock_fp_result.to_dict.return_value = {"server": "Apache", "technologies": []}
        mock_fp = AsyncMock()
        mock_fp.fingerprint = AsyncMock(return_value=mock_fp_result)

        with patch("security_mcp.scanners.python_connect.PythonConnectScanner", return_value=mock_scanner):
            with patch("security_mcp.scanners.crawler.PythonTechFingerprinter", return_value=mock_fp):
                with patch("security_mcp.scanners.cve_enricher.CVEEnricher") as mock_enricher_cls:
                    mock_enricher = MagicMock()
                    mock_enricher.lookup = AsyncMock(return_value=[])
                    mock_enricher_cls.return_value = mock_enricher
                    result = await recon("http://10.0.0.1", checks="ports,tech", timeout=2.0)

        assert "ports" in result
        assert "technologies" in result
        assert result["target"] == "http://10.0.0.1"

    @pytest.mark.asyncio
    async def test_default_checks(self):
        """Default checks parameter ('ports,tech') works."""
        from security_mcp.tools.composite_recon import recon

        mock_scanner = AsyncMock()
        mock_scanner.scan_with_banners = AsyncMock(return_value={"open_ports": {}, "host": "10.0.0.1"})

        mock_fp_result = MagicMock()
        mock_fp_result.to_dict.return_value = {}
        mock_fp = AsyncMock()
        mock_fp.fingerprint = AsyncMock(return_value=mock_fp_result)

        with patch("security_mcp.scanners.python_connect.PythonConnectScanner", return_value=mock_scanner):
            with patch("security_mcp.scanners.crawler.PythonTechFingerprinter", return_value=mock_fp):
                with patch("security_mcp.scanners.cve_enricher.CVEEnricher") as mock_enricher_cls:
                    mock_enricher = MagicMock()
                    mock_enricher.lookup = AsyncMock(return_value=[])
                    mock_enricher_cls.return_value = mock_enricher
                    result = await recon("10.0.0.1")

        assert "checks_run" in result
        assert "ports" in result["checks_run"]
        assert "tech" in result["checks_run"]
