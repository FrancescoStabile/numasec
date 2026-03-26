"""Tests for security_mcp.scanners."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_mcp.scanners._base import PortInfo, ScanEngineFactory, ScanResult, ScanType
from security_mcp.scanners.naabu import NaabuScanner, _guess_service
from security_mcp.scanners.nmap import NmapScanner
from security_mcp.scanners.python_connect import (
    TOP_PORTS,
    PythonConnectScanner,
)
from security_mcp.scanners.shodan import ShodanError, ShodanPassiveScanner

# ---------------------------------------------------------------------------
# Dataclass / Enum tests
# ---------------------------------------------------------------------------


class TestPortInfo:
    def test_defaults(self):
        p = PortInfo(port=80)
        assert p.port == 80
        assert p.protocol == "tcp"
        assert p.state == "open"
        assert p.service == ""
        assert p.version == ""
        assert p.banner == ""

    def test_all_fields(self):
        p = PortInfo(
            port=443, protocol="tcp", state="open",
            service="https", version="nginx 1.18.0", banner="HTTP/1.1 200",
        )
        assert p.service == "https"
        assert p.version == "nginx 1.18.0"


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult(host="10.0.0.1")
        assert r.host == "10.0.0.1"
        assert r.ports == []
        assert r.os_guess is None
        assert r.scanner_used == ""

    def test_with_ports(self):
        ports = [PortInfo(port=80), PortInfo(port=443)]
        r = ScanResult(host="example.com", ports=ports, scanner_used="test")
        assert len(r.ports) == 2


class TestScanType:
    def test_all_values(self):
        assert ScanType.CONNECT.value == "connect"
        assert ScanType.SYN.value == "syn"
        assert ScanType.UDP.value == "udp"
        assert ScanType.PASSIVE.value == "passive"


# ---------------------------------------------------------------------------
# ScanEngineFactory tests
# ---------------------------------------------------------------------------


class TestScanEngineFactory:
    def test_auto_naabu(self):
        with patch("security_mcp.scanners._base.shutil.which", side_effect=lambda x: "/usr/bin/naabu" if x == "naabu" else None):
            scanner = ScanEngineFactory.create("auto")
            assert isinstance(scanner, NaabuScanner)

    def test_auto_nmap_fallback(self):
        def _which(name):
            if name == "naabu":
                return None
            if name == "nmap":
                return "/usr/bin/nmap"
            return None

        with patch("security_mcp.scanners._base.shutil.which", side_effect=_which):
            scanner = ScanEngineFactory.create("auto")
            assert isinstance(scanner, NmapScanner)

    def test_auto_python_fallback(self):
        with patch("security_mcp.scanners._base.shutil.which", return_value=None):
            scanner = ScanEngineFactory.create("auto")
            assert isinstance(scanner, PythonConnectScanner)

    def test_explicit_naabu(self):
        scanner = ScanEngineFactory.create("naabu")
        assert isinstance(scanner, NaabuScanner)

    def test_explicit_python(self):
        scanner = ScanEngineFactory.create("python")
        assert isinstance(scanner, PythonConnectScanner)

    def test_explicit_nmap(self):
        scanner = ScanEngineFactory.create("nmap")
        assert isinstance(scanner, NmapScanner)


# ---------------------------------------------------------------------------
# PythonConnectScanner tests
# ---------------------------------------------------------------------------


class TestPythonConnectScannerProperties:
    def test_capabilities(self):
        s = PythonConnectScanner()
        assert s.capabilities == {ScanType.CONNECT}

    def test_no_external_binary(self):
        s = PythonConnectScanner()
        assert s.requires_external_binary is False


class TestPythonConnectResolve:
    def test_top_100(self):
        s = PythonConnectScanner()
        result = s._resolve_ports("top-100")
        assert len(result) == 100
        assert result == TOP_PORTS[:100]

    def test_top_1000(self):
        s = PythonConnectScanner()
        result = s._resolve_ports("top-1000")
        assert result == list(TOP_PORTS)

    def test_explicit_ports(self):
        s = PythonConnectScanner()
        result = s._resolve_ports("80,443,8080")
        assert result == [80, 443, 8080]

    def test_port_range(self):
        s = PythonConnectScanner()
        result = s._resolve_ports("1-10")
        assert result == list(range(1, 11))

    def test_single_port(self):
        s = PythonConnectScanner()
        result = s._resolve_ports("443")
        assert result == [443]


class TestPythonConnectDiscover:
    @pytest.mark.asyncio
    async def test_discover_with_mocked_connections(self):
        """Mock asyncio.open_connection to simulate open/closed ports."""
        s = PythonConnectScanner()

        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        call_count = 0

        async def fake_open(host, port):
            nonlocal call_count
            call_count += 1
            if port in (80, 443):
                return (AsyncMock(), mock_writer)
            raise OSError("Connection refused")

        with patch("security_mcp.scanners.python_connect.asyncio.open_connection", side_effect=fake_open):
            result = await s.discover_ports("10.0.0.1", ports="80,443,22", rate_limit=100)

        assert result.host == "10.0.0.1"
        assert result.scanner_used == "python_connect"
        assert len(result.ports) == 2
        open_ports = {p.port for p in result.ports}
        assert open_ports == {80, 443}
        assert result.scan_time > 0


class TestPythonConnectBanner:
    @pytest.mark.asyncio
    async def test_detect_services_banner(self):
        s = PythonConnectScanner()

        mock_reader = AsyncMock()
        # Port 22 now uses _grab_line_banner (readline), not generic read.
        mock_reader.readline = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.2p1\r\n")
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        async def fake_open(host, port):
            return (mock_reader, mock_writer)

        with patch("security_mcp.scanners.python_connect.asyncio.open_connection", side_effect=fake_open):
            result = await s.detect_services("10.0.0.1", [22])

        assert len(result) == 1
        assert result[0].port == 22
        assert result[0].service == "ssh"
        assert "SSH" in result[0].banner


# ---------------------------------------------------------------------------
# NaabuScanner tests
# ---------------------------------------------------------------------------


class TestNaabuScannerProperties:
    def test_capabilities(self):
        s = NaabuScanner()
        assert ScanType.CONNECT in s.capabilities
        assert ScanType.SYN in s.capabilities
        assert ScanType.UDP in s.capabilities

    def test_requires_binary(self):
        s = NaabuScanner()
        assert s.requires_external_binary is True


class TestNaabuParseJson:
    def test_parse_json_output(self):
        s = NaabuScanner()
        json_lines = (
            '{"host":"example.com","ip":"93.184.216.34","port":80,"protocol":"tcp"}\n'
            '{"host":"example.com","ip":"93.184.216.34","port":443,"protocol":"tcp"}\n'
        )
        result = s._parse_json_output(json_lines, "example.com")
        assert result.host == "example.com"
        assert len(result.ports) == 2
        ports = {p.port for p in result.ports}
        assert ports == {80, 443}
        assert result.scanner_used == "naabu"

    def test_parse_empty_output(self):
        s = NaabuScanner()
        result = s._parse_json_output("", "example.com")
        assert result.ports == []

    def test_parse_mixed_lines(self):
        s = NaabuScanner()
        output = (
            'some warning line\n'
            '{"host":"test.com","port":22,"protocol":"tcp"}\n'
            'another warning\n'
        )
        result = s._parse_json_output(output, "test.com")
        assert len(result.ports) == 1
        assert result.ports[0].port == 22


class TestNaabuDiscover:
    @pytest.mark.asyncio
    async def test_binary_not_found(self):
        s = NaabuScanner()
        with (
            patch("security_mcp.scanners.naabu.shutil.which", return_value=None),
            pytest.raises(FileNotFoundError, match="naabu binary not found"),
        ):
            await s.discover_ports("example.com")

    @pytest.mark.asyncio
    async def test_discover_success(self):
        s = NaabuScanner()
        json_output = (
            '{"host":"example.com","ip":"93.184.216.34","port":80,"protocol":"tcp"}\n'
            '{"host":"example.com","ip":"93.184.216.34","port":443,"protocol":"tcp"}\n'
        )

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(json_output.encode(), b""))
        mock_proc.returncode = 0

        with patch("security_mcp.scanners.naabu.shutil.which", return_value="/usr/bin/naabu"), \
             patch("security_mcp.scanners.naabu.asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await s.discover_ports("example.com", ports="top-1000")

        assert result.host == "example.com"
        assert len(result.ports) == 2
        assert result.scanner_used == "naabu"
        assert result.scan_time > 0


class TestGuessService:
    def test_known_port(self):
        assert _guess_service(22) == "ssh"
        assert _guess_service(80) == "http"
        assert _guess_service(443) == "https"

    def test_banner_override(self):
        assert _guess_service(8080, "SSH-2.0-OpenSSH") == "ssh"
        assert _guess_service(9999, "HTTP/1.1 200 OK") == "http"

    def test_unknown(self):
        assert _guess_service(55555) == ""


# ---------------------------------------------------------------------------
# NmapScanner tests
# ---------------------------------------------------------------------------


class TestNmapScannerProperties:
    def test_capabilities(self):
        s = NmapScanner()
        assert ScanType.CONNECT in s.capabilities
        assert ScanType.SYN in s.capabilities

    def test_requires_binary(self):
        s = NmapScanner()
        assert s.requires_external_binary is True


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host starttime="1234">
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 4.15" accuracy="95"/>
    </os>
  </host>
</nmaprun>"""


class TestNmapParseXml:
    def test_parse_xml_output(self):
        s = NmapScanner()
        result = s._parse_xml_output(SAMPLE_NMAP_XML, "example.com")
        assert result.host == "example.com"
        assert result.scanner_used == "nmap"
        # Only open ports (80 and 443, not 22 which is closed)
        assert len(result.ports) == 2
        ports = {p.port for p in result.ports}
        assert ports == {80, 443}
        # Check service detection
        http_port = next(p for p in result.ports if p.port == 80)
        assert http_port.service == "http"
        assert "Apache" in http_port.version
        # OS detection
        assert result.os_guess == "Linux 4.15"

    def test_parse_invalid_xml(self):
        s = NmapScanner()
        result = s._parse_xml_output("not xml", "example.com")
        assert result.ports == []

    def test_parse_empty_xml(self):
        s = NmapScanner()
        result = s._parse_xml_output("<nmaprun></nmaprun>", "example.com")
        assert result.ports == []


class TestNmapDiscover:
    @pytest.mark.asyncio
    async def test_binary_not_found(self):
        s = NmapScanner()
        with (
            patch("security_mcp.scanners.nmap.shutil.which", return_value=None),
            pytest.raises(FileNotFoundError, match="nmap binary not found"),
        ):
            await s.discover_ports("example.com")

    @pytest.mark.asyncio
    async def test_discover_success(self):
        s = NmapScanner()
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(SAMPLE_NMAP_XML.encode(), b""),
        )
        mock_proc.returncode = 0

        with patch("security_mcp.scanners.nmap.shutil.which", return_value="/usr/bin/nmap"), \
             patch("security_mcp.scanners.nmap.asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await s.discover_ports("example.com", ports="top-1000")

        assert len(result.ports) == 2
        assert result.scanner_used == "nmap"

    @pytest.mark.asyncio
    async def test_syn_scan_command(self):
        """Verify SYN scan uses -sS flag."""
        s = NmapScanner()
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"<nmaprun></nmaprun>", b""),
        )
        mock_proc.returncode = 0

        with patch("security_mcp.scanners.nmap.shutil.which", return_value="/usr/bin/nmap"), \
             patch("security_mcp.scanners.nmap.asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await s.discover_ports("example.com", scan_type=ScanType.SYN)

        # Check that -sS was passed
        cmd_args = mock_exec.call_args[0]
        assert "-sS" in cmd_args


# ---------------------------------------------------------------------------
# ShodanPassiveScanner
# ---------------------------------------------------------------------------


class TestShodanScannerProperties:
    def test_capabilities(self):
        s = ShodanPassiveScanner(api_key="test-key")
        assert s.capabilities == {ScanType.PASSIVE}

    def test_no_external_binary(self):
        s = ShodanPassiveScanner(api_key="test-key")
        assert s.requires_external_binary is False


class TestShodanNoApiKey:
    @pytest.mark.asyncio
    async def test_raises_without_api_key(self):
        s = ShodanPassiveScanner(api_key="")
        with pytest.raises(ShodanError, match="API key required"):
            await s.discover_ports("1.2.3.4")


class TestShodanDiscover:
    @pytest.mark.asyncio
    async def test_discover_success(self):
        shodan_response = {
            "ip_str": "93.184.216.34",
            "os": "Linux",
            "data": [
                {
                    "port": 80,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.21.0",
                    "data": "HTTP/1.1 200 OK\r\nServer: nginx",
                },
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.21.0",
                    "data": "HTTP/1.1 200 OK",
                },
            ],
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = shodan_response
        mock_response.text = '{"ip_str": "93.184.216.34"}'

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("security_mcp.scanners.shodan.httpx.AsyncClient", return_value=mock_client):
            s = ShodanPassiveScanner(api_key="test-key")
            result = await s.discover_ports("93.184.216.34")

        assert result.host == "93.184.216.34"
        assert result.scanner_used == "shodan"
        assert result.os_guess == "Linux"
        assert len(result.ports) == 2
        assert result.ports[0].port == 80
        assert result.ports[0].service == "nginx"
        assert result.ports[0].version == "1.21.0"
        assert result.ports[1].port == 443

    @pytest.mark.asyncio
    async def test_discover_404_returns_empty(self):
        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("security_mcp.scanners.shodan.httpx.AsyncClient", return_value=mock_client):
            s = ShodanPassiveScanner(api_key="test-key")
            result = await s.discover_ports("10.0.0.1")

        assert result.host == "10.0.0.1"
        assert len(result.ports) == 0

    @pytest.mark.asyncio
    async def test_discover_api_error(self):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("security_mcp.scanners.shodan.httpx.AsyncClient", return_value=mock_client):
            s = ShodanPassiveScanner(api_key="bad-key")
            with pytest.raises(ShodanError, match="401"):
                await s.discover_ports("1.2.3.4")

    @pytest.mark.asyncio
    async def test_banner_truncated_to_500(self):
        long_banner = "A" * 1000
        shodan_response = {
            "data": [{"port": 80, "data": long_banner}],
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = shodan_response
        mock_response.text = "{}"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("security_mcp.scanners.shodan.httpx.AsyncClient", return_value=mock_client):
            s = ShodanPassiveScanner(api_key="test-key")
            result = await s.discover_ports("1.2.3.4")

        assert len(result.ports[0].banner) == 500


class TestShodanDetectServices:
    @pytest.mark.asyncio
    async def test_detect_filters_by_port(self):
        shodan_response = {
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "", "data": ""},
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "", "data": ""},
                {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2", "data": ""},
            ],
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = shodan_response
        mock_response.text = "{}"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("security_mcp.scanners.shodan.httpx.AsyncClient", return_value=mock_client):
            s = ShodanPassiveScanner(api_key="test-key")
            ports = await s.detect_services("1.2.3.4", [80, 22])

        assert len(ports) == 2
        assert {p.port for p in ports} == {80, 22}


class TestScanEngineFactoryShodan:
    def test_factory_creates_shodan(self):
        scanner = ScanEngineFactory.create("shodan")
        assert isinstance(scanner, ShodanPassiveScanner)


# ---------------------------------------------------------------------------
# Enhanced PythonConnectScanner — Banner grabbing
# ---------------------------------------------------------------------------


class TestBannerGrabbingHttp:
    """Test protocol-aware banner grabbing for HTTP ports."""

    @pytest.mark.asyncio
    async def test_banner_grabbing_http_server_header(self):
        """Send HTTP HEAD, extract Server header from response."""
        s = PythonConnectScanner()

        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Content-Type: text/html\r\n"
            b"Connection: close\r\n\r\n"
        )

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=http_response)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        banner = await s._grab_banner(mock_reader, mock_writer, 80, target="example.com")
        assert banner == "nginx/1.24.0"

    @pytest.mark.asyncio
    async def test_banner_grabbing_http_no_server_header(self):
        """When no Server header, return the HTTP status line."""
        s = PythonConnectScanner()

        http_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=http_response)
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        banner = await s._grab_banner(mock_reader, mock_writer, 8080, target="10.0.0.1")
        assert banner == "HTTP/1.1 200 OK"

    @pytest.mark.asyncio
    async def test_banner_grabbing_ssh(self):
        """SSH banner is read as a single line."""
        s = PythonConnectScanner()

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        banner = await s._grab_banner(mock_reader, mock_writer, 22, target="10.0.0.1")
        assert "SSH-2.0-OpenSSH_8.9p1" in banner

    @pytest.mark.asyncio
    async def test_banner_grabbing_smtp(self):
        """SMTP banner is read as a single line."""
        s = PythonConnectScanner()

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(
            return_value=b"220 mail.example.com ESMTP Postfix\r\n"
        )
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        banner = await s._grab_banner(mock_reader, mock_writer, 25, target="mail.example.com")
        assert "Postfix" in banner
        assert "220" in banner

    @pytest.mark.asyncio
    async def test_banner_grabbing_ftp(self):
        """FTP welcome banner is read as a single line."""
        s = PythonConnectScanner()

        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(
            return_value=b"220 ProFTPD 1.3.5 Server ready.\r\n"
        )
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        banner = await s._grab_banner(mock_reader, mock_writer, 21, target="ftp.example.com")
        assert "ProFTPD" in banner

    @pytest.mark.asyncio
    async def test_banner_grabbing_generic(self):
        """Unknown ports use generic read."""
        s = PythonConnectScanner()

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"Redis v=7.0.5 crlf")
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        banner = await s._grab_banner(mock_reader, mock_writer, 6379, target="10.0.0.1")
        assert "Redis" in banner

    @pytest.mark.asyncio
    async def test_banner_grabbing_timeout(self):
        """Timeout during banner grab returns empty string."""
        s = PythonConnectScanner()

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(side_effect=TimeoutError())
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        banner = await s._grab_banner(mock_reader, mock_writer, 9999, target="10.0.0.1")
        assert banner == ""


# ---------------------------------------------------------------------------
# Enhanced PythonConnectScanner — Version extraction
# ---------------------------------------------------------------------------


class TestVersionExtraction:
    """Test regex-based version extraction from banner strings."""

    def test_openssh_version(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert product == "OpenSSH"
        assert version == "8.9"

    def test_openssh_three_part(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("SSH-2.0-OpenSSH_9.3.1")
        assert product == "OpenSSH"
        assert version == "9.3.1"

    def test_apache_version(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("Apache/2.4.41 (Ubuntu)")
        assert product == "Apache"
        assert version == "2.4.41"

    def test_nginx_version(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("nginx/1.24.0")
        assert product == "nginx"
        assert version == "1.24.0"

    def test_iis_version(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("Microsoft-IIS/10.0")
        assert product == "IIS"
        assert version == "10.0"

    def test_mysql_version(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("5.5.5-MySQL 8.0.33")
        assert product == "MySQL"
        assert version == "8.0.33"

    def test_postgresql_version(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("PostgreSQL 15.3 on x86_64")
        assert product == "PostgreSQL"
        assert version == "15.3"

    def test_express_no_version(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("X-Powered-By: Express")
        assert product == "Express"
        assert version == ""

    def test_proftpd(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("220 ProFTPD 1.3.5 Server ready.")
        assert product == "ProFTPD"
        assert version == "1.3.5"

    def test_unknown_banner(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("some random service banner")
        assert product == ""
        assert version == ""

    def test_empty_banner(self):
        s = PythonConnectScanner()
        product, version = s._extract_version("")
        assert product == ""
        assert version == ""


# ---------------------------------------------------------------------------
# Enhanced PythonConnectScanner — SSL info
# ---------------------------------------------------------------------------


class TestSslInfoExtraction:
    """Test SSL/TLS certificate info extraction."""

    def test_parse_cert_dict_full(self):
        """Verify _parse_cert_dict extracts all fields correctly."""
        cert = {
            "subject": (
                (("commonName", "example.com"),),
            ),
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "*.example.com"),
            ),
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "issuer": (
                (("organizationName", "Let's Encrypt"),),
                (("commonName", "R3"),),
            ),
        }
        info = PythonConnectScanner._parse_cert_dict(cert)
        assert info["cn"] == "example.com"
        assert info["san"] == ["example.com", "*.example.com"]
        assert info["expiry"] == "Jan  1 00:00:00 2027 GMT"
        assert info["issuer"] == "Let's Encrypt"

    def test_parse_cert_dict_minimal(self):
        """Cert with only CN, no SANs or issuer details."""
        cert = {
            "subject": (
                (("commonName", "test.local"),),
            ),
        }
        info = PythonConnectScanner._parse_cert_dict(cert)
        assert info["cn"] == "test.local"
        assert "san" not in info
        assert "issuer" not in info

    def test_parse_cert_dict_empty(self):
        """Empty cert dict returns empty info."""
        info = PythonConnectScanner._parse_cert_dict({})
        assert info == {}

    @pytest.mark.asyncio
    async def test_get_ssl_info_connection_error(self):
        """SSL connection failure returns empty dict."""
        s = PythonConnectScanner()

        async def fake_open(*args, **kwargs):
            raise OSError("Connection refused")

        with patch(
            "security_mcp.scanners.python_connect.asyncio.open_connection",
            side_effect=fake_open,
        ):
            info = await s._get_ssl_info("10.0.0.1", 443)
        assert info == {}


# ---------------------------------------------------------------------------
# Enhanced PythonConnectScanner — Full enhanced result format
# ---------------------------------------------------------------------------


class TestEnhancedResultFormat:
    """Test scan_with_banners() output structure."""

    @pytest.mark.asyncio
    async def test_enhanced_result_structure(self):
        """Verify the full enhanced result dict keys and types."""
        s = PythonConnectScanner()

        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        call_count = 0

        async def fake_open(host, port, **kwargs):
            nonlocal call_count
            call_count += 1
            # For discovery phase: ports 80 and 22 are open, rest closed.
            # For banner phase: return appropriate banners.
            if port == 80:
                reader = AsyncMock()
                reader.read = AsyncMock(
                    return_value=(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Server: Apache/2.4.41\r\n\r\n"
                    )
                )
                return reader, mock_writer
            if port == 22:
                reader = AsyncMock()
                reader.readline = AsyncMock(
                    return_value=b"SSH-2.0-OpenSSH_8.9p1\r\n"
                )
                return reader, mock_writer
            raise OSError("Connection refused")

        with patch(
            "security_mcp.scanners.python_connect.asyncio.open_connection",
            side_effect=fake_open,
        ):
            result = await s.scan_with_banners("10.0.0.1", ports="22,80,443")

        # Top-level keys.
        assert "open_ports" in result
        assert "services" in result
        assert "ssl_info" in result
        assert "scan_duration_ms" in result

        # open_ports is sorted list of ints.
        assert isinstance(result["open_ports"], list)
        assert result["open_ports"] == sorted(result["open_ports"])

        # services dict keyed by port string.
        assert isinstance(result["services"], dict)
        for port_str, svc in result["services"].items():
            assert isinstance(port_str, str)
            assert "name" in svc
            assert "banner" in svc
            assert "version" in svc
            assert "product" in svc

        # scan_duration_ms is a positive float.
        assert result["scan_duration_ms"] > 0

    @pytest.mark.asyncio
    async def test_enhanced_result_no_open_ports(self):
        """When no ports are open, return empty collections."""
        s = PythonConnectScanner()

        async def fake_open(host, port, **kwargs):
            raise OSError("Connection refused")

        with patch(
            "security_mcp.scanners.python_connect.asyncio.open_connection",
            side_effect=fake_open,
        ):
            result = await s.scan_with_banners("10.0.0.1", ports="12345")

        assert result["open_ports"] == []
        assert result["services"] == {}
        assert result["ssl_info"] == {}
        assert result["scan_duration_ms"] > 0

    @pytest.mark.asyncio
    async def test_enhanced_result_service_versions(self):
        """Verify version extraction populates the services dict."""
        s = PythonConnectScanner()

        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        async def fake_open(host, port, **kwargs):
            if port == 80:
                reader = AsyncMock()
                reader.read = AsyncMock(
                    return_value=b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"
                )
                return reader, mock_writer
            raise OSError("Connection refused")

        with patch(
            "security_mcp.scanners.python_connect.asyncio.open_connection",
            side_effect=fake_open,
        ):
            result = await s.scan_with_banners("10.0.0.1", ports="80")

        assert 80 in result["open_ports"]
        svc = result["services"]["80"]
        assert svc["product"] == "nginx"
        assert svc["version"] == "1.24.0"
        assert svc["banner"] == "nginx/1.24.0"


# ---------------------------------------------------------------------------
# port_scan tool wrapper
# ---------------------------------------------------------------------------


class TestPortScanTool:
    """Test the recon tool (replaces port_scan) registered in ToolRegistry."""

    def test_recon_in_registry(self):
        """Verify recon is registered with correct schema."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "recon" in registry.available_tools

        schemas = registry.get_schemas()
        recon_schema = next(s for s in schemas if s["function"]["name"] == "recon")
        params = recon_schema["function"]["parameters"]
        assert "target" in params["properties"]
        assert "ports" in params["properties"]
        assert "timeout" in params["properties"]
        assert params["required"] == ["target"]

    @pytest.mark.asyncio
    async def test_port_scan_tool_calls_scanner(self):
        """Verify the tool wrapper creates scanner and returns results."""
        from security_mcp.tools import port_scan

        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        async def fake_open(host, port, **kwargs):
            if port == 80:
                reader = AsyncMock()
                reader.read = AsyncMock(
                    return_value=b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
                )
                return reader, mock_writer
            raise OSError("Connection refused")

        with patch(
            "security_mcp.scanners.python_connect.asyncio.open_connection",
            side_effect=fake_open,
        ):
            result = await port_scan(target="10.0.0.1", ports="80,443")

        assert isinstance(result, dict)
        assert "open_ports" in result
        assert "services" in result
        assert 80 in result["open_ports"]
