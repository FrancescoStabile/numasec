"""Tests for security_mcp.scanners.service_prober — protocol-specific service probing."""

from __future__ import annotations

import asyncio
import ftplib
import smtplib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_mcp.scanners._base import PortInfo
from security_mcp.scanners.service_prober import (
    ServiceProbeResult,
    ServiceProber,
)


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------


class TestProbeFtpAnonymousAllowed:
    @pytest.mark.asyncio
    async def test_probe_ftp_anonymous_allowed(self):
        """FTP anonymous login succeeds -- should report high-severity finding."""
        prober = ServiceProber()

        async def fake_to_thread(func, *args, **kwargs):
            return ("220 ProFTPD 1.3.5 Server ready.", ["pub", "incoming"], False, "")

        with patch("asyncio.to_thread", side_effect=fake_to_thread):
            result = await prober._probe_ftp("10.0.0.1", 21, 5.0)

        assert result.port == 21
        assert result.service == "ftp"
        assert result.details.get("anonymous_access") is True
        assert any(f["type"] == "anonymous_access" for f in result.findings)
        assert any(f["severity"] == "high" for f in result.findings)
        assert result.error == ""


class TestProbeFtpAnonymousDenied:
    @pytest.mark.asyncio
    async def test_probe_ftp_anonymous_denied(self):
        """FTP anonymous login rejected (530) -- no security finding."""
        prober = ServiceProber()

        async def fake_to_thread(func, *args, **kwargs):
            return ("220 vsftpd 3.0.3", [], False, "530 Login incorrect.")

        with patch("asyncio.to_thread", side_effect=fake_to_thread):
            result = await prober._probe_ftp("10.0.0.1", 21, 5.0)

        assert result.port == 21
        assert result.details.get("anonymous_access") is False
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------


class TestProbeSmtpOpenRelay:
    @pytest.mark.asyncio
    async def test_probe_smtp_open_relay(self):
        """SMTP open relay -- RCPT TO for external domain accepted (code 250)."""
        prober = ServiceProber()

        info = {
            "banner": "220 mail.example.com ESMTP Postfix",
            "connect_code": 220,
            "ehlo_supported": True,
            "extensions": ["250-STARTTLS", "250-SIZE 10240000"],
            "starttls": True,
            "open_relay": True,
            "relay_test_code": 250,
            "relay_test_msg": "Ok",
            "vrfy_enabled": False,
            "vrfy_code": 502,
            "vrfy_response": "5.5.1 VRFY command disabled",
            "expn_enabled": False,
        }

        async def fake_to_thread(func, *args, **kwargs):
            return info

        with patch("asyncio.to_thread", side_effect=fake_to_thread):
            result = await prober._probe_smtp("10.0.0.1", 25, 5.0)

        assert result.service == "smtp"
        assert any(f["type"] == "open_relay" for f in result.findings)
        assert any(f["severity"] == "critical" for f in result.findings)


class TestProbeSmtpVrfyEnumeration:
    @pytest.mark.asyncio
    async def test_probe_smtp_vrfy_enumeration(self):
        """SMTP VRFY command enabled -- user enumeration possible."""
        prober = ServiceProber()

        info = {
            "banner": "220 mail.example.com ESMTP",
            "connect_code": 220,
            "ehlo_supported": True,
            "extensions": ["250-VRFY"],
            "starttls": False,
            "open_relay": False,
            "vrfy_enabled": True,
            "vrfy_code": 252,
            "vrfy_response": "2.1.5 root <root@mail.example.com>",
            "expn_enabled": False,
        }

        async def fake_to_thread(func, *args, **kwargs):
            return info

        with patch("asyncio.to_thread", side_effect=fake_to_thread):
            result = await prober._probe_smtp("10.0.0.1", 25, 5.0)

        assert any(f["type"] == "vrfy_enabled" for f in result.findings)
        assert any(f["severity"] == "medium" for f in result.findings)


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------


class TestProbeSshWeakAlgorithms:
    @pytest.mark.asyncio
    async def test_probe_ssh_weak_algorithms(self):
        """When asyncssh is unavailable, probe falls back to raw banner."""
        prober = ServiceProber()

        with patch("security_mcp.scanners.service_prober.HAS_ASYNCSSH", False):
            mock_data = b"SSH-2.0-OpenSSH_7.4 CentOS"

            async def fake_raw_recv(host, port, timeout):
                return mock_data

            with patch.object(prober, "_raw_recv", side_effect=fake_raw_recv):
                result = await prober._probe_ssh("10.0.0.1", 22, 5.0)

        assert result.service == "ssh"
        assert result.version == "SSH-2.0-OpenSSH_7.4 CentOS"
        assert result.details.get("server_version") == "SSH-2.0-OpenSSH_7.4 CentOS"


class TestProbeSshNotInstalled:
    @pytest.mark.asyncio
    async def test_probe_ssh_not_installed_uses_banner(self):
        """Without asyncssh, SSH probe falls back to raw banner grab."""
        prober = ServiceProber()

        with patch("security_mcp.scanners.service_prober.HAS_ASYNCSSH", False):
            mock_data = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

            async def fake_raw_recv(host, port, timeout):
                return mock_data

            with patch.object(prober, "_raw_recv", side_effect=fake_raw_recv):
                result = await prober._probe_ssh("10.0.0.1", 22, 5.0)

        assert result.service == "ssh"
        assert "OpenSSH_8.2p1" in result.version
        assert result.details.get("note") == "Install asyncssh for full algorithm/auth enumeration"
        assert result.details.get("os_hint") == "Ubuntu Linux"


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------


class TestProbeSmbNotInstalled:
    @pytest.mark.asyncio
    async def test_probe_smb_not_installed_uses_raw(self):
        """Without smbprotocol, SMB probe falls back to raw socket negotiation."""
        prober = ServiceProber()

        # Build a fake SMB2 response (at least 74 bytes)
        fake_response = bytearray(80)
        fake_response[4:8] = b"\xfeSMB"  # SMB2 magic
        # Set signing not required at offset 70 (security mode = 0x00)
        fake_response[70] = 0x00
        fake_response[71] = 0x00

        with patch("security_mcp.scanners.service_prober.HAS_SMBPROTOCOL", False):
            # Mock _probe_smb_raw to avoid real socket operations
            async def fake_probe_smb_raw(host, port, timeout, result, findings):
                result.details["raw_response_len"] = len(fake_response)
                result.details["smb1_supported"] = False
                result.details["signing_required"] = False
                result.details["note"] = "Install smbprotocol for null-session and share enumeration"
                findings.append({
                    "type": "smb_signing_disabled",
                    "severity": "medium",
                    "detail": "SMB message signing is not required (relay attacks possible)",
                })

            with patch.object(prober, "_probe_smb_raw", side_effect=fake_probe_smb_raw):
                result = await prober._probe_smb("10.0.0.1", 445, 5.0)

        assert result.service == "smb"
        assert result.details.get("note") == "Install smbprotocol for null-session and share enumeration"
        assert any(f["type"] == "smb_signing_disabled" for f in result.findings)


# ---------------------------------------------------------------------------
# Database: Redis
# ---------------------------------------------------------------------------


class TestProbeDatabaseRedisUnauth:
    @pytest.mark.asyncio
    async def test_probe_redis_unauthenticated(self):
        """Redis responds to PING without auth -- critical finding."""
        prober = ServiceProber()

        read_responses = [
            b"+PONG\r\n",  # PING response (readline)
            b"$1000\r\nredis_version:7.0.11\r\nos:Linux\r\n",  # INFO response (read)
            b"*2\r\n$3\r\ndir\r\n$16\r\n/var/lib/redis\r\n",  # CONFIG response (read)
        ]

        class FakeReader:
            def __init__(self):
                self._call_idx = 0

            async def readline(self):
                return read_responses[0]

            async def read(self, n):
                self._call_idx += 1
                idx = min(self._call_idx, len(read_responses) - 1)
                return read_responses[idx]

        class FakeWriter:
            def write(self, data):
                pass

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def fake_wait_for(coro, timeout):
            return await coro

        async def fake_open_connection(host, port):
            return FakeReader(), FakeWriter()

        with patch("asyncio.open_connection", side_effect=fake_open_connection):
            with patch("asyncio.wait_for", side_effect=fake_wait_for):
                result = await prober._probe_redis("10.0.0.1", 6379, 5.0)

        assert result.service == "redis"
        assert any(f["type"] == "no_auth_required" for f in result.findings)
        assert any(f["severity"] == "critical" for f in result.findings)


# ---------------------------------------------------------------------------
# Database: MySQL
# ---------------------------------------------------------------------------


class TestProbeDatabaseMysqlVersion:
    @pytest.mark.asyncio
    async def test_probe_mysql_version_extraction(self):
        """MySQL greeting packet is parsed for version string."""
        prober = ServiceProber()

        # Build a minimal MySQL greeting packet
        version_str = b"8.0.33"
        # Payload: proto_version(1) + version + null + remaining filler
        payload = bytes([10]) + version_str + b"\x00" + b"\x00" * 40
        pkt_len = len(payload)
        header = bytes([pkt_len & 0xFF, (pkt_len >> 8) & 0xFF, (pkt_len >> 16) & 0xFF, 0])

        class FakeReader:
            def __init__(self):
                self._call_count = 0

            async def readexactly(self, n):
                self._call_count += 1
                if self._call_count == 1:
                    return header
                elif self._call_count == 2:
                    return payload
                return b"\x00" * n

        class FakeWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def fake_wait_for(coro, timeout):
            return await coro

        async def fake_open_connection(host, port):
            return FakeReader(), FakeWriter()

        with patch("asyncio.open_connection", side_effect=fake_open_connection):
            with patch("asyncio.wait_for", side_effect=fake_wait_for):
                with patch.object(prober, "_mysql_try_anonymous", return_value=False):
                    result = await prober._probe_mysql("10.0.0.1", 3306, 5.0)

        assert result.service == "mysql"
        assert result.version == "8.0.33"
        assert result.details.get("server_version") == "8.0.33"


# ---------------------------------------------------------------------------
# probe_all parallelism
# ---------------------------------------------------------------------------


class TestProbeAllParallel:
    @pytest.mark.asyncio
    async def test_probe_all_parallel_multiple_ports(self):
        """probe_all dispatches to correct probe methods concurrently."""
        prober = ServiceProber()

        ftp_result = ServiceProbeResult(port=21, protocol="tcp", service="ftp", version="vsftpd 3.0.3")
        ssh_result = ServiceProbeResult(port=22, protocol="tcp", service="ssh", version="OpenSSH_8.2p1")

        async def fake_probe_ftp(host, port, timeout):
            return ftp_result

        async def fake_probe_ssh(host, port, timeout):
            return ssh_result

        with patch.object(prober, "_probe_ftp", side_effect=fake_probe_ftp):
            with patch.object(prober, "_probe_ssh", side_effect=fake_probe_ssh):
                ports = [
                    PortInfo(port=21, service="ftp"),
                    PortInfo(port=22, service="ssh"),
                ]
                results = await prober.probe_all("10.0.0.1", ports, timeout=5.0)

        assert len(results) == 2
        ports_probed = {r.port for r in results}
        assert ports_probed == {21, 22}


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class TestProbeTimeoutHandling:
    @pytest.mark.asyncio
    async def test_probe_timeout_returns_error_result(self):
        """If a probe times out, probe_all returns an error result (no crash)."""
        prober = ServiceProber()

        async def slow_probe(host, port, timeout):
            await asyncio.sleep(999)

        with patch.object(prober, "_probe_ftp", side_effect=slow_probe):
            ports = [PortInfo(port=21, service="ftp")]
            results = await prober.probe_all("10.0.0.1", ports, timeout=0.1)

        assert len(results) == 1
        assert results[0].error == "timeout"


# ---------------------------------------------------------------------------
# Empty ports list
# ---------------------------------------------------------------------------


class TestEmptyPortsList:
    @pytest.mark.asyncio
    async def test_empty_ports_returns_empty(self):
        """probe_all with no ports returns an empty list without errors."""
        prober = ServiceProber()
        results = await prober.probe_all("10.0.0.1", [], timeout=5.0)
        assert results == []

    @pytest.mark.asyncio
    async def test_unknown_service_skipped(self):
        """Ports with unrecognized services are silently skipped."""
        prober = ServiceProber()
        ports = [PortInfo(port=9999, service="unknown_proto")]
        results = await prober.probe_all("10.0.0.1", ports, timeout=5.0)
        assert results == []
