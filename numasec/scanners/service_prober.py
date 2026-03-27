"""Protocol-specific service probing for non-HTTP services.

Probes discovered services with protocol-aware tests after port scanning.
Uses stdlib (ftplib, smtplib, socket) where possible; optional packages
(asyncssh, smbprotocol) provide deeper enumeration when installed.
"""

from __future__ import annotations

import asyncio
import contextlib
import ftplib
import logging
import smtplib
import struct
from dataclasses import dataclass, field
from typing import Any

from numasec.scanners._base import PortInfo

logger = logging.getLogger("numasec.scanners.service_prober")

# ---------------------------------------------------------------------------
# Optional dependencies — degrade gracefully when missing
# ---------------------------------------------------------------------------

try:
    import asyncssh

    HAS_ASYNCSSH = True
except ImportError:
    HAS_ASYNCSSH = False

try:
    from smbprotocol.connection import Connection as SMBConnection
    from smbprotocol.session import Session as SMBSession
    from smbprotocol.tree import TreeConnect

    HAS_SMBPROTOCOL = True
except ImportError:
    HAS_SMBPROTOCOL = False

# ---------------------------------------------------------------------------
# Weak SSH algorithms flagged during probing
# ---------------------------------------------------------------------------

_WEAK_KEX: frozenset[str] = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    }
)

_WEAK_CIPHERS: frozenset[str] = frozenset(
    {
        "arcfour",
        "arcfour128",
        "arcfour256",
        "3des-cbc",
        "blowfish-cbc",
        "cast128-cbc",
    }
)

_WEAK_MACS: frozenset[str] = frozenset(
    {
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1-96",
    }
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ServiceProbeResult:
    """Result from probing a single service."""

    port: int
    protocol: str
    service: str
    version: str
    findings: list[dict[str, Any]] = field(default_factory=list)  # security-relevant findings
    details: dict[str, Any] = field(default_factory=dict)  # protocol-specific enumeration data
    error: str = ""  # empty string if probe succeeded


# ---------------------------------------------------------------------------
# ServiceProber
# ---------------------------------------------------------------------------


class ServiceProber:
    """Probe discovered services with protocol-specific tests.

    After port scanning discovers open ports, this class performs deeper
    protocol-level enumeration: banner parsing, anonymous/null-session
    checks, weak-configuration detection, and version extraction.
    """

    # Port number -> probe method name
    _PROBE_MAP: dict[int, str] = {
        21: "_probe_ftp",
        22: "_probe_ssh",
        25: "_probe_smtp",
        110: "_probe_pop3",
        143: "_probe_imap",
        445: "_probe_smb",
        587: "_probe_smtp",
        993: "_probe_imap",
        995: "_probe_pop3",
        3306: "_probe_mysql",
        5432: "_probe_postgresql",
        6379: "_probe_redis",
        27017: "_probe_mongodb",
        11211: "_probe_memcached",
    }

    # Service name -> probe method name (for non-standard ports)
    _SERVICE_PROBE_MAP: dict[str, str] = {
        "ftp": "_probe_ftp",
        "ssh": "_probe_ssh",
        "smtp": "_probe_smtp",
        "smb": "_probe_smb",
        "microsoft-ds": "_probe_smb",
        "mysql": "_probe_mysql",
        "postgresql": "_probe_postgresql",
        "redis": "_probe_redis",
        "mongodb": "_probe_mongodb",
        "mongod": "_probe_mongodb",
        "memcached": "_probe_memcached",
        "memcache": "_probe_memcached",
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def probe_all(
        self,
        host: str,
        ports: list[Any],  # list of PortInfo
        timeout: float = 5.0,
        max_concurrent: int = 5,
    ) -> list[ServiceProbeResult]:
        """Probe all discovered services in parallel with concurrency limit.

        Args:
            host: Target hostname or IP address.
            ports: List of ``PortInfo`` from port scanning phase.
            timeout: Per-probe timeout in seconds.
            max_concurrent: Maximum number of probes running simultaneously.

        Returns:
            List of ``ServiceProbeResult``, one per probed port.
            Ports with no matching probe function are silently skipped.
        """
        sem = asyncio.Semaphore(max_concurrent)
        tasks: list[asyncio.Task[ServiceProbeResult | None]] = []

        for port_info in ports:
            method_name = self._resolve_probe(port_info)
            if method_name is None:
                continue
            probe_fn = getattr(self, method_name, None)
            if probe_fn is None:
                logger.warning("Probe method %s not found, skipping port %d", method_name, port_info.port)
                continue
            tasks.append(asyncio.create_task(self._run_probe(sem, probe_fn, host, port_info.port, timeout)))

        if not tasks:
            return []

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        results: list[ServiceProbeResult] = []
        for r in raw_results:
            if isinstance(r, ServiceProbeResult):
                results.append(r)
            elif isinstance(r, BaseException):
                logger.debug("Probe task raised: %s", r)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_probe(self, port_info: PortInfo) -> str | None:
        """Determine the probe method for a given port.

        Prefers port-number match, falls back to service-name match.
        """
        method = self._PROBE_MAP.get(port_info.port)
        if method:
            return method
        service = port_info.service.lower().strip()
        return self._SERVICE_PROBE_MAP.get(service)

    async def _run_probe(
        self,
        sem: asyncio.Semaphore,
        probe_fn: Any,
        host: str,
        port: int,
        timeout: float,
    ) -> ServiceProbeResult:
        """Execute a single probe under the semaphore and timeout guard."""
        async with sem:
            try:
                return await asyncio.wait_for(probe_fn(host, port, timeout), timeout=timeout + 2.0)
            except TimeoutError:
                logger.warning("Probe timed out for %s:%d", host, port)
                return ServiceProbeResult(port=port, protocol="tcp", service="unknown", version="", error="timeout")
            except Exception as exc:
                logger.warning("Probe failed for %s:%d: %s", host, port, exc)
                return ServiceProbeResult(port=port, protocol="tcp", service="unknown", version="", error=str(exc))

    @staticmethod
    async def _raw_recv(host: str, port: int, timeout: float, send: bytes | None = None) -> bytes:
        """Open a TCP socket, optionally send data, and return whatever arrives."""
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            if send:
                writer.write(send)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            return data
        finally:
            writer.close()
            await writer.wait_closed()

    # ------------------------------------------------------------------
    # FTP
    # ------------------------------------------------------------------

    async def _probe_ftp(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe FTP: anonymous login, directory listing, write test."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="ftp", version="")
        findings: list[dict[str, Any]] = []

        def _ftp_work() -> tuple[str, list[str], bool, str]:
            """Blocking FTP operations — runs in a thread."""
            banner = ""
            file_list: list[str] = []
            writable = False
            err = ""
            ftp = ftplib.FTP(timeout=timeout)
            try:
                banner = ftp.connect(host, port, timeout=timeout)
                ftp.login("anonymous", "anonymous@example.com")
                with contextlib.suppress(ftplib.error_perm):
                    file_list = ftp.nlst()[:50]  # cap listing
                # Write test — create and immediately remove a temp directory
                try:
                    ftp.mkd("__secmcp_probe_test__")
                    ftp.rmd("__secmcp_probe_test__")
                    writable = True
                except ftplib.error_perm:
                    pass
            except ftplib.error_perm as exc:
                err = str(exc)
            except (OSError, EOFError) as exc:
                err = str(exc)
            finally:
                with contextlib.suppress(Exception):
                    ftp.quit()
            return banner, file_list, writable, err

        banner, file_list, writable, err = await asyncio.to_thread(_ftp_work)

        # Parse version from banner (e.g. "220 ProFTPD 1.3.5 Server ready.")
        result.version = banner
        result.details["banner"] = banner
        result.details["file_list"] = file_list

        if err and "530" in err:
            # 530 = login denied, anonymous access not allowed — not a finding, just info
            result.details["anonymous_access"] = False
        elif not err:
            result.details["anonymous_access"] = True
            findings.append(
                {
                    "type": "anonymous_access",
                    "severity": "high",
                    "detail": "FTP anonymous login permitted",
                    "evidence": f"Banner: {banner[:200]}",
                }
            )
            if writable:
                result.details["writable"] = True
                findings.append(
                    {
                        "type": "writable_dir",
                        "severity": "critical",
                        "detail": "FTP anonymous user can create directories (writable)",
                        "evidence": "Successfully created and removed __secmcp_probe_test__",
                    }
                )
        else:
            result.error = err

        result.findings = findings
        return result

    # ------------------------------------------------------------------
    # SSH
    # ------------------------------------------------------------------

    async def _probe_ssh(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe SSH: algorithm negotiation, auth methods, version."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="ssh", version="")
        findings: list[dict[str, Any]] = []

        if HAS_ASYNCSSH:
            try:
                conn = await asyncio.wait_for(
                    asyncssh.connect(
                        host,
                        port=port,
                        known_hosts=None,
                        username="secmcp_probe",
                        password="",
                        login_timeout=timeout,
                    ),
                    timeout=timeout + 1.0,
                )
                # Successful connect (unlikely without valid creds) — gather info and close
                server_version = conn.get_extra_info("server_version", "")
                result.version = server_version
                result.details["server_version"] = server_version
                conn.close()
                await conn.wait_closed()
            except asyncssh.PermissionDenied:
                pass
            except asyncssh.DisconnectError as exc:
                result.details["disconnect_reason"] = str(exc)
            except (OSError, TimeoutError) as exc:
                result.error = str(exc)
                return result

            # Second connection attempt to enumerate algorithms
            try:
                raw_conn: Any = await asyncio.wait_for(
                    asyncssh.create_connection(
                        None,  # type: ignore[arg-type]
                        host,
                        port=port,
                        known_hosts=None,
                        login_timeout=timeout,
                    ),
                    timeout=timeout + 1.0,
                )
                _, ssh_conn = raw_conn
                alg_info = {
                    "kex": list(getattr(ssh_conn, "_kex_algs", [])),
                    "ciphers": list(getattr(ssh_conn, "_enc_algs", [])),
                    "macs": list(getattr(ssh_conn, "_mac_algs", [])),
                    "server_host_key": list(getattr(ssh_conn, "_server_host_key_algs", [])),
                }
                result.details["algorithms"] = alg_info

                # Flag weak algorithms
                weak_kex = _WEAK_KEX & set(alg_info.get("kex", []))
                weak_ciphers = _WEAK_CIPHERS & set(alg_info.get("ciphers", []))
                weak_macs = _WEAK_MACS & set(alg_info.get("macs", []))
                all_weak = list(weak_kex | weak_ciphers | weak_macs)
                if all_weak:
                    findings.append(
                        {
                            "type": "weak_algorithms",
                            "severity": "medium",
                            "detail": f"SSH server supports weak algorithms: {', '.join(sorted(all_weak))}",
                            "evidence": {
                                "kex": sorted(weak_kex),
                                "ciphers": sorted(weak_ciphers),
                                "macs": sorted(weak_macs),
                            },
                        }
                    )

                ssh_conn.close()
                await ssh_conn.wait_closed()
            except Exception as exc:
                logger.debug("SSH algorithm enumeration failed for %s:%d: %s", host, port, exc)
        else:
            # Fallback: raw banner grab
            try:
                data = await self._raw_recv(host, port, timeout)
                banner = data.decode("utf-8", errors="ignore").strip()
                result.version = banner
                result.details["server_version"] = banner
                # Parse OS hint from banner (e.g. "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
                if "ubuntu" in banner.lower():
                    result.details["os_hint"] = "Ubuntu Linux"
                elif "debian" in banner.lower():
                    result.details["os_hint"] = "Debian Linux"
                elif "redhat" in banner.lower() or "rhel" in banner.lower():
                    result.details["os_hint"] = "Red Hat Linux"

                # Flag password auth — can't determine without asyncssh, note it
                result.details["note"] = "Install asyncssh for full algorithm/auth enumeration"
            except (OSError, TimeoutError) as exc:
                result.error = str(exc)

        result.findings = findings
        return result

    # ------------------------------------------------------------------
    # SMB
    # ------------------------------------------------------------------

    async def _probe_smb(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe SMB: null session, share enumeration, signing, SMBv1."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="smb", version="")
        findings: list[dict[str, Any]] = []

        if HAS_SMBPROTOCOL:
            await self._probe_smb_native(host, port, timeout, result, findings)
        else:
            await self._probe_smb_raw(host, port, timeout, result, findings)

        result.findings = findings
        return result

    async def _probe_smb_native(
        self,
        host: str,
        port: int,
        timeout: float,
        result: ServiceProbeResult,
        findings: list[dict[str, Any]],
    ) -> None:
        """SMB probing via smbprotocol library."""

        def _smb_work() -> dict[str, Any]:
            info: dict[str, Any] = {}
            try:
                conn = SMBConnection(uuid=None, server_name=host, port=port, require_signing=False)
                conn.connect(timeout=timeout)
                info["connected"] = True
                info["dialect"] = str(getattr(conn, "dialect", "unknown"))
                info["signing_required"] = bool(getattr(conn, "require_signing", True))

                # Null session
                try:
                    session = SMBSession(conn, username="", password="")
                    session.connect()
                    info["null_session"] = True

                    # Share enumeration via IPC$
                    try:
                        tree = TreeConnect(session, rf"\\{host}\IPC$")
                        tree.connect()
                        info["ipc_accessible"] = True
                        tree.disconnect()
                    except Exception:
                        info["ipc_accessible"] = False

                    session.disconnect()
                except Exception:
                    info["null_session"] = False

                # Guest session
                try:
                    session = SMBSession(conn, username="Guest", password="")
                    session.connect()
                    info["guest_access"] = True
                    session.disconnect()
                except Exception:
                    info["guest_access"] = False

                conn.disconnect()
            except Exception as exc:
                info["error"] = str(exc)
            return info

        info = await asyncio.to_thread(_smb_work)
        result.details.update(info)

        if info.get("null_session"):
            findings.append(
                {
                    "type": "null_session_allowed",
                    "severity": "high",
                    "detail": "SMB null session authentication succeeded",
                    "evidence": f"Dialect: {info.get('dialect', 'unknown')}",
                }
            )
        if info.get("guest_access"):
            findings.append(
                {
                    "type": "guest_access",
                    "severity": "medium",
                    "detail": "SMB guest account access permitted",
                }
            )
        if not info.get("signing_required", True):
            findings.append(
                {
                    "type": "smb_signing_disabled",
                    "severity": "medium",
                    "detail": "SMB message signing is not required (relay attacks possible)",
                }
            )

    async def _probe_smb_raw(
        self,
        host: str,
        port: int,
        timeout: float,
        result: ServiceProbeResult,
        findings: list[dict[str, Any]],
    ) -> None:
        """SMB probing via raw socket — negotiate protocol to extract version and signing info."""
        # SMB1 Negotiate Protocol Request
        # NetBIOS header (4 bytes) + SMB header (32 bytes) + negotiate payload
        smb1_negotiate = (
            b"\x00\x00\x00\x55"  # NetBIOS: session message, length 85
            b"\xff\x53\x4d\x42"  # SMB magic: \xffSMB
            b"\x72"  # Command: Negotiate (0x72)
            b"\x00\x00\x00\x00"  # Status: SUCCESS
            b"\x18"  # Flags: case-sensitive paths
            b"\x53\xc0"  # Flags2: unicode, NT status, extended security
            b"\x00\x00"  # PID High
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
            b"\x00\x00"  # Reserved
            b"\x00\x00"  # Tree ID
            b"\xff\xfe"  # Process ID
            b"\x00\x00"  # User ID
            b"\x00\x00"  # Multiplex ID
            # Negotiate payload: dialect strings
            b"\x00"  # Word count: 0
            b"\x32\x00"  # Byte count: 50
            b"\x02NT LM 0.12\x00"  # SMB1 dialect
            b"\x02SMB 2.002\x00"  # SMB2.0 dialect
            b"\x02SMB 2.???\x00"  # SMB2 wildcard
        )

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                writer.write(smb1_negotiate)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            finally:
                writer.close()
                await writer.wait_closed()

            if len(data) < 40:
                result.error = "SMB response too short"
                return

            result.details["raw_response_len"] = len(data)

            # Check for SMB1 vs SMB2 response
            if data[4:8] == b"\xffSMB":
                # SMB1 response
                result.details["smb1_supported"] = True
                findings.append(
                    {
                        "type": "smb1_enabled",
                        "severity": "medium",
                        "detail": "Server supports SMBv1 (deprecated, EternalBlue-vulnerable protocol)",
                    }
                )
                # Security mode byte at offset 39 in SMB1 negotiate response
                if len(data) > 39:
                    sec_mode = data[39]
                    signing_enabled = bool(sec_mode & 0x02)
                    signing_required = bool(sec_mode & 0x04)
                    result.details["signing_enabled"] = signing_enabled
                    result.details["signing_required"] = signing_required
                    if not signing_required:
                        findings.append(
                            {
                                "type": "smb_signing_disabled",
                                "severity": "medium",
                                "detail": "SMB message signing is not required",
                            }
                        )
            elif data[4:8] == b"\xfeSMB":
                # SMB2 response
                result.details["smb1_supported"] = False
                # SMB2 negotiate response: security mode at offset 70
                if len(data) > 70:
                    sec_mode = struct.unpack_from("<H", data, 70)[0]
                    signing_required = bool(sec_mode & 0x02)
                    result.details["signing_required"] = signing_required
                    if not signing_required:
                        findings.append(
                            {
                                "type": "smb_signing_disabled",
                                "severity": "medium",
                                "detail": "SMB message signing is not required (relay attacks possible)",
                            }
                        )
                # Dialect version at offset 72
                if len(data) > 73:
                    dialect = struct.unpack_from("<H", data, 72)[0]
                    dialect_str = f"{dialect >> 8}.{dialect & 0xFF:02d}"
                    result.version = f"SMB {dialect_str}"
                    result.details["dialect"] = dialect_str

            result.details["note"] = "Install smbprotocol for null-session and share enumeration"

        except (OSError, TimeoutError) as exc:
            result.error = str(exc)

    # ------------------------------------------------------------------
    # SMTP
    # ------------------------------------------------------------------

    async def _probe_smtp(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe SMTP: banner, EHLO extensions, open relay, VRFY, EXPN."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="smtp", version="")
        findings: list[dict[str, Any]] = []

        def _smtp_work() -> dict[str, Any]:
            info: dict[str, Any] = {}
            smtp: smtplib.SMTP | None = None
            try:
                smtp = smtplib.SMTP(timeout=timeout)
                code, msg = smtp.connect(host, port)
                banner = msg.decode("utf-8", errors="ignore")
                info["banner"] = banner
                info["connect_code"] = code

                # EHLO to enumerate extensions
                ehlo_code, ehlo_msg = smtp.ehlo("secmcp-probe.local")
                if ehlo_code == 250:
                    extensions = ehlo_msg.decode("utf-8", errors="ignore").splitlines()
                    info["extensions"] = extensions
                    info["ehlo_supported"] = True

                    # STARTTLS availability
                    info["starttls"] = any("STARTTLS" in ext.upper() for ext in extensions)
                else:
                    info["ehlo_supported"] = False

                # Open relay test: try to relay a message to an external domain
                try:
                    smtp.mail("test@secmcp-probe.local")
                    relay_code, relay_msg = smtp.rcpt("test@external-nonexistent-domain.com")
                    info["relay_test_code"] = relay_code
                    info["relay_test_msg"] = relay_msg.decode("utf-8", errors="ignore")
                    if relay_code == 250:
                        info["open_relay"] = True
                    else:
                        info["open_relay"] = False
                    smtp.rset()
                except smtplib.SMTPRecipientsRefused:
                    info["open_relay"] = False
                except smtplib.SMTPSenderRefused:
                    info["open_relay"] = False
                except smtplib.SMTPServerDisconnected:
                    info["open_relay"] = False
                    return info

                # VRFY test
                try:
                    vrfy_code, vrfy_msg = smtp.vrfy("root")
                    info["vrfy_code"] = vrfy_code
                    info["vrfy_response"] = vrfy_msg.decode("utf-8", errors="ignore")
                    # 250 or 252 = VRFY works
                    info["vrfy_enabled"] = vrfy_code in (250, 252)
                except smtplib.SMTPServerDisconnected:
                    info["vrfy_enabled"] = False
                    return info

                # EXPN test
                try:
                    expn_code, _ = smtp.docmd("EXPN", "postmaster")
                    info["expn_code"] = expn_code
                    info["expn_enabled"] = expn_code in (250, 252)
                except smtplib.SMTPServerDisconnected:
                    info["expn_enabled"] = False

            except (OSError, smtplib.SMTPException) as exc:
                info["error"] = str(exc)
            finally:
                if smtp is not None:
                    with contextlib.suppress(Exception):
                        smtp.quit()
            return info

        info = await asyncio.to_thread(_smtp_work)
        result.details.update(info)
        result.version = info.get("banner", "")

        if info.get("open_relay"):
            findings.append(
                {
                    "type": "open_relay",
                    "severity": "critical",
                    "detail": "SMTP open relay detected — server accepts mail for arbitrary external domains",
                    "evidence": f"RCPT TO response code: {info.get('relay_test_code')}",
                }
            )
        if info.get("vrfy_enabled"):
            findings.append(
                {
                    "type": "vrfy_enabled",
                    "severity": "medium",
                    "detail": "SMTP VRFY command enabled — allows user enumeration",
                    "evidence": f"VRFY root response: {info.get('vrfy_response', '')}",
                }
            )
        if info.get("expn_enabled"):
            findings.append(
                {
                    "type": "expn_enabled",
                    "severity": "medium",
                    "detail": "SMTP EXPN command enabled — allows mailing list expansion/user enumeration",
                }
            )

        result.findings = findings
        return result

    # ------------------------------------------------------------------
    # POP3
    # ------------------------------------------------------------------

    async def _probe_pop3(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe POP3: banner grab and version extraction."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="pop3", version="")
        try:
            data = await self._raw_recv(host, port, timeout)
            banner = data.decode("utf-8", errors="ignore").strip()
            result.version = banner
            result.details["banner"] = banner
        except (OSError, TimeoutError) as exc:
            result.error = str(exc)
        return result

    # ------------------------------------------------------------------
    # IMAP
    # ------------------------------------------------------------------

    async def _probe_imap(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe IMAP: banner grab and version extraction."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="imap", version="")
        try:
            data = await self._raw_recv(host, port, timeout)
            banner = data.decode("utf-8", errors="ignore").strip()
            result.version = banner
            result.details["banner"] = banner
        except (OSError, TimeoutError) as exc:
            result.error = str(exc)
        return result

    # ------------------------------------------------------------------
    # MySQL
    # ------------------------------------------------------------------

    async def _probe_mysql(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe MySQL: greeting packet parse, version, auth check."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="mysql", version="")
        findings: list[dict[str, Any]] = []

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                # MySQL sends a greeting packet immediately after connect
                header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
                pkt_len = header[0] | (header[1] << 8) | (header[2] << 16)
                pkt_num = header[3]  # noqa: F841 — sequence number, useful for debugging
                payload = await asyncio.wait_for(reader.readexactly(pkt_len), timeout=timeout)

                if len(payload) < 1:
                    result.error = "Empty MySQL greeting"
                    return result

                # Error packet: first byte 0xff
                if payload[0] == 0xFF:
                    err_code = struct.unpack_from("<H", payload, 1)[0] if len(payload) > 2 else 0
                    err_msg = payload[3:].decode("utf-8", errors="ignore") if len(payload) > 3 else ""
                    result.error = f"MySQL error {err_code}: {err_msg}"
                    result.details["error_code"] = err_code
                    return result

                # Parse greeting packet
                proto_version = payload[0]
                result.details["protocol_version"] = proto_version

                # Server version: null-terminated string starting at byte 1
                null_pos = payload.index(b"\x00", 1)
                server_version = payload[1:null_pos].decode("utf-8", errors="ignore")
                result.version = server_version
                result.details["server_version"] = server_version

                # Thread ID (4 bytes after null terminator)
                offset = null_pos + 1
                if len(payload) > offset + 4:
                    thread_id = struct.unpack_from("<I", payload, offset)[0]
                    result.details["thread_id"] = thread_id
                    offset += 4

                # Salt (first 8 bytes)
                if len(payload) > offset + 8:
                    offset += 8  # skip salt part 1

                # Filler byte
                if len(payload) > offset:
                    offset += 1

                # Capability flags (lower 2 bytes)
                if len(payload) > offset + 2:
                    cap_lower = struct.unpack_from("<H", payload, offset)[0]
                    result.details["capabilities_lower"] = cap_lower
                    offset += 2

                # Character set
                if len(payload) > offset:
                    charset = payload[offset]
                    result.details["charset"] = charset
                    offset += 1

                # Status flags
                if len(payload) > offset + 2:
                    status = struct.unpack_from("<H", payload, offset)[0]
                    result.details["status_flags"] = status
                    offset += 2

                # Capability flags (upper 2 bytes)
                if len(payload) > offset + 2:
                    cap_upper = struct.unpack_from("<H", payload, offset)[0]
                    result.details["capabilities_upper"] = cap_upper
                    offset += 2

                # Auth plugin data length or 0
                if len(payload) > offset:
                    auth_plugin_data_len = payload[offset]
                    result.details["auth_plugin_data_len"] = auth_plugin_data_len
                    offset += 1

                # Skip 10 reserved bytes
                offset += 10

                # Auth plugin name at the end
                if offset < len(payload):
                    try:
                        plugin_null = payload.index(b"\x00", offset)
                        auth_plugin = payload[offset:plugin_null].decode("utf-8", errors="ignore")
                    except ValueError:
                        auth_plugin = payload[offset:].decode("utf-8", errors="ignore")
                    result.details["auth_plugin"] = auth_plugin

            finally:
                writer.close()
                await writer.wait_closed()

            # Check for anonymous access by attempting a login with empty credentials
            anon_result = await self._mysql_try_anonymous(host, port, timeout)
            if anon_result:
                result.details["anonymous_access"] = True
                findings.append(
                    {
                        "type": "anonymous_access",
                        "severity": "critical",
                        "detail": f"MySQL allows unauthenticated access (version: {server_version})",
                        "evidence": "Login with empty username/password succeeded",
                    }
                )
            else:
                result.details["anonymous_access"] = False

        except (OSError, TimeoutError, struct.error, ValueError) as exc:
            result.error = str(exc)

        result.findings = findings
        return result

    async def _mysql_try_anonymous(self, host: str, port: int, timeout: float) -> bool:
        """Attempt MySQL login with empty credentials. Returns True if successful."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                # Read greeting
                header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
                pkt_len = header[0] | (header[1] << 8) | (header[2] << 16)
                await asyncio.wait_for(reader.readexactly(pkt_len), timeout=timeout)

                # Send a minimal handshake response with empty username/password
                # Client capabilities: basic set
                auth_packet = bytearray()
                auth_packet += struct.pack("<I", 0x0000A685)  # capabilities
                auth_packet += struct.pack("<I", 65535)  # max packet size
                auth_packet += struct.pack("B", 33)  # charset utf8
                auth_packet += b"\x00" * 23  # reserved
                auth_packet += b"\x00"  # empty username
                auth_packet += b"\x00"  # empty auth response

                # Wrap in MySQL packet header
                pkt = struct.pack("<I", len(auth_packet))[:3] + b"\x01" + auth_packet
                writer.write(pkt)
                await writer.drain()

                # Read response
                resp_header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
                resp_len = resp_header[0] | (resp_header[1] << 8) | (resp_header[2] << 16)
                resp_payload = await asyncio.wait_for(reader.readexactly(resp_len), timeout=timeout)

                # 0x00 = OK packet = login success
                return len(resp_payload) > 0 and resp_payload[0] == 0x00
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, TimeoutError, struct.error):
            return False

    # ------------------------------------------------------------------
    # PostgreSQL
    # ------------------------------------------------------------------

    async def _probe_postgresql(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe PostgreSQL: startup message, auth method check."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="postgresql", version="")
        findings: list[dict[str, Any]] = []

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                # Send StartupMessage: protocol 3.0, user=secmcp_probe, database=postgres
                user = b"user\x00secmcp_probe\x00"
                database = b"database\x00postgres\x00"
                params = user + database + b"\x00"  # trailing null terminates params
                # Length = 4 (length field) + 4 (protocol version) + params
                msg_len = 4 + 4 + len(params)
                startup = struct.pack(">I", msg_len) + struct.pack(">I", 0x00030000) + params

                writer.write(startup)
                await writer.drain()

                # Read response
                resp_type_raw = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
                resp_type = chr(resp_type_raw[0])
                resp_len_raw = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
                resp_len = struct.unpack(">I", resp_len_raw)[0]
                resp_body = b""
                if resp_len > 4:
                    resp_body = await asyncio.wait_for(reader.readexactly(resp_len - 4), timeout=timeout)

                result.details["auth_type_char"] = resp_type

                if resp_type == "R":
                    # Authentication response
                    if len(resp_body) >= 4:
                        auth_code = struct.unpack(">I", resp_body[:4])[0]
                        auth_names = {
                            0: "trust",  # AuthenticationOk — no password needed
                            2: "kerberos",
                            3: "cleartext",  # AuthenticationCleartextPassword
                            5: "md5",  # AuthenticationMD5Password
                            10: "sasl",  # AuthenticationSASL (SCRAM-SHA-256)
                        }
                        auth_method = auth_names.get(auth_code, f"unknown({auth_code})")
                        result.details["auth_method"] = auth_method
                        result.details["auth_code"] = auth_code

                        if auth_code == 0:
                            # Trust auth — no password required at all
                            result.details["no_password"] = True
                            findings.append(
                                {
                                    "type": "no_password_auth",
                                    "severity": "critical",
                                    "detail": "PostgreSQL trust authentication — no password required",
                                    "evidence": f"Auth response code: {auth_code} (trust)",
                                }
                            )
                        elif auth_code == 3:
                            result.details["cleartext_password"] = True
                            findings.append(
                                {
                                    "type": "cleartext_auth",
                                    "severity": "medium",
                                    "detail": "PostgreSQL uses cleartext password authentication",
                                }
                            )
                elif resp_type == "E":
                    # Error response — parse message fields
                    error_msg = resp_body.decode("utf-8", errors="ignore")
                    result.details["error_message"] = error_msg
                    # Extract version from error if present (some PG versions include it)
                    if "PostgreSQL" in error_msg:
                        result.version = error_msg

                # Try to read ParameterStatus messages for version
                try:
                    while True:
                        msg_type_raw = await asyncio.wait_for(reader.readexactly(1), timeout=1.0)
                        msg_type = chr(msg_type_raw[0])
                        if msg_type == "S":
                            # ParameterStatus
                            plen_raw = await asyncio.wait_for(reader.readexactly(4), timeout=1.0)
                            plen = struct.unpack(">I", plen_raw)[0]
                            pbody = await asyncio.wait_for(reader.readexactly(plen - 4), timeout=1.0)
                            parts = pbody.rstrip(b"\x00").split(b"\x00", 1)
                            if len(parts) == 2:
                                key = parts[0].decode("utf-8", errors="ignore")
                                val = parts[1].decode("utf-8", errors="ignore")
                                if key == "server_version":
                                    result.version = val
                                    result.details["server_version"] = val
                                result.details.setdefault("parameters", {})[key] = val
                        elif msg_type == "K":
                            # BackendKeyData — skip
                            plen_raw = await asyncio.wait_for(reader.readexactly(4), timeout=1.0)
                            plen = struct.unpack(">I", plen_raw)[0]
                            await asyncio.wait_for(reader.readexactly(plen - 4), timeout=1.0)
                        elif msg_type == "Z":
                            # ReadyForQuery — done
                            plen_raw = await asyncio.wait_for(reader.readexactly(4), timeout=1.0)
                            plen = struct.unpack(">I", plen_raw)[0]
                            await asyncio.wait_for(reader.readexactly(plen - 4), timeout=1.0)
                            break
                        else:
                            break
                except (TimeoutError, OSError):
                    pass  # no more messages, that's fine

            finally:
                writer.close()
                await writer.wait_closed()

        except (OSError, TimeoutError, struct.error) as exc:
            result.error = str(exc)

        result.findings = findings
        return result

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------

    async def _probe_redis(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe Redis: PING, INFO, CONFIG availability."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="redis", version="")
        findings: list[dict[str, Any]] = []

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                # PING
                writer.write(b"PING\r\n")
                await writer.drain()
                ping_resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
                ping_str = ping_resp.decode("utf-8", errors="ignore").strip()

                if ping_str == "+PONG":
                    result.details["authenticated"] = False
                    findings.append(
                        {
                            "type": "no_auth_required",
                            "severity": "critical",
                            "detail": "Redis accepts commands without authentication",
                            "evidence": "PING returned +PONG without AUTH",
                        }
                    )

                    # INFO server
                    writer.write(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
                    await writer.drain()
                    info_data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    info_str = info_data.decode("utf-8", errors="ignore")
                    result.details["info_raw"] = info_str[:2000]  # cap stored data

                    for line in info_str.splitlines():
                        if line.startswith("redis_version:"):
                            result.version = line.split(":", 1)[1].strip()
                            result.details["redis_version"] = result.version
                        elif line.startswith("os:"):
                            result.details["os"] = line.split(":", 1)[1].strip()
                        elif line.startswith("tcp_port:"):
                            result.details["tcp_port"] = line.split(":", 1)[1].strip()
                        elif line.startswith("redis_mode:"):
                            result.details["redis_mode"] = line.split(":", 1)[1].strip()

                    # CONFIG GET dir — check if CONFIG is available (RCE vector)
                    writer.write(b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n")
                    await writer.drain()
                    config_resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    config_str = config_resp.decode("utf-8", errors="ignore")

                    if "-ERR" not in config_str and "-DENIED" not in config_str.upper():
                        result.details["config_command"] = True
                        findings.append(
                            {
                                "type": "config_command_available",
                                "severity": "critical",
                                "detail": "Redis CONFIG command available — enables file-write RCE via CONFIG SET dir/dbfilename",
                                "evidence": f"CONFIG GET dir response: {config_str[:200]}",
                            }
                        )
                    else:
                        result.details["config_command"] = False

                elif ping_str.startswith("-NOAUTH") or ping_str.startswith("-ERR") and "AUTH" in ping_str.upper():
                    result.details["authenticated"] = True
                    result.details["auth_required"] = True
                else:
                    result.details["ping_response"] = ping_str

            finally:
                writer.close()
                await writer.wait_closed()

        except (OSError, TimeoutError) as exc:
            result.error = str(exc)

        result.findings = findings
        return result

    # ------------------------------------------------------------------
    # MongoDB
    # ------------------------------------------------------------------

    async def _probe_mongodb(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe MongoDB: isMaster command, auth status, database listing."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="mongodb", version="")
        findings: list[dict[str, Any]] = []

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                # Build isMaster command using OP_MSG (MongoDB 3.6+ wire protocol)
                # BSON document: {"isMaster": 1, "$db": "admin"}
                bson_doc = self._build_bson({"isMaster": 1, "$db": "admin"})
                # OP_MSG: flagBits(4) + kind=0(1) + bson
                op_msg_body = struct.pack("<I", 0) + b"\x00" + bson_doc
                # MsgHeader: messageLength(4) + requestID(4) + responseTo(4) + opCode(4)
                msg_len = 16 + len(op_msg_body)
                header = struct.pack("<iiii", msg_len, 1, 0, 2013)  # opCode 2013 = OP_MSG
                writer.write(header + op_msg_body)
                await writer.drain()

                # Read response header
                resp_header = await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
                resp_msg_len = struct.unpack("<i", resp_header[:4])[0]
                resp_body = await asyncio.wait_for(reader.readexactly(resp_msg_len - 16), timeout=timeout)

                # Parse OP_MSG response: skip flagBits(4) + kind(1), then BSON
                if len(resp_body) > 5:
                    bson_data = resp_body[5:]
                    parsed = self._parse_bson_simple(bson_data)
                    result.details["isMaster"] = parsed

                    if "maxWireVersion" in parsed:
                        result.details["max_wire_version"] = parsed["maxWireVersion"]
                    if "version" in parsed:
                        result.version = str(parsed["version"])
                        result.details["server_version"] = result.version
                    if parsed.get("ismaster") or parsed.get("isWritablePrimary"):
                        result.details["is_primary"] = True

                    # If isMaster succeeded, try listDatabases
                    await self._mongodb_list_databases(reader, writer, timeout, result, findings)

            finally:
                writer.close()
                await writer.wait_closed()

        except (OSError, TimeoutError, struct.error) as exc:
            result.error = str(exc)

        result.findings = findings
        return result

    async def _mongodb_list_databases(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float,
        result: ServiceProbeResult,
        findings: list[dict[str, Any]],
    ) -> None:
        """Try to list MongoDB databases (indicates no auth)."""
        try:
            bson_doc = self._build_bson({"listDatabases": 1, "$db": "admin"})
            op_msg_body = struct.pack("<I", 0) + b"\x00" + bson_doc
            msg_len = 16 + len(op_msg_body)
            header = struct.pack("<iiii", msg_len, 2, 0, 2013)
            writer.write(header + op_msg_body)
            await writer.drain()

            resp_header = await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
            resp_msg_len = struct.unpack("<i", resp_header[:4])[0]
            resp_body = await asyncio.wait_for(reader.readexactly(resp_msg_len - 16), timeout=timeout)

            if len(resp_body) > 5:
                bson_data = resp_body[5:]
                parsed = self._parse_bson_simple(bson_data)

                if parsed.get("ok") == 1.0 or parsed.get("ok") == 1:
                    result.details["no_auth"] = True
                    db_names = []
                    if "databases" in parsed and isinstance(parsed["databases"], list):
                        db_names = [d.get("name", "") for d in parsed["databases"] if isinstance(d, dict)]
                    result.details["databases"] = db_names
                    findings.append(
                        {
                            "type": "no_auth_required",
                            "severity": "critical",
                            "detail": "MongoDB allows unauthenticated access — listDatabases succeeded",
                            "evidence": f"Databases: {', '.join(db_names[:10])}",
                        }
                    )
                else:
                    result.details["no_auth"] = False
        except (OSError, TimeoutError, struct.error) as exc:
            logger.debug("MongoDB listDatabases failed: %s", exc)
            # Auth is likely required — not a finding
            result.details["no_auth"] = False

    @staticmethod
    def _build_bson(doc: dict[str, Any]) -> bytes:
        """Build a minimal BSON document from a flat dict (strings, ints, floats).

        Supports: string (type 0x02), int32 (type 0x10), float64 (type 0x01).
        This is intentionally minimal — only what the probe commands need.
        """
        body = bytearray()
        for key, val in doc.items():
            key_bytes = key.encode("utf-8") + b"\x00"
            if isinstance(val, str):
                encoded = val.encode("utf-8") + b"\x00"
                body += b"\x02" + key_bytes + struct.pack("<i", len(encoded)) + encoded
            elif isinstance(val, float):
                body += b"\x01" + key_bytes + struct.pack("<d", val)
            elif isinstance(val, int):
                body += b"\x10" + key_bytes + struct.pack("<i", val)
        body += b"\x00"  # document terminator
        return struct.pack("<i", len(body) + 4) + bytes(body)

    @staticmethod
    def _parse_bson_simple(data: bytes) -> dict[str, Any]:
        """Parse a flat BSON document. Handles types: string, int32, int64, double, bool, null, array.

        Nested documents and arrays are returned as raw dicts/lists where feasible.
        Unknown types are skipped.
        """
        result: dict[str, Any] = {}
        if len(data) < 5:
            return result
        doc_len = struct.unpack_from("<i", data, 0)[0]
        pos = 4
        end = min(doc_len, len(data))

        while pos < end:
            type_byte = data[pos]
            pos += 1
            if type_byte == 0x00:
                break

            # Element name (cstring)
            null_idx = data.index(b"\x00", pos)
            name = data[pos:null_idx].decode("utf-8", errors="ignore")
            pos = null_idx + 1

            if type_byte == 0x01:  # double
                result[name] = struct.unpack_from("<d", data, pos)[0]
                pos += 8
            elif type_byte == 0x02:  # string
                slen = struct.unpack_from("<i", data, pos)[0]
                pos += 4
                result[name] = data[pos : pos + slen - 1].decode("utf-8", errors="ignore")
                pos += slen
            elif type_byte == 0x03:  # embedded document
                dlen = struct.unpack_from("<i", data, pos)[0]
                sub = ServiceProber._parse_bson_simple(data[pos : pos + dlen])
                result[name] = sub
                pos += dlen
            elif type_byte == 0x04:  # array (same format as document, keys are "0","1",...)
                alen = struct.unpack_from("<i", data, pos)[0]
                sub = ServiceProber._parse_bson_simple(data[pos : pos + alen])
                result[name] = list(sub.values())
                pos += alen
            elif type_byte == 0x08:  # bool
                result[name] = data[pos] != 0
                pos += 1
            elif type_byte == 0x0A:  # null
                result[name] = None
            elif type_byte == 0x10:  # int32
                result[name] = struct.unpack_from("<i", data, pos)[0]
                pos += 4
            elif type_byte == 0x12:  # int64
                result[name] = struct.unpack_from("<q", data, pos)[0]
                pos += 8
            else:
                # Unknown type — we cannot safely determine element size, so stop
                break

        return result

    # ------------------------------------------------------------------
    # Memcached
    # ------------------------------------------------------------------

    async def _probe_memcached(self, host: str, port: int, timeout: float) -> ServiceProbeResult:
        """Probe Memcached: stats command for version and exposure info."""
        result = ServiceProbeResult(port=port, protocol="tcp", service="memcached", version="")
        findings: list[dict[str, Any]] = []

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            try:
                writer.write(b"stats\r\n")
                await writer.drain()

                # Read stats response until END\r\n
                buf = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                    if not chunk:
                        break
                    buf += chunk
                    if b"END\r\n" in buf or b"ERROR" in buf:
                        break

                stats_str = buf.decode("utf-8", errors="ignore")

                if "ERROR" in stats_str:
                    result.details["auth_required"] = True
                    return result

                # No auth required — the stats command worked
                findings.append(
                    {
                        "type": "no_auth_required",
                        "severity": "high",
                        "detail": "Memcached accepts commands without authentication",
                        "evidence": "stats command returned data",
                    }
                )

                # Parse STAT lines
                stats: dict[str, str] = {}
                for line in stats_str.splitlines():
                    if line.startswith("STAT "):
                        parts = line.split(None, 2)
                        if len(parts) == 3:
                            stats[parts[1]] = parts[2]

                result.details["stats"] = stats
                if "version" in stats:
                    result.version = stats["version"]
                    result.details["memcached_version"] = stats["version"]
                if "curr_connections" in stats:
                    result.details["connections"] = stats["curr_connections"]
                if "curr_items" in stats:
                    result.details["items"] = stats["curr_items"]
                if "total_connections" in stats:
                    result.details["total_connections"] = stats["total_connections"]

                # Sensitive data exposure risk if items are present
                items_count = int(stats.get("curr_items", "0"))
                if items_count > 0:
                    findings.append(
                        {
                            "type": "sensitive_data_exposure",
                            "severity": "medium",
                            "detail": f"Memcached holds {items_count} cached items — potential sensitive data exposure",
                        }
                    )

            finally:
                writer.close()
                await writer.wait_closed()

        except (OSError, TimeoutError) as exc:
            result.error = str(exc)

        result.findings = findings
        return result
