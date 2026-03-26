"""Out-of-Band (OOB) callback detection via interactsh.

Provides tools for blind vulnerability detection (blind SSRF, blind XSS,
blind SQLi, blind XXE) by:

1. Registering with a ProjectDiscovery interactsh server
2. Generating unique callback URLs (FQDNs) per test
3. Polling for DNS/HTTP/SMTP interactions triggered by the target

Protocol: RSA-2048 key exchange → AES-CFB encrypted interactions.
Server: ``oast.live`` (public, free) or self-hosted.

Usage in a scan:
    1. ``oob_setup`` → creates session, returns domain
    2. Inject ``{domain}`` into SSRF/XXE/XSS payloads
    3. ``oob_poll`` → check if target made a callback
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger("security_mcp.tools.oob_tool")

# Default public interactsh servers (ProjectDiscovery)
DEFAULT_SERVER = "oast.live"
FALLBACK_SERVERS = ["oast.fun", "oast.me", "oast.site"]

# Correlation ID lengths (match Go client defaults)
CID_LENGTH = 20
CID_NONCE_LENGTH = 13


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_string(length: int) -> str:
    """Generate a random lowercase alphanumeric string."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class OOBSession:
    """Active interactsh OOB session."""

    server: str
    correlation_id: str
    secret_key: str
    private_key_pem: str  # PEM-encoded RSA private key
    domain: str  # Base domain for payloads (cid + nonce + server)
    created_at: float = field(default_factory=time.time)
    interactions_found: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "correlation_id": self.correlation_id,
            "domain": self.domain,
            "created_at": self.created_at,
            "interactions_found": self.interactions_found,
        }


@dataclass
class Interaction:
    """A single OOB interaction (DNS/HTTP/SMTP callback)."""

    protocol: str  # dns, http, smtp
    unique_id: str
    full_id: str
    remote_address: str
    raw_request: str
    timestamp: str
    query_type: str = ""  # For DNS: A, AAAA, CNAME, etc.

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol": self.protocol,
            "unique_id": self.unique_id,
            "full_id": self.full_id,
            "remote_address": self.remote_address,
            "raw_request": self.raw_request[:500],  # Cap for readability
            "timestamp": self.timestamp,
        }
        if self.query_type:
            d["query_type"] = self.query_type
        return d


@dataclass
class OOBPollResult:
    """Result from polling for OOB interactions."""

    session_domain: str
    interactions: list[Interaction] = field(default_factory=list)
    poll_count: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_domain": self.session_domain,
            "interaction_count": len(self.interactions),
            "interactions": [i.to_dict() for i in self.interactions],
            "poll_count": self.poll_count,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Core OOB client
# ---------------------------------------------------------------------------


class OOBClient:
    """Interactsh protocol client for OOB detection."""

    def __init__(self, server: str = DEFAULT_SERVER, timeout: float = 10.0) -> None:
        self.server = server
        self.timeout = timeout

    async def register(self) -> OOBSession:
        """Register with the interactsh server.

        Generates an RSA-2048 key pair, a correlation ID, and a secret key,
        then POSTs the registration to the server.

        Returns:
            ``OOBSession`` with the registered domain.

        Raises:
            RuntimeError: If registration fails on all servers.
        """
        # Generate RSA key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Generate correlation ID and secret
        correlation_id = _random_string(CID_LENGTH)
        secret_key = uuid.uuid4().hex

        # Build registration payload
        payload = {
            "public-key": base64.b64encode(public_pem).decode(),
            "secret-key": secret_key,
            "correlation-id": correlation_id,
        }

        # Try primary server, then fallbacks
        servers = [self.server] + [s for s in FALLBACK_SERVERS if s != self.server]
        last_error = ""

        for server in servers:
            try:
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                    resp = await client.post(
                        f"https://{server}/register",
                        json=payload,
                    )
                    if resp.status_code == 200:
                        nonce = _random_string(CID_NONCE_LENGTH)
                        domain = f"{correlation_id}{nonce}.{server}"
                        logger.info("OOB session registered: %s", domain)
                        return OOBSession(
                            server=server,
                            correlation_id=correlation_id,
                            secret_key=secret_key,
                            private_key_pem=private_pem,
                            domain=domain,
                        )
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    logger.warning("Registration failed on %s: %s", server, last_error)
            except httpx.HTTPError as e:
                last_error = str(e)
                logger.warning("Connection failed to %s: %s", server, last_error)

        raise RuntimeError(f"OOB registration failed on all servers. Last error: {last_error}")

    async def poll(self, session: OOBSession) -> list[Interaction]:
        """Poll for interactions on a registered session.

        Args:
            session: Active OOB session from ``register()``.

        Returns:
            List of ``Interaction`` objects (may be empty if no callbacks yet).
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(
                    f"https://{session.server}/poll",
                    params={
                        "id": session.correlation_id,
                        "secret": session.secret_key,
                    },
                )
                if resp.status_code != 200:
                    logger.warning("Poll failed: HTTP %d", resp.status_code)
                    return []

                data = resp.json()
                aes_key_enc = data.get("aes_key", "")
                raw_data = data.get("data", [])

                if not raw_data:
                    return []

                # Decrypt AES key with RSA private key
                private_key = serialization.load_pem_private_key(
                    session.private_key_pem.encode(),
                    password=None,
                )
                aes_key = private_key.decrypt(  # type: ignore[union-attr]
                    base64.b64decode(aes_key_enc),
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # Decrypt each interaction
                interactions: list[Interaction] = []
                for encrypted_item in raw_data:
                    interaction = self._decrypt_interaction(aes_key, encrypted_item)
                    if interaction:
                        interactions.append(interaction)
                        session.interactions_found += 1

                return interactions

        except httpx.HTTPError as e:
            logger.warning("Poll connection error: %s", e)
            return []
        except Exception as e:
            logger.warning("Poll decryption error: %s", e)
            return []

    def generate_payload_url(self, session: OOBSession, suffix: str = "") -> str:
        """Generate a unique subdomain for use in a payload.

        Each call returns a different subdomain so interactions can be
        correlated back to specific test cases.

        Args:
            session: Active OOB session.
            suffix: Optional suffix to append before the nonce.

        Returns:
            FQDN like ``{cid}{suffix}{nonce}.{server}``.
        """
        nonce_len = max(1, CID_NONCE_LENGTH - len(suffix))
        nonce = _random_string(nonce_len)
        return f"{session.correlation_id}{suffix}{nonce}.{session.server}"

    @staticmethod
    def _decrypt_interaction(aes_key: bytes, encrypted_b64: str) -> Interaction | None:
        """Decrypt a single base64-encoded AES-CFB encrypted interaction."""
        try:
            raw = base64.b64decode(encrypted_b64)
            block_size = 16  # AES block size in bytes
            iv = raw[:block_size]
            ciphertext = raw[block_size:]

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            obj = json.loads(plaintext.rstrip(b"\n").decode())
            return Interaction(
                protocol=obj.get("protocol", "unknown"),
                unique_id=obj.get("unique-id", ""),
                full_id=obj.get("full-id", ""),
                remote_address=obj.get("remote-address", ""),
                raw_request=obj.get("raw-request", ""),
                timestamp=obj.get("timestamp", ""),
                query_type=obj.get("q-type", ""),
            )
        except Exception as e:
            logger.warning("Failed to decrypt interaction: %s", e)
            return None

    async def deregister(self, session: OOBSession) -> bool:
        """Deregister a session from the interactsh server.

        Args:
            session: Active OOB session to deregister.

        Returns:
            True if deregistration succeeded.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.post(
                    f"https://{session.server}/deregister",
                    json={
                        "correlation-id": session.correlation_id,
                        "secret-key": session.secret_key,
                    },
                )
                return resp.status_code == 200
        except httpx.HTTPError:
            return False


# ---------------------------------------------------------------------------
# Tool wrappers
# ---------------------------------------------------------------------------

# Module-level session store (shared across tool calls within a scan)
_active_sessions: dict[str, OOBSession] = {}


async def python_oob_setup(server: str | None = None) -> str:
    """Set up an OOB (Out-of-Band) callback listener for blind vulnerability detection.

    Registers with an interactsh server and returns a unique domain.
    Use this domain in SSRF, XXE, XSS, and SQLi payloads to detect
    blind vulnerabilities via DNS/HTTP callbacks.

    Args:
        server: Optional interactsh server hostname (default: oast.live).

    Returns:
        JSON string with session info including the callback domain.
    """
    oob = OOBClient(server=server or DEFAULT_SERVER)
    try:
        session = await oob.register()
        _active_sessions[session.correlation_id] = session

        return json.dumps(
            {
                "status": "registered",
                "domain": session.domain,
                "correlation_id": session.correlation_id,
                "usage": (
                    f"Inject {session.domain} (or subdomains like test.{session.domain}) "
                    "into SSRF/XXE/XSS payloads, then call oob_poll to check for callbacks."
                ),
                "example_payloads": {
                    "ssrf": f"http://{session.domain}/",
                    "xxe": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{session.domain}/xxe">]>',
                    "xss": f"<img src=http://{session.domain}/xss>",
                    "sqli_dns": f"LOAD_FILE('\\\\\\\\{session.domain}\\\\a')",
                },
            },
            indent=2,
        )
    except RuntimeError as e:
        return json.dumps({"status": "error", "error": str(e)})


async def python_oob_poll(correlation_id: str | None = None) -> str:
    """Poll for OOB interactions (DNS/HTTP/SMTP callbacks) on an active session.

    Call this after injecting the OOB domain into payloads and waiting
    a few seconds for the target to make callbacks.

    Args:
        correlation_id: Session correlation ID from oob_setup. If omitted,
            polls the most recently created session.

    Returns:
        JSON string with interaction details (protocol, remote address, etc.).
    """
    if not _active_sessions:
        return json.dumps({"status": "error", "error": "No active OOB session. Call oob_setup first."})

    # Find the session
    session: OOBSession | None = None
    if correlation_id and correlation_id in _active_sessions:
        session = _active_sessions[correlation_id]
    else:
        # Use the most recently created session
        session = max(_active_sessions.values(), key=lambda s: s.created_at)

    oob = OOBClient(server=session.server)
    interactions = await oob.poll(session)

    result = OOBPollResult(
        session_domain=session.domain,
        interactions=interactions,
        poll_count=session.interactions_found,
    )

    if interactions:
        return json.dumps(
            {
                "status": "interactions_found",
                "blind_vulnerability_confirmed": True,
                **result.to_dict(),
            },
            indent=2,
        )

    return json.dumps(
        {
            "status": "no_interactions",
            "blind_vulnerability_confirmed": False,
            **result.to_dict(),
            "hint": "Wait 5-10 seconds after injecting the payload, then poll again.",
        },
        indent=2,
    )
