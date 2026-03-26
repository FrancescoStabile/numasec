"""Tests for P2-A: OOB (Out-of-Band) callback detection via interactsh."""

from __future__ import annotations

import base64
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from security_mcp.tools.oob_tool import (
    CID_LENGTH,
    CID_NONCE_LENGTH,
    DEFAULT_SERVER,
    Interaction,
    OOBClient,
    OOBPollResult,
    OOBSession,
    _active_sessions,
    _random_string,
    python_oob_poll,
    python_oob_setup,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(status_code: int = 200, json_body: dict | None = None, text: str = "") -> httpx.Response:
    """Build a fake httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        text=text or json.dumps(json_body or {}),
        request=httpx.Request("GET", "http://test"),
    )


def _generate_test_keypair() -> tuple[rsa.RSAPrivateKey, bytes]:
    """Generate RSA keypair for testing encryption/decryption."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def _encrypt_interaction(public_key: rsa.RSAPublicKey, interaction_data: dict) -> tuple[str, str]:
    """Encrypt an interaction dict the same way the interactsh server does.

    Returns (aes_key_encrypted_b64, data_encrypted_b64).
    """
    # Generate random AES key
    aes_key = os.urandom(32)

    # Encrypt AES key with RSA public key
    aes_key_encrypted = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    aes_key_b64 = base64.b64encode(aes_key_encrypted).decode()

    # Encrypt interaction data with AES-CFB
    plaintext = json.dumps(interaction_data).encode() + b"\n"
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    data_b64 = base64.b64encode(iv + ciphertext).decode()

    return aes_key_b64, data_b64


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------


class TestOOBSession:
    def test_to_dict(self):
        s = OOBSession(
            server="oast.live",
            correlation_id="abc123",
            secret_key="secret",
            private_key_pem="-----BEGIN RSA PRIVATE KEY-----\n...",
            domain="abc123nonce.oast.live",
            created_at=1000.0,
            interactions_found=3,
        )
        d = s.to_dict()
        assert d["server"] == "oast.live"
        assert d["correlation_id"] == "abc123"
        assert d["domain"] == "abc123nonce.oast.live"
        assert d["interactions_found"] == 3
        # Private key should NOT be in to_dict
        assert "private_key_pem" not in d

    def test_private_key_not_exposed(self):
        s = OOBSession(
            server="oast.live",
            correlation_id="abc",
            secret_key="secret",
            private_key_pem="PRIVATE",
            domain="abc.oast.live",
        )
        d = s.to_dict()
        assert "PRIVATE" not in json.dumps(d)


class TestInteraction:
    def test_to_dict(self):
        i = Interaction(
            protocol="http",
            unique_id="abc123",
            full_id="abc123nonce.oast.live",
            remote_address="1.2.3.4",
            raw_request="GET / HTTP/1.1\r\nHost: abc123nonce.oast.live",
            timestamp="2024-01-01T00:00:00Z",
        )
        d = i.to_dict()
        assert d["protocol"] == "http"
        assert d["remote_address"] == "1.2.3.4"
        assert "query_type" not in d  # Only for DNS

    def test_dns_interaction(self):
        i = Interaction(
            protocol="dns",
            unique_id="abc123",
            full_id="abc123nonce.oast.live",
            remote_address="8.8.8.8",
            raw_request="",
            timestamp="2024-01-01T00:00:00Z",
            query_type="A",
        )
        d = i.to_dict()
        assert d["protocol"] == "dns"
        assert d["query_type"] == "A"

    def test_raw_request_truncation(self):
        i = Interaction(
            protocol="http",
            unique_id="abc",
            full_id="abc.oast.live",
            remote_address="1.2.3.4",
            raw_request="A" * 1000,
            timestamp="",
        )
        d = i.to_dict()
        assert len(d["raw_request"]) == 500


class TestOOBPollResult:
    def test_empty(self):
        r = OOBPollResult(session_domain="abc.oast.live")
        d = r.to_dict()
        assert d["interaction_count"] == 0
        assert d["interactions"] == []

    def test_with_interactions(self):
        r = OOBPollResult(
            session_domain="abc.oast.live",
            interactions=[
                Interaction(
                    protocol="dns",
                    unique_id="abc",
                    full_id="abc.oast.live",
                    remote_address="8.8.8.8",
                    raw_request="",
                    timestamp="",
                    query_type="A",
                ),
            ],
        )
        d = r.to_dict()
        assert d["interaction_count"] == 1


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestRandomString:
    def test_length(self):
        s = _random_string(20)
        assert len(s) == 20

    def test_characters(self):
        s = _random_string(100)
        assert all(c in "abcdefghijklmnopqrstuvwxyz0123456789" for c in s)

    def test_uniqueness(self):
        strings = {_random_string(20) for _ in range(100)}
        assert len(strings) == 100  # All should be unique


# ---------------------------------------------------------------------------
# OOBClient.register tests
# ---------------------------------------------------------------------------


class TestRegister:
    async def test_successful_registration(self):
        client = OOBClient(server="oast.live")
        resp = _mock_response(200, json_body={"message": "registration successful"})

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(return_value=resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            session = await client.register()

        assert session.server == "oast.live"
        assert len(session.correlation_id) == CID_LENGTH
        assert session.domain.endswith(".oast.live")
        assert "BEGIN RSA PRIVATE KEY" in session.private_key_pem

    async def test_registration_uses_post(self):
        client = OOBClient(server="oast.live")
        resp = _mock_response(200)

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(return_value=resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            await client.register()

            call_args = mock_http.post.call_args
            assert "register" in call_args[0][0]
            payload = call_args[1]["json"]
            assert "public-key" in payload
            assert "secret-key" in payload
            assert "correlation-id" in payload

    async def test_fallback_server(self):
        client = OOBClient(server="oast.live")
        fail_resp = _mock_response(500)
        ok_resp = _mock_response(200)

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return fail_resp
            return ok_resp

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(side_effect=mock_post)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            session = await client.register()

        assert call_count == 2
        assert session.server != "oast.live"

    async def test_all_servers_fail(self):
        client = OOBClient(server="oast.live")
        fail_resp = _mock_response(500)

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(return_value=fail_resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            with pytest.raises(RuntimeError, match="OOB registration failed"):
                await client.register()

    async def test_connection_error_triggers_fallback(self):
        client = OOBClient(server="oast.live")
        ok_resp = _mock_response(200)

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("timeout")
            return ok_resp

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(side_effect=mock_post)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            session = await client.register()

        assert call_count == 2


# ---------------------------------------------------------------------------
# OOBClient.poll tests
# ---------------------------------------------------------------------------


class TestPoll:
    def _make_session(self) -> OOBSession:
        """Create a test session with a real RSA key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return OOBSession(
            server="oast.live",
            correlation_id="testcid12345678901234",
            secret_key="testsecret",
            private_key_pem=private_pem,
            domain="testcid12345678901234nonce.oast.live",
        ), private_key

    async def test_poll_no_interactions(self):
        session, _ = self._make_session()
        client = OOBClient()
        resp = _mock_response(200, json_body={"aes_key": "", "data": []})

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            interactions = await client.poll(session)

        assert interactions == []

    async def test_poll_with_encrypted_interaction(self):
        session, private_key = self._make_session()
        public_key = private_key.public_key()

        interaction_data = {
            "protocol": "dns",
            "unique-id": "testcid12345678901234",
            "full-id": "testcid12345678901234nonce.oast.live",
            "remote-address": "8.8.8.8",
            "raw-request": "DNS A query",
            "timestamp": "2024-01-01T00:00:00Z",
            "q-type": "A",
        }

        aes_key_b64, data_b64 = _encrypt_interaction(public_key, interaction_data)
        resp = _mock_response(200, json_body={"aes_key": aes_key_b64, "data": [data_b64]})

        client = OOBClient()
        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            interactions = await client.poll(session)

        assert len(interactions) == 1
        assert interactions[0].protocol == "dns"
        assert interactions[0].remote_address == "8.8.8.8"
        assert interactions[0].query_type == "A"
        assert session.interactions_found == 1

    async def test_poll_multiple_interactions(self):
        session, private_key = self._make_session()
        public_key = private_key.public_key()

        dns_data = {
            "protocol": "dns",
            "unique-id": "abc",
            "full-id": "abc.oast.live",
            "remote-address": "8.8.8.8",
            "raw-request": "",
            "timestamp": "",
            "q-type": "A",
        }
        http_data = {
            "protocol": "http",
            "unique-id": "abc",
            "full-id": "abc.oast.live",
            "remote-address": "1.2.3.4",
            "raw-request": "GET / HTTP/1.1",
            "timestamp": "",
        }

        aes_key_b64_1, data_b64_1 = _encrypt_interaction(public_key, dns_data)
        # Use same AES key for both (simulate server behavior)
        # Actually, server sends one AES key for all items in a poll
        _, data_b64_2 = _encrypt_interaction(public_key, http_data)

        # For a proper test, use the SAME AES key for both items
        aes_key = os.urandom(32)
        aes_key_enc = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        aes_key_b64 = base64.b64encode(aes_key_enc).decode()

        def encrypt_with_key(data: dict) -> str:
            plaintext = json.dumps(data).encode() + b"\n"
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            enc = cipher.encryptor()
            ct = enc.update(plaintext) + enc.finalize()
            return base64.b64encode(iv + ct).decode()

        d1 = encrypt_with_key(dns_data)
        d2 = encrypt_with_key(http_data)

        resp = _mock_response(200, json_body={"aes_key": aes_key_b64, "data": [d1, d2]})

        client = OOBClient()
        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            interactions = await client.poll(session)

        assert len(interactions) == 2
        protocols = {i.protocol for i in interactions}
        assert "dns" in protocols
        assert "http" in protocols

    async def test_poll_http_error(self):
        session, _ = self._make_session()
        client = OOBClient()

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            interactions = await client.poll(session)

        assert interactions == []

    async def test_poll_non_200_status(self):
        session, _ = self._make_session()
        client = OOBClient()
        resp = _mock_response(401)

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.get = AsyncMock(return_value=resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            interactions = await client.poll(session)

        assert interactions == []


# ---------------------------------------------------------------------------
# Payload URL generation
# ---------------------------------------------------------------------------


class TestGeneratePayloadUrl:
    def test_basic_generation(self):
        session = OOBSession(
            server="oast.live",
            correlation_id="a" * CID_LENGTH,
            secret_key="secret",
            private_key_pem="",
            domain=f"{'a' * CID_LENGTH}nonce.oast.live",
        )
        client = OOBClient()
        url = client.generate_payload_url(session)

        assert url.endswith(".oast.live")
        assert url.startswith("a" * CID_LENGTH)

    def test_with_suffix(self):
        session = OOBSession(
            server="oast.live",
            correlation_id="abc",
            secret_key="secret",
            private_key_pem="",
            domain="abc.oast.live",
        )
        client = OOBClient()
        url = client.generate_payload_url(session, suffix="ssrf")

        assert "ssrf" in url
        assert url.endswith(".oast.live")

    def test_unique_per_call(self):
        session = OOBSession(
            server="oast.live",
            correlation_id="abc",
            secret_key="secret",
            private_key_pem="",
            domain="abc.oast.live",
        )
        client = OOBClient()
        urls = {client.generate_payload_url(session) for _ in range(50)}
        assert len(urls) == 50


# ---------------------------------------------------------------------------
# Deregister
# ---------------------------------------------------------------------------


class TestDeregister:
    async def test_successful_deregister(self):
        session = OOBSession(
            server="oast.live",
            correlation_id="abc",
            secret_key="secret",
            private_key_pem="",
            domain="abc.oast.live",
        )
        client = OOBClient()
        resp = _mock_response(200)

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(return_value=resp)
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            result = await client.deregister(session)

        assert result is True

    async def test_failed_deregister(self):
        session = OOBSession(
            server="oast.live",
            correlation_id="abc",
            secret_key="secret",
            private_key_pem="",
            domain="abc.oast.live",
        )
        client = OOBClient()

        with patch("security_mcp.tools.oob_tool.httpx.AsyncClient") as mock_cls:
            mock_http = AsyncMock()
            mock_http.post = AsyncMock(side_effect=httpx.ConnectError("fail"))
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_http

            result = await client.deregister(session)

        assert result is False


# ---------------------------------------------------------------------------
# Decrypt interaction tests
# ---------------------------------------------------------------------------


class TestDecryptInteraction:
    def test_successful_decryption(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        data = {
            "protocol": "http",
            "unique-id": "test123",
            "full-id": "test123.oast.live",
            "remote-address": "1.2.3.4",
            "raw-request": "GET /xss HTTP/1.1",
            "timestamp": "2024-01-01T00:00:00Z",
        }

        # Encrypt with AES-CFB
        aes_key = os.urandom(32)
        plaintext = json.dumps(data).encode() + b"\n"
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        encrypted_b64 = base64.b64encode(iv + ct).decode()

        interaction = OOBClient._decrypt_interaction(aes_key, encrypted_b64)

        assert interaction is not None
        assert interaction.protocol == "http"
        assert interaction.remote_address == "1.2.3.4"
        assert interaction.unique_id == "test123"

    def test_corrupted_data_returns_none(self):
        aes_key = os.urandom(32)
        interaction = OOBClient._decrypt_interaction(aes_key, "not-valid-base64!!!")
        assert interaction is None

    def test_wrong_key_returns_none(self):
        # Encrypt with one key, decrypt with another
        aes_key = os.urandom(32)
        wrong_key = os.urandom(32)
        data = json.dumps({"protocol": "dns"}).encode() + b"\n"
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        enc = cipher.encryptor()
        ct = enc.update(data) + enc.finalize()
        encrypted_b64 = base64.b64encode(iv + ct).decode()

        # Wrong key → decryption produces garbage → JSON parse fails → None
        interaction = OOBClient._decrypt_interaction(wrong_key, encrypted_b64)
        assert interaction is None


# ---------------------------------------------------------------------------
# Tool wrapper tests
# ---------------------------------------------------------------------------


class TestOobSetupTool:
    async def test_successful_setup(self):
        _active_sessions.clear()

        mock_session = OOBSession(
            server="oast.live",
            correlation_id="testcid12345678901234",
            secret_key="secret",
            private_key_pem="pem",
            domain="testcid12345678901234nonce.oast.live",
        )

        with patch(
            "security_mcp.tools.oob_tool.OOBClient.register",
            new_callable=AsyncMock,
            return_value=mock_session,
        ):
            output = await python_oob_setup()
            data = json.loads(output)

        assert data["status"] == "registered"
        assert "domain" in data
        assert "example_payloads" in data
        assert "ssrf" in data["example_payloads"]
        assert "xxe" in data["example_payloads"]
        assert "testcid12345678901234" in _active_sessions

    async def test_failed_setup(self):
        _active_sessions.clear()

        with patch(
            "security_mcp.tools.oob_tool.OOBClient.register",
            new_callable=AsyncMock,
            side_effect=RuntimeError("All servers failed"),
        ):
            output = await python_oob_setup()
            data = json.loads(output)

        assert data["status"] == "error"
        assert "All servers failed" in data["error"]

    async def test_custom_server(self):
        _active_sessions.clear()

        mock_session = OOBSession(
            server="oast.fun",
            correlation_id="abc",
            secret_key="secret",
            private_key_pem="pem",
            domain="abc.oast.fun",
        )

        with patch(
            "security_mcp.tools.oob_tool.OOBClient.register",
            new_callable=AsyncMock,
            return_value=mock_session,
        ) as mock_register:
            await python_oob_setup(server="oast.fun")


class TestOobPollTool:
    async def test_poll_no_session(self):
        _active_sessions.clear()
        output = await python_oob_poll()
        data = json.loads(output)
        assert data["status"] == "error"
        assert "No active OOB session" in data["error"]

    async def test_poll_with_interactions(self):
        _active_sessions.clear()
        session = OOBSession(
            server="oast.live",
            correlation_id="testcid",
            secret_key="secret",
            private_key_pem="pem",
            domain="testcid.oast.live",
        )
        _active_sessions["testcid"] = session

        mock_interactions = [
            Interaction(
                protocol="dns",
                unique_id="testcid",
                full_id="testcid.oast.live",
                remote_address="8.8.8.8",
                raw_request="DNS A query",
                timestamp="2024-01-01T00:00:00Z",
                query_type="A",
            ),
        ]

        with patch(
            "security_mcp.tools.oob_tool.OOBClient.poll",
            new_callable=AsyncMock,
            return_value=mock_interactions,
        ):
            output = await python_oob_poll(correlation_id="testcid")
            data = json.loads(output)

        assert data["status"] == "interactions_found"
        assert data["blind_vulnerability_confirmed"] is True
        assert data["interaction_count"] == 1

    async def test_poll_no_interactions(self):
        _active_sessions.clear()
        session = OOBSession(
            server="oast.live",
            correlation_id="testcid",
            secret_key="secret",
            private_key_pem="pem",
            domain="testcid.oast.live",
        )
        _active_sessions["testcid"] = session

        with patch(
            "security_mcp.tools.oob_tool.OOBClient.poll",
            new_callable=AsyncMock,
            return_value=[],
        ):
            output = await python_oob_poll()
            data = json.loads(output)

        assert data["status"] == "no_interactions"
        assert data["blind_vulnerability_confirmed"] is False
        assert "hint" in data

    async def test_poll_uses_most_recent_session(self):
        _active_sessions.clear()
        old_session = OOBSession(
            server="oast.live",
            correlation_id="old",
            secret_key="secret",
            private_key_pem="pem",
            domain="old.oast.live",
            created_at=1000.0,
        )
        new_session = OOBSession(
            server="oast.live",
            correlation_id="new",
            secret_key="secret",
            private_key_pem="pem",
            domain="new.oast.live",
            created_at=2000.0,
        )
        _active_sessions["old"] = old_session
        _active_sessions["new"] = new_session

        with patch(
            "security_mcp.tools.oob_tool.OOBClient.poll",
            new_callable=AsyncMock,
            return_value=[],
        ):
            output = await python_oob_poll()  # No correlation_id
            data = json.loads(output)

        assert data["session_domain"] == "new.oast.live"


# ---------------------------------------------------------------------------
# Tool registration test
# ---------------------------------------------------------------------------


class TestToolRegistration:
    def test_registry_has_oob_tool(self):
        """oob (replaces oob_setup + oob_poll) should be registered."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        names = [
            s.get("function", s).get("name", "") if isinstance(s, dict) else ""
            for s in registry.get_schemas()
        ]
        assert "oob" in names
