"""Encrypted payload pack (.kbpack) — zstd + Fernet."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("security_mcp.knowledge.pack")


class KBPack:
    """Encrypted knowledge base pack for offensive payloads.

    Only payloads are encrypted (not descriptive templates).
    Format: YAML files → JSON bytes → zstd compressed → Fernet encrypted.
    Decrypted ONLY in memory — never written to disk in plaintext.
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key

    def build(self, payload_dir: Path, output: Path) -> str:
        """Build encrypted pack from payload YAML files.

        Returns SHA-256 hex digest of the encrypted pack file.
        """
        if self._key is None:
            raise ValueError("Encryption key required to build a pack")

        import zstandard as zstd
        from cryptography.fernet import Fernet

        # Collect all YAML payloads
        payloads: dict[str, Any] = {}
        if payload_dir.is_dir():
            for yaml_file in sorted(payload_dir.rglob("*.yaml")):
                try:
                    data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                    if data and isinstance(data, dict):
                        key_name = yaml_file.stem
                        payloads[key_name] = data
                except (yaml.YAMLError, OSError) as exc:
                    logger.warning("Skipping %s: %s", yaml_file, exc)

        if not payloads:
            logger.warning("No payloads found in %s", payload_dir)

        # Serialize → compress → encrypt
        json_bytes = json.dumps(payloads, ensure_ascii=False).encode("utf-8")

        compressor = zstd.ZstdCompressor(level=9)
        compressed = compressor.compress(json_bytes)

        fernet = Fernet(self._key)
        encrypted = fernet.encrypt(compressed)

        # Write to output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(encrypted)

        # SHA-256 signature
        signature = hashlib.sha256(encrypted).hexdigest()
        logger.info(
            "Built pack: %d payloads, %d → %d → %d bytes, SHA256=%s",
            len(payloads),
            len(json_bytes),
            len(compressed),
            len(encrypted),
            signature[:16],
        )
        return signature

    def load(self, pack_path: Path) -> dict[str, Any]:
        """Load and decrypt a .kbpack file. Decrypted ONLY in memory."""
        if self._key is None:
            raise ValueError("Encryption key required to load a pack")

        import zstandard as zstd
        from cryptography.fernet import Fernet

        encrypted = pack_path.read_bytes()

        # Decrypt → decompress → parse
        fernet = Fernet(self._key)
        compressed = fernet.decrypt(encrypted)

        decompressor = zstd.ZstdDecompressor()
        json_bytes = decompressor.decompress(compressed)

        payloads: dict[str, Any] = json.loads(json_bytes.decode("utf-8"))
        logger.info("Loaded pack: %d payloads from %s", len(payloads), pack_path.name)
        return payloads

    def verify(self, pack_path: Path, expected_sha256: str) -> bool:
        """Verify pack file integrity against expected SHA-256."""
        actual = hashlib.sha256(pack_path.read_bytes()).hexdigest()
        return actual == expected_sha256

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet encryption key."""
        from cryptography.fernet import Fernet

        return Fernet.generate_key()
