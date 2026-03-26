"""Template YAML signing and verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


class TemplateSigner:
    """Sign and verify YAML template integrity."""

    def __init__(self, signatures_path: Path | None = None) -> None:
        self._signatures_path = signatures_path
        self._signatures: dict[str, str] = {}
        if signatures_path and signatures_path.exists():
            self._signatures = json.loads(signatures_path.read_text())

    def sign_file(self, path: Path) -> str:
        """Compute SHA-256 signature for a template file."""
        content = path.read_bytes()
        sig = hashlib.sha256(content).hexdigest()
        self._signatures[str(path)] = sig
        return sig

    def verify_file(self, path: Path) -> bool:
        """Verify a template file against stored signature."""
        if str(path) not in self._signatures:
            return False
        content = path.read_bytes()
        return hashlib.sha256(content).hexdigest() == self._signatures[str(path)]

    def save_signatures(self) -> None:
        """Persist signatures to disk."""
        if self._signatures_path:
            self._signatures_path.write_text(json.dumps(self._signatures, indent=2))
