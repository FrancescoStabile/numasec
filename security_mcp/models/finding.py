"""Finding model with auto-enrichment and validation."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from security_mcp.models.enums import Severity


class Finding(BaseModel):
    """Security finding with SARIF-compatible fields and auto-enrichment."""

    id: str = Field(default="", description="Auto-generated finding ID")
    title: str = Field(..., min_length=3)
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: str = ""
    url: str = ""
    method: str = ""
    parameter: str = ""
    payload: str = ""
    request_dump: str = ""
    response_status: int | None = None

    # Standards mapping
    cwe_id: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""  # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    owasp_category: str = ""
    rule_id: str = ""

    # Remediation
    remediation_summary: str = ""

    # Confidence & compliance mapping
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    attack_technique: str = ""
    wstg_id: str = ""

    # Attack chain cross-references
    related_finding_ids: list[str] = Field(default_factory=list)
    chain_id: str = ""  # Groups findings into attack chains

    # Metadata
    target: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    confirmed: bool = False
    false_positive: bool = False
    tool_used: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Severity:
        if isinstance(v, str):
            v = v.strip().lower()
            mapping = {"crit": "critical", "high": "high", "med": "medium", "low": "low"}
            v = mapping.get(v, v)
            return Severity(v)
        return v

    @field_validator("title")
    @classmethod
    def clean_title(cls, v: str) -> str:
        return re.sub(r"\s+", " ", v.strip())

    @model_validator(mode="after")
    def auto_generate_id(self) -> Finding:
        if not self.id:
            raw = f"{self.method}:{self.url}:{self.parameter}:{self.title}"
            self.id = f"SSEC-{hashlib.sha256(raw.encode()).hexdigest()[:12].upper()}"
        return self

    def fingerprint(self) -> str:
        """SARIF-compatible partial fingerprint for deduplication."""
        raw = f"{self.method}:{self.url}:{self.parameter}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
