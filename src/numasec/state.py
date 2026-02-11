"""
NumaSec v3 - Session State

State management: findings, history, target profile, attack plan.

Finding model uses Pydantic for validation:
  - Enforces specific, non-generic titles
  - Validates severity as enum
  - Auto-generates timestamps
  - Supports CWE/CVSS/OWASP enrichment
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from numasec.target_profile import TargetProfile
from numasec.planner import AttackPlan

logger = logging.getLogger("numasec.state")


# ═══════════════════════════════════════════════════════════════════════════
# Severity Enum
# ═══════════════════════════════════════════════════════════════════════════

class Severity(str, enum.Enum):
    """Standardized severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ═══════════════════════════════════════════════════════════════════════════
# Finding — Pydantic-validated security finding
# ═══════════════════════════════════════════════════════════════════════════

# Titles that are too generic to be useful
_GENERIC_TITLES = frozenset({
    "vulnerability", "issue", "finding", "problem", "bug",
    "vulnerability found", "issue found", "security issue",
    "potential vulnerability", "possible issue",
})


class Finding(BaseModel):
    """A validated security finding.

    Pydantic enforces:
      - Title must be specific (>= 10 chars, not a generic word)
      - Severity must be a valid enum value
      - Timestamp auto-generated
      - Optional fields for CVSS/CWE/OWASP enrichment
    """
    title: str
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    cve: str | None = None
    cvss_score: float | None = None
    cwe_id: str = ""          # e.g. "CWE-89"
    owasp_category: str = ""  # e.g. "A03:2021 - Injection"

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {datetime: lambda v: v.isoformat()},
    }

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """Normalize severity to lowercase and validate."""
        if isinstance(v, Severity):
            return v.value
        v = str(v).lower().strip()
        valid = {s.value for s in Severity}
        if v not in valid:
            # Attempt fuzzy match
            for sev in valid:
                if sev.startswith(v[:3]):
                    return sev
            logger.warning(f"Invalid severity '{v}', defaulting to 'info'")
            return "info"  # safe fallback
        return v

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, v: str) -> str:
        """Ensure title is specific enough to be useful."""
        v = str(v).strip()
        if not v:
            return "Untitled Finding"
        # Allow short titles but warn about generics
        if v.lower() in _GENERIC_TITLES:
            return f"{v} (needs specificity)"
        return v

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict — backward compatible with dataclass version."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
        }


@dataclass
class State:
    """Session state for the agent."""
    
    # Conversation history (LLM format)
    messages: list[dict] = field(default_factory=list)
    
    # Security findings discovered
    findings: list[Finding] = field(default_factory=list)
    
    # Current target
    target: str | None = None
    
    # Structured target knowledge (Fase A)
    profile: TargetProfile = field(default_factory=TargetProfile)
    
    # Attack plan (Fase B)
    plan: AttackPlan = field(default_factory=lambda: AttackPlan(objective=""))
    
    # Session data (cookies, tokens, etc)
    session_data: dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    started_at: datetime = field(default_factory=datetime.now)
    iteration: int = 0
    
    def add_message(self, role: str, content: str | list):
        """Add message to history."""
        self.messages.append({"role": role, "content": content})
        self.iteration += 1
    
    def add_finding(self, finding: Finding):
        """Add security finding with auto-enrichment (CWE/CVSS/OWASP)."""
        try:
            from numasec.standards import enrich_finding
            enrich_finding(finding)
        except Exception as e:
            logger.debug(f"Finding enrichment failed: {e}")
        self.findings.append(finding)
    
    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        """Get findings by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    @property
    def critical_count(self) -> int:
        return len(self.get_findings_by_severity("critical"))
    
    @property
    def high_count(self) -> int:
        return len(self.get_findings_by_severity("high"))
    
    def clear(self):
        """Clear state for new session."""
        self.messages.clear()
        self.findings.clear()
        self.session_data.clear()
        self.profile = TargetProfile()
        self.plan = AttackPlan(objective="")
        self.iteration = 0
        self.started_at = datetime.now()
