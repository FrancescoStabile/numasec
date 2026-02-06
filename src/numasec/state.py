"""
NumaSec v3 - Session State

State management: findings, history, target profile, attack plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from numasec.target_profile import TargetProfile
from numasec.planner import AttackPlan


@dataclass
class Finding:
    """A security finding."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    cve: str | None = None
    cvss_score: float | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
            "cve": self.cve,
            "cvss_score": self.cvss_score,
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
        """Add security finding."""
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
