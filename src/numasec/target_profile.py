"""
NumaSec — Target Profile (Structured Memory)

Everything the agent knows about the target, auto-populated from tool results.
Injected into LLM context as a structured summary to reduce token usage
and enable structured reasoning.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Port:
    """A discovered network port."""
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""

    def __str__(self) -> str:
        parts = [f"{self.number}/{self.protocol}"]
        if self.service:
            parts.append(self.service)
        if self.product:
            ver = f" {self.version}" if self.version else ""
            parts.append(f"{self.product}{ver}")
        return " ".join(parts)


@dataclass
class Endpoint:
    """A discovered web endpoint."""
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str = ""
    auth_required: bool = False
    parameters: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    notes: str = ""
    interesting: bool = False

    def __str__(self) -> str:
        status = f" [{self.status_code}]" if self.status_code else ""
        return f"{self.method} {self.url}{status}"


@dataclass
class Credential:
    """A discovered credential."""
    username: str
    password: str
    source: str = ""
    target: str = ""
    valid: bool = False

    def __str__(self) -> str:
        valid_str = "verified" if self.valid else "?"
        return f"{valid_str} {self.username}:{self.password} ({self.source})"


@dataclass
class Technology:
    """A detected technology."""
    name: str
    version: str = ""
    category: str = ""  # "framework", "server", "language", "cms", "waf", "os", "database"

    def __str__(self) -> str:
        ver = f" {self.version}" if self.version else ""
        return f"{self.name}{ver}"


@dataclass
class VulnHypothesis:
    """A suspected vulnerability that needs testing."""
    vuln_type: str        # "sqli", "xss", "lfi", "idor", "ssti", "rce", "auth_bypass"
    location: str         # URL or parameter
    evidence: str = ""
    confidence: float = 0.5  # 0.0 = wild guess, 1.0 = confirmed
    tested: bool = False
    confirmed: bool = False
    tool_used: str = ""
    exploitation_notes: str = ""

    def __str__(self) -> str:
        status = "CONFIRMED" if self.confirmed else ("TESTED" if self.tested else "UNTESTED")
        return f"[{status}] {self.vuln_type} @ {self.location} (confidence: {self.confidence:.0%})"


@dataclass
class TargetProfile:
    """
    Everything the agent knows about the target.

    Auto-populated by extractors after each tool call.
    Serialized with sessions for resume capability.
    Injected into LLM context as structured summary.
    """
    # Identity
    target: str = ""
    scope: list[str] = field(default_factory=list)

    # Reconnaissance
    ports: list[Port] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)

    # Authentication
    credentials: list[Credential] = field(default_factory=list)
    session_tokens: dict[str, str] = field(default_factory=dict)

    # Vulnerability tracking
    hypotheses: list[VulnHypothesis] = field(default_factory=list)

    # Metadata
    os_guess: str = ""
    server_header: str = ""
    waf_detected: bool = False
    waf_type: str = ""

    # SPA (Single Page Application) detection
    spa_detected: bool = False
    spa_shell_hash: str = ""     # MD5 of normalised root HTML body (first 3 KB)
    spa_shell_title: str = ""    # <title> of the SPA shell page

    # Timeline
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())

    # ── Mutation methods ──

    def add_port(self, port: Port) -> bool:
        """Add port if not already known. Returns True if new."""
        if not any(p.number == port.number and p.protocol == port.protocol for p in self.ports):
            self.ports.append(port)
            self._touch()
            return True
        return False

    def add_endpoint(self, endpoint: Endpoint) -> bool:
        """Add or update endpoint. Returns True if new."""
        for i, ep in enumerate(self.endpoints):
            if ep.url == endpoint.url and ep.method == endpoint.method:
                self.endpoints[i] = endpoint
                self._touch()
                return False
        self.endpoints.append(endpoint)
        self._touch()
        return True

    def add_technology(self, tech: Technology) -> bool:
        """Add technology if not known. Returns True if new."""
        if not any(t.name.lower() == tech.name.lower() for t in self.technologies):
            self.technologies.append(tech)
            self._touch()
            return True
        return False

    def add_credential(self, cred: Credential) -> bool:
        """Add credential if not known. Returns True if new."""
        if not any(c.username == cred.username and c.password == cred.password for c in self.credentials):
            self.credentials.append(cred)
            self._touch()
            return True
        return False

    def add_hypothesis(self, hyp: VulnHypothesis) -> bool:
        """Add hypothesis if not duplicate. Returns True if new."""
        for h in self.hypotheses:
            if h.vuln_type == hyp.vuln_type and h.location == hyp.location:
                # Update existing if higher confidence
                if hyp.confidence > h.confidence:
                    h.confidence = hyp.confidence
                    h.evidence = hyp.evidence
                if hyp.confirmed:
                    h.confirmed = True
                if hyp.tested:
                    h.tested = True
                self._touch()
                return False
        self.hypotheses.append(hyp)
        self._touch()
        return True

    def mark_hypothesis_tested(self, vuln_type: str, location: str, confirmed: bool, notes: str = ""):
        """Mark a hypothesis as tested."""
        for h in self.hypotheses:
            if h.vuln_type == vuln_type and h.location == location:
                h.tested = True
                h.confirmed = confirmed
                h.confidence = 1.0 if confirmed else 0.0
                if notes:
                    h.exploitation_notes = notes
                self._touch()
                return

    # ── Query methods ──

    def get_open_ports(self) -> list[int]:
        return [p.number for p in self.ports if p.state == "open"]

    def get_web_ports(self) -> list[int]:
        web_services = {"http", "https", "http-alt", "http-proxy", "ssl/http"}
        return [p.number for p in self.ports
                if p.state == "open" and (
                    p.service in web_services
                    or p.number in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090)
                )]

    def get_untested_hypotheses(self) -> list[VulnHypothesis]:
        return [h for h in self.hypotheses if not h.tested]

    def get_confirmed_vulns(self) -> list[VulnHypothesis]:
        return [h for h in self.hypotheses if h.confirmed]

    def has_technology(self, name: str) -> bool:
        return any(name.lower() in t.name.lower() for t in self.technologies)

    def get_interesting_endpoints(self) -> list[Endpoint]:
        return [e for e in self.endpoints if e.interesting or e.auth_required or e.parameters]

    # ── Context injection ──

    def to_prompt_summary(self) -> str:
        """
        Generate a structured summary for LLM context injection.
        Designed to be compact and information-dense.
        """
        if not self.target:
            return ""

        lines = [f"## Current Target Knowledge: {self.target}"]

        # Ports
        if self.ports:
            open_ports = [p for p in self.ports if p.state == "open"]
            if open_ports:
                lines.append(f"\n### Open Ports ({len(open_ports)})")
                for p in open_ports[:20]:
                    lines.append(f"- {p}")

        # Technologies
        if self.technologies:
            lines.append(f"\n### Technologies")
            lines.append(", ".join(str(t) for t in self.technologies))

        # Key endpoints
        interesting = self.get_interesting_endpoints()
        if interesting:
            lines.append(f"\n### Key Endpoints ({len(interesting)})")
            for ep in interesting[:15]:
                lines.append(f"- {ep}")

        # WAF
        if self.waf_detected:
            lines.append(f"\n### WAF: {self.waf_type or 'Detected (unknown type)'}")

        # SPA detection — CRITICAL for preventing false-positive findings
        if self.spa_detected or self.spa_shell_title:
            title_hint = f" ({self.spa_shell_title})" if self.spa_shell_title else ""
            lines.append(f"\n### \u26a0 SPA Application Detected{title_hint}")
            lines.append(
                "**IMPORTANT:** This target serves the SAME HTML shell for ALL routes. "
                "A 200 OK on /.git, /.env, /admin etc. does NOT mean those files are exposed \u2014 "
                "the server returns its index.html for every path the client-side router doesn't handle."
            )
            lines.append(
                "Focus on **API endpoints** (/api/*, /rest/*, /graphql) for real server-side vulnerabilities. "
                "Only flag a sensitive file as exposed if the response body contains the ACTUAL file content "
                "(not the app shell HTML)."
            )

        # Subdomains
        if self.subdomains:
            lines.append(f"\n### Subdomains ({len(self.subdomains)})")
            for s in self.subdomains[:10]:
                lines.append(f"- {s}")

        # Credentials
        if self.credentials:
            lines.append(f"\n### Credentials Found ({len(self.credentials)})")
            for c in self.credentials:
                lines.append(f"- {c}")

        # Vulnerability hypotheses
        untested = self.get_untested_hypotheses()
        confirmed = self.get_confirmed_vulns()

        if confirmed:
            lines.append(f"\n### CONFIRMED Vulnerabilities ({len(confirmed)})")
            for v in confirmed:
                lines.append(f"- {v}")

        if untested:
            lines.append(f"\n### Untested Hypotheses ({len(untested)})")
            for h in untested[:10]:
                lines.append(f"- {h}")

        return "\n".join(lines)

    # ── Serialization ──

    def to_dict(self) -> dict:
        """Serialize for session persistence."""
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> TargetProfile:
        """Deserialize from session data."""
        if not data:
            return cls()

        profile = cls()
        profile.target = data.get("target", "")
        profile.scope = data.get("scope", [])
        profile.os_guess = data.get("os_guess", "")
        profile.server_header = data.get("server_header", "")
        profile.waf_detected = data.get("waf_detected", False)
        profile.waf_type = data.get("waf_type", "")
        profile.spa_detected = data.get("spa_detected", False)
        profile.spa_shell_hash = data.get("spa_shell_hash", "")
        profile.spa_shell_title = data.get("spa_shell_title", "")
        profile.subdomains = data.get("subdomains", [])
        profile.session_tokens = data.get("session_tokens", {})
        profile.last_updated = data.get("last_updated", datetime.now().isoformat())

        for p in data.get("ports", []):
            if isinstance(p, dict):
                profile.ports.append(Port(**p))
        for e in data.get("endpoints", []):
            if isinstance(e, dict):
                profile.endpoints.append(Endpoint(**e))
        for t in data.get("technologies", []):
            if isinstance(t, dict):
                profile.technologies.append(Technology(**t))
        for c in data.get("credentials", []):
            if isinstance(c, dict):
                profile.credentials.append(Credential(**c))
        for h in data.get("hypotheses", []):
            if isinstance(h, dict):
                profile.hypotheses.append(VulnHypothesis(**h))

        return profile

    def _touch(self):
        self.last_updated = datetime.now().isoformat()
