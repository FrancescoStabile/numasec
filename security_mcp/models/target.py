"""Target profile and related data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""
    state: str = "open"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str = ""
    auth_required: bool = False
    parameters: list[str] = field(default_factory=list)


@dataclass
class Technology:
    name: str
    version: str = ""
    category: str = ""  # web_server, language, cms, framework, database


@dataclass
class Credential:
    username: str
    password: str
    source: str = ""  # default_creds, brute_force, leak
    valid: bool = True


@dataclass
class Token:
    """Discovered authentication token (JWT, session cookie, API key, etc.)."""

    value: str
    token_type: str = "bearer"  # bearer, cookie, api_key, jwt
    source: str = ""  # Tool that discovered it
    valid: bool = True
    expires_at: str = ""


@dataclass
class VulnHypothesis:
    vuln_type: str
    location: str
    confidence: float = 0.5
    evidence: str = ""
    tested: bool = False
    confirmed: bool = False


@dataclass
class TargetProfile:
    """Accumulated knowledge about the target under test."""

    target: str = ""
    os_guess: str = ""
    is_spa: bool = False
    spa_framework: str = ""
    waf_detected: bool = False
    waf_name: str = ""
    cdn_detected: bool = False

    ports: list[Port] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    hypotheses: list[VulnHypothesis] = field(default_factory=list)

    def add_port(self, port: Port) -> None:
        if not any(p.number == port.number and p.protocol == port.protocol for p in self.ports):
            self.ports.append(port)

    def add_endpoint(self, endpoint: Endpoint) -> None:
        if not any(e.url == endpoint.url and e.method == endpoint.method for e in self.endpoints):
            self.endpoints.append(endpoint)

    def add_technology(self, tech: Technology) -> None:
        if not any(t.name.lower() == tech.name.lower() for t in self.technologies):
            self.technologies.append(tech)

    def add_credential(self, cred: Credential) -> None:
        """Deduplicated credential addition."""
        if not any(
            c.username == cred.username and c.password == cred.password
            for c in self.credentials
        ):
            self.credentials.append(cred)

    def add_token(self, token: Token) -> None:
        """Deduplicated token addition."""
        if not any(t.value == token.value for t in self.tokens):
            self.tokens.append(token)

    def get_auth_header(self) -> dict[str, str] | None:
        """Return the best available auth header for authenticated testing."""
        for token in self.tokens:
            if token.valid:
                if token.token_type == "bearer":
                    return {"Authorization": f"Bearer {token.value}"}
                if token.token_type == "cookie":
                    return {"Cookie": token.value}
                if token.token_type == "api_key":
                    return {"X-API-Key": token.value}
        return None

    def has_service(self, service: str) -> bool:
        return any(p.service == service for p in self.ports)

    def get_open_ports(self) -> list[int]:
        return [p.number for p in self.ports if p.state == "open"]
