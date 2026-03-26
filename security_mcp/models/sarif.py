"""SARIF 2.1.0 data models for CI/CD integration."""

from __future__ import annotations

from dataclasses import dataclass, field

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


@dataclass
class SarifMessage:
    text: str
    markdown: str = ""


@dataclass
class SarifArtifactLocation:
    uri: str
    uri_base_id: str = ""


@dataclass
class SarifPhysicalLocation:
    artifact_location: SarifArtifactLocation


@dataclass
class SarifLocation:
    physical_location: SarifPhysicalLocation


@dataclass
class SarifResult:
    rule_id: str
    level: str  # error | warning | note | none
    message: SarifMessage
    locations: list[SarifLocation] = field(default_factory=list)
    partial_fingerprints: dict[str, str] = field(default_factory=dict)
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class SarifRule:
    id: str
    name: str
    short_description: SarifMessage
    full_description: SarifMessage = field(default_factory=lambda: SarifMessage(text=""))
    help_uri: str = ""
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class SarifToolDriver:
    name: str = "security_mcp"
    version: str = "0.1.0"
    semantic_version: str = "0.1.0"
    information_uri: str = ""
    rules: list[SarifRule] = field(default_factory=list)


@dataclass
class SarifTool:
    driver: SarifToolDriver = field(default_factory=SarifToolDriver)


@dataclass
class SarifRun:
    tool: SarifTool = field(default_factory=SarifTool)
    results: list[SarifResult] = field(default_factory=list)


@dataclass
class SarifLog:
    version: str = SARIF_VERSION
    schema_uri: str = SARIF_SCHEMA  # Mapped to "$schema" on serialization
    runs: list[SarifRun] = field(default_factory=list)
