"""security-mcp enumerations."""

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity levels (aligned with CVSS qualitative ratings)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"



class PhaseStatus(StrEnum):
    """Attack phase execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PTESPhase(StrEnum):
    """PTES methodology phases."""

    RECON = "reconnaissance"
    MAPPING = "service_mapping"
    VULNERABILITY = "vulnerability_testing"
    EXPLOITATION = "exploitation_validation"
    REPORTING = "reporting"



