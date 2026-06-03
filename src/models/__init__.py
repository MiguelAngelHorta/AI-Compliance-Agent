"""Data models for compliance findings."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Risk severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResourceType(StrEnum):
    """AWS resource types that can be scanned."""

    IAM_POLICY = "iam_policy"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_ACCESS_KEY = "iam_access_key"
    S3_BUCKET = "s3_bucket"
    SECURITY_GROUP = "security_group"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"


class FindingType(StrEnum):
    """Types of compliance findings."""

    OVERPERMISSIVE = "overpermissive"
    UNENCRYPTED = "unencrypted"
    PUBLIC_ACCESS = "public_access"
    NO_MFA = "no_mfa"
    UNUSED_ACCESS_KEY = "unused_access_key"
    DEPRECATED_RUNTIME = "deprecated_runtime"
    NO_VERSIONING = "no_versioning"
    NO_LOGGING = "no_logging"
    NO_BACKUP = "no_backup"
    WILDCARD_ACTION = "wildcard_action"
    OPEN_PORT = "open_port"


class Finding(BaseModel):
    """A single compliance finding from a scan."""

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    resource_type: ResourceType
    resource_arn: str
    resource_name: str = ""
    finding_type: FindingType
    severity: Severity
    title: str
    description: str
    raw_data: dict = Field(default_factory=dict)  # type: ignore[assignment]

    # Populated after Claude reasoning (Phase 2)
    control_mappings: list[str] = Field(default_factory=list)
    claude_reasoning: str = ""
    remediation: str = ""
    action_taken: str = "none"
    action_details: dict = Field(default_factory=dict)  # type: ignore[assignment]
    status: str = "open"


class ScanResult(BaseModel):
    """Aggregated results from a full scan."""

    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    findings: list[Finding] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
