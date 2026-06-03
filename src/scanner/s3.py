"""S3 scanner: detects unencrypted buckets, public access, missing versioning/logging."""
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.models import Finding, FindingType, ResourceType, Severity


def scan_s3(session: boto3.Session | None = None) -> list[Finding]:
    """Run all S3 checks and return findings."""
    client = (session or boto3.Session()).client("s3")
    findings: list[Finding] = []

    buckets = client.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"

        findings.extend(_check_encryption(client, name, arn))
        findings.extend(_check_public_access(client, name, arn))
        findings.extend(_check_versioning(client, name, arn))
        findings.extend(_check_logging(client, name, arn))

    return findings


def _check_encryption(client: Any, name: str, arn: str) -> list[Finding]:
    """Check if default encryption is enabled."""
    findings: list[Finding] = []
    try:
        client.get_bucket_encryption(Bucket=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(
                Finding(
                    resource_type=ResourceType.S3_BUCKET,
                    resource_arn=arn,
                    resource_name=name,
                    finding_type=FindingType.UNENCRYPTED,
                    severity=Severity.HIGH,
                    title=f"Bucket '{name}' has no default encryption",
                    description=(
                        f"S3 bucket '{name}' does not have default server-side encryption "
                        "enabled. Data stored in this bucket is not encrypted at rest."
                    ),
                    raw_data={"bucket": name},
                )
            )
    return findings


def _check_public_access(client: Any, name: str, arn: str) -> list[Finding]:
    """Check if Block Public Access is enabled."""
    findings: list[Finding] = []
    try:
        config = client.get_public_access_block(Bucket=name)
        block = config["PublicAccessBlockConfiguration"]

        all_blocked = all([
            block.get("BlockPublicAcls", False),
            block.get("IgnorePublicAcls", False),
            block.get("BlockPublicPolicy", False),
            block.get("RestrictPublicBuckets", False),
        ])

        if not all_blocked:
            findings.append(
                Finding(
                    resource_type=ResourceType.S3_BUCKET,
                    resource_arn=arn,
                    resource_name=name,
                    finding_type=FindingType.PUBLIC_ACCESS,
                    severity=Severity.CRITICAL,
                    title=f"Bucket '{name}' does not fully block public access",
                    description=(
                        f"S3 bucket '{name}' has incomplete Block Public Access settings. "
                        "This could allow unintended public access to bucket contents."
                    ),
                    raw_data={"public_access_block": block},
                )
            )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append(
                Finding(
                    resource_type=ResourceType.S3_BUCKET,
                    resource_arn=arn,
                    resource_name=name,
                    finding_type=FindingType.PUBLIC_ACCESS,
                    severity=Severity.CRITICAL,
                    title=f"Bucket '{name}' has no Block Public Access configuration",
                    description=(
                        f"S3 bucket '{name}' has no Block Public Access configuration at all. "
                        "The bucket may be publicly accessible."
                    ),
                    raw_data={"bucket": name},
                )
            )
    return findings


def _check_versioning(client: Any, name: str, arn: str) -> list[Finding]:
    """Check if versioning is enabled."""
    findings: list[Finding] = []
    versioning = client.get_bucket_versioning(Bucket=name)

    if versioning.get("Status") != "Enabled":
        findings.append(
            Finding(
                resource_type=ResourceType.S3_BUCKET,
                resource_arn=arn,
                resource_name=name,
                finding_type=FindingType.NO_VERSIONING,
                severity=Severity.MEDIUM,
                title=f"Bucket '{name}' does not have versioning enabled",
                description=(
                    f"S3 bucket '{name}' does not have versioning enabled. Without versioning, "
                    "deleted or overwritten objects cannot be recovered."
                ),
                raw_data={"versioning": versioning},
            )
        )
    return findings


def _check_logging(client: Any, name: str, arn: str) -> list[Finding]:
    """Check if server access logging is enabled."""
    findings: list[Finding] = []
    logging_config = client.get_bucket_logging(Bucket=name)

    if "LoggingEnabled" not in logging_config:
        findings.append(
            Finding(
                resource_type=ResourceType.S3_BUCKET,
                resource_arn=arn,
                resource_name=name,
                finding_type=FindingType.NO_LOGGING,
                severity=Severity.LOW,
                title=f"Bucket '{name}' has no access logging",
                description=(
                    f"S3 bucket '{name}' does not have server access logging enabled. "
                    "Access logging provides records of requests made to the bucket."
                ),
                raw_data={"bucket": name},
            )
        )
    return findings
