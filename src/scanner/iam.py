"""IAM scanner: detects overpermissive policies, missing MFA, and stale access keys."""
import json
from datetime import UTC, datetime
from typing import Any

import boto3

from src.models import Finding, FindingType, ResourceType, Severity


def scan_iam(session: boto3.Session | None = None) -> list[Finding]:
    """Run all IAM checks and return findings."""
    client = (session or boto3.Session()).client("iam")
    findings: list[Finding] = []

    findings.extend(_check_wildcard_policies(client))
    findings.extend(_check_users_without_mfa(client))
    findings.extend(_check_stale_access_keys(client))
    findings.extend(_check_overpermissive_roles(client))

    return findings


def _check_wildcard_policies(client: Any) -> list[Finding]:
    """Find IAM policies with Action: * or Resource: *."""
    findings: list[Finding] = []
    paginator = client.get_paginator("list_policies")

    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            arn = policy["Arn"]
            name = policy["PolicyName"]

            version = client.get_policy_version(
                PolicyArn=arn,
                VersionId=policy["DefaultVersionId"],
            )
            document = version["PolicyVersion"]["Document"]

            if isinstance(document, str):
                document = json.loads(document)

            statements = document.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue

                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                has_wildcard_action = "*" in actions
                has_wildcard_resource = "*" in resources

                if has_wildcard_action:
                    findings.append(
                        Finding(
                            resource_type=ResourceType.IAM_POLICY,
                            resource_arn=arn,
                            resource_name=name,
                            finding_type=FindingType.WILDCARD_ACTION,
                            severity=Severity.CRITICAL,
                            title=f"Policy '{name}' grants Action: *",
                            description=(
                                f"IAM policy '{name}' contains a statement with Action: *, "
                                "granting full access to all AWS services. This violates the "
                                "principle of least privilege."
                            ),
                            raw_data={"statement": stmt},
                        )
                    )
                elif has_wildcard_resource and any("*" in a for a in actions):
                    findings.append(
                        Finding(
                            resource_type=ResourceType.IAM_POLICY,
                            resource_arn=arn,
                            resource_name=name,
                            finding_type=FindingType.OVERPERMISSIVE,
                            severity=Severity.HIGH,
                            title=f"Policy '{name}' has wildcard resource with broad actions",
                            description=(
                                f"IAM policy '{name}' grants broad actions on Resource: *, "
                                "which may allow unintended access across the account."
                            ),
                            raw_data={"statement": stmt},
                        )
                    )

    return findings


def _check_users_without_mfa(client: Any) -> list[Finding]:
    """Find IAM users without MFA enabled."""
    findings: list[Finding] = []
    paginator = client.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            arn = user["Arn"]

            mfa_devices = client.list_mfa_devices(UserName=username)
            if not mfa_devices["MFADevices"]:
                findings.append(
                    Finding(
                        resource_type=ResourceType.IAM_USER,
                        resource_arn=arn,
                        resource_name=username,
                        finding_type=FindingType.NO_MFA,
                        severity=Severity.HIGH,
                        title=f"User '{username}' has no MFA enabled",
                        description=(
                            f"IAM user '{username}' does not have multi-factor authentication "
                            "enabled. This increases the risk of unauthorized access if "
                            "credentials are compromised."
                        ),
                        raw_data={"user": user},
                    )
                )

    return findings


def _check_stale_access_keys(
    client: Any, max_age_days: int = 90
) -> list[Finding]:
    """Find access keys older than max_age_days."""
    findings: list[Finding] = []
    now = datetime.now(UTC)
    paginator = client.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = client.list_access_keys(UserName=username)

            for key in keys["AccessKeyMetadata"]:
                create_date = key["CreateDate"]
                if isinstance(create_date, str):
                    create_date = datetime.fromisoformat(create_date)

                age_days = (now - create_date.replace(tzinfo=UTC)).days

                if age_days > max_age_days:
                    findings.append(
                        Finding(
                            resource_type=ResourceType.IAM_ACCESS_KEY,
                            resource_arn=user["Arn"],
                            resource_name=f"{username}/{key['AccessKeyId']}",
                            finding_type=FindingType.UNUSED_ACCESS_KEY,
                            severity=Severity.MEDIUM,
                            title=f"Access key for '{username}' is {age_days} days old",
                            description=(
                                f"Access key {key['AccessKeyId']} for user '{username}' "
                                f"was created {age_days} days ago (threshold: {max_age_days}). "
                                "Stale access keys increase the risk of credential compromise."
                            ),
                            raw_data={
                                "access_key": key,
                                "age_days": age_days,
                            },
                        )
                    )

    return findings


def _check_overpermissive_roles(client: Any) -> list[Finding]:
    """Find IAM roles with overly broad trust policies."""
    findings: list[Finding] = []
    paginator = client.get_paginator("list_roles")

    for page in paginator.paginate():
        for role in page["Roles"]:
            name = role["RoleName"]
            arn = role["Arn"]

            # Skip AWS service-linked roles
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue

            trust_policy = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust_policy, str):
                trust_policy = json.loads(trust_policy)

            for stmt in trust_policy.get("Statement", []):
                principal = stmt.get("Principal", {})

                # Check for wildcard principal
                if principal == "*" or principal.get("AWS") == "*":
                    findings.append(
                        Finding(
                            resource_type=ResourceType.IAM_ROLE,
                            resource_arn=arn,
                            resource_name=name,
                            finding_type=FindingType.OVERPERMISSIVE,
                            severity=Severity.CRITICAL,
                            title=f"Role '{name}' trusts all AWS principals",
                            description=(
                                f"IAM role '{name}' has a trust policy with Principal: *, "
                                "allowing any AWS account to assume it. This is a critical "
                                "security risk."
                            ),
                            raw_data={"trust_policy": trust_policy},
                        )
                    )

    return findings
