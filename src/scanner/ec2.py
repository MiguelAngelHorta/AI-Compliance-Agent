"""EC2 scanner: detects overly permissive security groups."""
from typing import Any

import boto3

from src.models import Finding, FindingType, ResourceType, Severity

# Ports that should never be open to 0.0.0.0/0
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana",
}


def scan_ec2(session: boto3.Session | None = None) -> list[Finding]:
    """Run all EC2 checks and return findings."""
    client = (session or boto3.Session()).client("ec2")
    findings: list[Finding] = []

    findings.extend(_check_security_groups(client))

    return findings


def _check_security_groups(client: Any) -> list[Finding]:
    """Find security groups with 0.0.0.0/0 on sensitive ports."""
    findings: list[Finding] = []
    paginator = client.get_paginator("describe_security_groups")

    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            arn = f"arn:aws:ec2:*:*:security-group/{sg_id}"

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)

                # Check IPv4 ranges
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        findings.extend(
                            _evaluate_open_rule(
                                sg_name, sg_id, arn, from_port, to_port, cidr, rule
                            )
                        )

                # Check IPv6 ranges
                for ip_range in rule.get("Ipv6Ranges", []):
                    cidr = ip_range.get("CidrIpv6", "")
                    if cidr == "::/0":
                        findings.extend(
                            _evaluate_open_rule(
                                sg_name, sg_id, arn, from_port, to_port, cidr, rule
                            )
                        )

    return findings


def _evaluate_open_rule(
    sg_name: str,
    sg_id: str,
    arn: str,
    from_port: int,
    to_port: int,
    cidr: str,
    rule: dict[str, object],
) -> list[Finding]:
    """Evaluate a single open security group rule."""
    findings: list[Finding] = []

    # All ports open
    if from_port == 0 and to_port == 65535:
        findings.append(
            Finding(
                resource_type=ResourceType.SECURITY_GROUP,
                resource_arn=arn,
                resource_name=f"{sg_name} ({sg_id})",
                finding_type=FindingType.OPEN_PORT,
                severity=Severity.CRITICAL,
                title=f"Security group '{sg_name}' allows all ports from {cidr}",
                description=(
                    f"Security group '{sg_name}' ({sg_id}) allows inbound traffic on "
                    f"all ports (0-65535) from {cidr}. This exposes all services to the internet."
                ),
                raw_data={"rule": rule, "security_group_id": sg_id},
            )
        )
        return findings

    # Check each sensitive port
    for port, service in SENSITIVE_PORTS.items():
        if from_port <= port <= to_port:
            findings.append(
                Finding(
                    resource_type=ResourceType.SECURITY_GROUP,
                    resource_arn=arn,
                    resource_name=f"{sg_name} ({sg_id})",
                    finding_type=FindingType.OPEN_PORT,
                    severity=Severity.HIGH,
                    title=f"Security group '{sg_name}' exposes {service} (port {port}) to {cidr}",
                    description=(
                        f"Security group '{sg_name}' ({sg_id}) allows inbound traffic on "
                        f"port {port} ({service}) from {cidr}. This service should not be "
                        "directly accessible from the internet."
                    ),
                    raw_data={"rule": rule, "port": port, "service": service},
                )
            )

    return findings
