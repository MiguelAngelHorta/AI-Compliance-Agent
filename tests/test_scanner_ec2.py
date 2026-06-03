"""Tests for the EC2 scanner."""

from moto import mock_aws

from src.models import FindingType, Severity
from src.scanner.ec2 import scan_ec2


@mock_aws
def test_detects_ssh_open_to_world(aws_session):
    """Security groups with SSH open to 0.0.0.0/0 should be flagged."""
    client = aws_session.client("ec2")

    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = client.create_security_group(
        GroupName="open-ssh",
        Description="SSH open to world",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "FromPort": 22,
            "ToPort": 22,
            "IpProtocol": "tcp",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    findings = scan_ec2(aws_session)

    ssh_findings = [
        f for f in findings
        if f.finding_type == FindingType.OPEN_PORT and "SSH" in f.title
    ]
    assert len(ssh_findings) >= 1
    assert ssh_findings[0].severity == Severity.HIGH


@mock_aws
def test_detects_all_ports_open(aws_session):
    """Security groups with all ports open should be flagged as critical."""
    client = aws_session.client("ec2")

    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = client.create_security_group(
        GroupName="all-open",
        Description="All ports open",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "FromPort": 0,
            "ToPort": 65535,
            "IpProtocol": "tcp",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    findings = scan_ec2(aws_session)

    all_port_findings = [
        f for f in findings
        if f.finding_type == FindingType.OPEN_PORT and "all ports" in f.title
    ]
    assert len(all_port_findings) >= 1
    assert all_port_findings[0].severity == Severity.CRITICAL


@mock_aws
def test_private_sg_no_findings(aws_session):
    """Security groups restricted to private IPs should not generate findings."""
    client = aws_session.client("ec2")

    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    sg = client.create_security_group(
        GroupName="private-only",
        Description="Private access only",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "FromPort": 22,
            "ToPort": 22,
            "IpProtocol": "tcp",
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
        }],
    )

    findings = scan_ec2(aws_session)

    sg_findings = [
        f for f in findings
        if "private-only" in f.resource_name
    ]
    assert len(sg_findings) == 0
