"""AWS resource scanners."""

from src.scanner.ec2 import scan_ec2
from src.scanner.iam import scan_iam
from src.scanner.s3 import scan_s3

SCANNERS = {
    "iam": scan_iam,
    "s3": scan_s3,
    "ec2": scan_ec2,
}

__all__ = ["SCANNERS", "scan_iam", "scan_s3", "scan_ec2"]
