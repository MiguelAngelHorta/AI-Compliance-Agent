"""Agentic actions: auto-remediate, escalate, or alert."""

from __future__ import annotations

import sys
from typing import Any

import boto3
import requests

from src.masking import mask_text
from src.models import Finding, Severity


def execute_actions(
    findings: list[Finding],
    dry_run: bool = True,
    github_repo: str = "",
    github_token: str = "",
    session: boto3.Session | None = None,
    mask: bool = True,
) -> list[Finding]:
    """Execute remediation or escalation for each assessed finding.

    When ``mask`` is True (the default), resource identifiers are masked in any
    content sent to GitHub Issues. Disable only when escalating to a private
    tracker where exposing real names is acceptable.
    """
    for i, finding in enumerate(findings):
        print(f"  [{i + 1}/{len(findings)}] {finding.title}", file=sys.stderr)

        if finding.severity == Severity.CRITICAL:
            _escalate(finding, dry_run, github_repo, github_token, mask)
        elif finding.severity in (Severity.HIGH, Severity.MEDIUM):
            _auto_remediate_if_safe(finding, dry_run, session)
        elif finding.severity == Severity.LOW:
            _log_acknowledged(finding, dry_run)

    return findings


def _auto_remediate_if_safe(
    finding: Finding,
    dry_run: bool,
    session: boto3.Session | None = None,
) -> None:
    """Auto-remediate findings that have safe, reversible fixes."""
    remediation_map: dict[str, Any] = {
        "no_versioning": _remediate_versioning,
        "unencrypted": _remediate_encryption,
    }

    action_fn = remediation_map.get(finding.finding_type.value)
    if not action_fn:
        print(f"    ⏭️  No auto-remediation available for {finding.finding_type.value}", file=sys.stderr)
        finding.action_taken = "skipped"
        return

    if dry_run:
        print(f"    🔍 [DRY RUN] Would auto-remediate: {finding.finding_type.value}", file=sys.stderr)
        finding.action_taken = "dry_run"
        return

    try:
        action_fn(finding, session)
        finding.action_taken = "auto_remediated"
        finding.status = "remediated"
        print(f"    ✅ Auto-remediated: {finding.finding_type.value}", file=sys.stderr)
    except Exception as e:
        print(f"    ❌ Remediation failed: {e}", file=sys.stderr)
        finding.action_taken = "failed"
        finding.action_details = {"error": str(e)}


def _escalate(
    finding: Finding,
    dry_run: bool,
    github_repo: str,
    github_token: str,
    mask: bool = True,
) -> None:
    """Escalate high/critical findings to GitHub Issues."""
    if not github_repo or not github_token:
        print(f"    ⚠️  [{finding.severity.value.upper()}] No GitHub config — skipping escalation", file=sys.stderr)
        finding.action_taken = "skipped_no_config"
        return

    # Mask resource identifiers in anything published to (potentially public)
    # GitHub Issues. Local console output elsewhere stays unmasked.
    # Mask the resource name and the ARN's identifying tail (not the whole ARN),
    # so the ARN skeleton (arn:aws:s3:::<masked>) survives for triage.
    arn = finding.resource_arn
    if ":::" in arn:
        arn_tail = arn.split(":::", 1)[1]
    elif "/" in arn:
        arn_tail = arn.rsplit("/", 1)[1]
    else:
        arn_tail = ""
    names = tuple(n for n in (finding.resource_name, arn_tail) if n)

    def m(text: str) -> str:
        return mask_text(text, names) if mask else text

    title = f"[{finding.severity.value.upper()}] {m(finding.title)}"

    controls_str = ", ".join(finding.control_mappings) if finding.control_mappings else "Not yet assessed"

    body = (
        f"## Security Finding\n\n"
        f"**Severity:** {finding.severity.value.upper()}\n"
        f"**Resource:** `{m(finding.resource_arn)}`\n"
        f"**Type:** {finding.finding_type.value}\n\n"
        f"## Description\n\n{m(finding.description)}\n\n"
        f"## Controls Violated\n\n{controls_str}\n\n"
        f"## Recommended Remediation\n\n{m(finding.remediation) or 'See Claude reasoning below.'}\n\n"
        f"## Claude Reasoning\n\n{m(finding.claude_reasoning) or 'Not yet assessed.'}\n\n"
        f"---\n*Created automatically by AI Compliance Agent*"
    )

    labels = [finding.severity.value, "compliance", finding.finding_type.value]

    if dry_run:
        print(f"    🔍 [DRY RUN] Would create GitHub issue: {title}", file=sys.stderr)
        print(f"         Labels: {labels}", file=sys.stderr)
        finding.action_taken = "dry_run"
        return

    try:
        url = f"https://api.github.com/repos/{github_repo}/issues"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        data = {"title": title, "body": body, "labels": labels}

        response = requests.post(url, headers=headers, json=data, timeout=10)
        response.raise_for_status()

        issue = response.json()
        issue_url = issue.get("html_url", "")
        print(f"    🎫 Created issue: {issue_url}", file=sys.stderr)
        finding.action_taken = "issue_created"
        finding.action_details = {"issue_url": issue_url, "issue_number": issue.get("number")}
        finding.status = "escalated"

    except Exception as e:
        print(f"    ❌ Failed to create issue: {e}", file=sys.stderr)
        finding.action_taken = "escalation_failed"
        finding.action_details = {"error": str(e)}


def _log_acknowledged(finding: Finding, dry_run: bool) -> None:
    """Acknowledge low-severity findings without action."""
    if dry_run:
        print(f"    🔍 [DRY RUN] Would acknowledge: {finding.finding_type.value}", file=sys.stderr)
    else:
        print(f"    📋 Acknowledged: {finding.finding_type.value}", file=sys.stderr)
    finding.action_taken = "acknowledged"
    finding.status = "acknowledged"


# --- Remediation Functions ---


def _remediate_versioning(finding: Finding, session: boto3.Session | None = None) -> None:
    """Enable versioning on an S3 bucket."""
    bucket_name = finding.resource_name
    client = (session or boto3.Session()).client("s3", verify=False)
    client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )


def _remediate_encryption(finding: Finding, session: boto3.Session | None = None) -> None:
    """Enable default encryption on an S3 bucket."""
    bucket_name = finding.resource_name
    client = (session or boto3.Session()).client("s3", verify=False)
    client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    },
                }
            ]
        },
    )
