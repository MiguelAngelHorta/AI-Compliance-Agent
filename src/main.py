"""AI Compliance Agent - main entry point."""

import argparse
import json
import os
import sys

from src.models import ScanResult
from src.scanner import SCANNERS


def run_scan(scanners: list[str] | None = None) -> ScanResult:
    """Execute scanners and return aggregated results."""
    result = ScanResult()
    targets = scanners or list(SCANNERS.keys())

    for name in targets:
        if name not in SCANNERS:
            result.errors.append(f"Unknown scanner: {name}")
            continue

        print(f"[*] Running {name} scanner...", file=sys.stderr)
        try:
            findings = SCANNERS[name]()
            result.findings.extend(findings)
            result.scanners_run.append(name)
            print(f"    Found {len(findings)} findings", file=sys.stderr)
        except Exception as e:
            error_msg = f"Scanner '{name}' failed: {e}"
            result.errors.append(error_msg)
            print(f"    ERROR: {e}", file=sys.stderr)

    return result


def run_reason(result: ScanResult, model: str | None = None) -> ScanResult:
    """Send findings to Claude for assessment."""
    from src.reasoner import HAIKU, assess_findings

    model_id = model or HAIKU

    if not result.findings:
        print("[*] No findings to assess", file=sys.stderr)
        return result

    count = len(result.findings)
    print(f"\n[*] Assessing {count} findings with Claude...", file=sys.stderr)
    result.findings = assess_findings(result.findings, model_id=model_id)
    print("[*] Assessment complete", file=sys.stderr)
    return result


def run_actions(
    result: ScanResult,
    dry_run: bool = True,
    github_repo: str = "",
    github_token: str = "",
    mask: bool = True,
) -> ScanResult:
    """Execute actions on assessed findings."""
    from src.actions import execute_actions

    if not result.findings:
        print("[*] No findings to act on", file=sys.stderr)
        return result

    mode = "DRY RUN" if dry_run else "LIVE"
    count = len(result.findings)
    print(f"\n[*] Executing actions ({mode}) on {count} findings...", file=sys.stderr)
    if not mask:
        print("[*] ⚠️  Resource masking DISABLED — real identifiers will be published", file=sys.stderr)

    result.findings = execute_actions(
        result.findings,
        dry_run=dry_run,
        github_repo=github_repo,
        github_token=github_token,
        mask=mask,
    )

    print("[*] Actions complete", file=sys.stderr)
    return result


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AI Security Compliance Agent"
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Run infrastructure scanners",
    )
    parser.add_argument(
        "--reason", action="store_true",
        help="Send findings to Claude for assessment",
    )
    parser.add_argument(
        "--act", action="store_true",
        help="Execute remediation/escalation actions",
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=True,
        help="Preview actions without executing (default: true)",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Execute actions for real (disables dry-run)",
    )
    parser.add_argument(
        "--scanners", nargs="+", choices=list(SCANNERS.keys()),
        help="Specific scanners to run (default: all)",
    )
    parser.add_argument(
        "--model", choices=["haiku", "sonnet"], default="haiku",
        help="Claude model to use (default: haiku)",
    )
    parser.add_argument(
        "--output", choices=["json", "summary"], default="summary",
        help="Output format (default: summary)",
    )
    parser.add_argument(
        "--no-mask", action="store_true",
        help="Do not mask resource identifiers in GitHub escalations "
             "(use only with a private tracker)",
    )

    args = parser.parse_args()

    if not args.scan:
        parser.print_help()
        sys.exit(1)

    import time as _time
    _run_start = _time.monotonic()

    # Phase 1: Scan
    result = run_scan(args.scanners)

    # Phase 2: Reason (optional)
    if args.reason:
        from src.reasoner import HAIKU, SONNET
        model_id = SONNET if args.model == "sonnet" else HAIKU
        result = run_reason(result, model=model_id)

    # Phase 3: Act (optional)
    if args.act:
        dry_run = not args.live
        github_repo = os.environ.get("GITHUB_REPO", "")
        github_token = os.environ.get("GITHUB_TOKEN", "")
        result = run_actions(
            result,
            dry_run=dry_run,
            github_repo=github_repo,
            github_token=github_token,
            mask=not args.no_mask,
        )

    # Phase 4: Metrics (best-effort; no-op unless PUSHGATEWAY_URL is set)
    from src.metrics import push_metrics
    push_metrics(result, _time.monotonic() - _run_start)

    # Output
    if args.output == "json":
        print(json.dumps(result.model_dump(), indent=2, default=str))
    else:
        _print_summary(result)


def _print_summary(result: ScanResult) -> None:
    """Print a human-readable summary."""
    print(f"\n{'=' * 60}")
    print(f"Scan: {result.scan_id}")
    print(f"Scanners: {', '.join(result.scanners_run)}")
    print(f"Findings: {len(result.findings)}")
    print(f"Severity: {result.summary}")
    if result.errors:
        print(f"Errors: {len(result.errors)}")
        for e in result.errors:
            print(f"  - {e}")
    print(f"{'=' * 60}\n")

    for f in result.findings:
        icon = {
            "critical": "🔴", "high": "🟠",
            "medium": "🟡", "low": "🔵", "info": "⚪",
        }.get(f.severity.value, "⚪")

        print(f"{icon} [{f.severity.value.upper()}] {f.title}")
        print(f"   Resource: {f.resource_arn}")
        print(f"   Type: {f.finding_type.value}")
        if f.control_mappings:
            print(f"   Controls: {', '.join(f.control_mappings)}")
        if f.remediation:
            print(f"   Fix: {f.remediation}")
        if f.action_taken and f.action_taken != "none":
            action_icon = {
                "auto_remediated": "✅",
                "issue_created": "🎫",
                "acknowledged": "📋",
                "dry_run": "🔍",
                "skipped": "⏭️",
            }.get(f.action_taken, "❓")
            print(f"   Action: {action_icon} {f.action_taken}")
        if f.claude_reasoning:
            short = f.claude_reasoning[:150]
            print(f"   Reasoning: {short}...")
        print()


if __name__ == "__main__":
    main()
