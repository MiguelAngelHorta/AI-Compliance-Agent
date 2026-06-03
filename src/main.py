"""AI Compliance Agent - main entry point."""

import argparse
import json
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


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="AI Security Compliance Agent")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run infrastructure scanners",
    )
    parser.add_argument(
        "--scanners",
        nargs="+",
        choices=list(SCANNERS.keys()),
        help="Specific scanners to run (default: all)",
    )
    parser.add_argument(
        "--output",
        choices=["json", "summary"],
        default="json",
        help="Output format (default: json)",
    )

    args = parser.parse_args()

    if not args.scan:
        parser.print_help()
        sys.exit(1)

    result = run_scan(args.scanners)

    if args.output == "json":
        print(json.dumps(result.model_dump(), indent=2, default=str))
    else:
        print(f"\nScan complete: {result.scan_id}")
        print(f"Scanners run: {', '.join(result.scanners_run)}")
        print(f"Total findings: {len(result.findings)}")
        print(f"Severity breakdown: {result.summary}")
        if result.errors:
            print(f"Errors: {result.errors}")

        print("\nFindings:")
        for f in result.findings:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
                f.severity.value, "⚪"
            )
            print(f"  {icon} [{f.severity.value.upper()}] {f.title}")
            print(f"     Resource: {f.resource_arn}")
            print(f"     Type: {f.finding_type.value}")
            print()


if __name__ == "__main__":
    main()
