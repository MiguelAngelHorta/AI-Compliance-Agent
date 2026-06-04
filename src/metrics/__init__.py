"""Best-effort push of run metrics to a Prometheus Pushgateway.

Active only when PUSHGATEWAY_URL is set in the environment (the Helm chart wires
this when metrics.enabled=true). Any failure here is swallowed — metrics must
never affect the agent run itself.
"""

from __future__ import annotations

import os
import sys
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.models import ScanResult

JOB_NAME = "compliance-agent"


def push_metrics(result: ScanResult, duration_seconds: float, job: str = JOB_NAME) -> None:
    """Push last-run metrics to $PUSHGATEWAY_URL. No-op if the var is unset."""
    url = os.environ.get("PUSHGATEWAY_URL")
    if not url:
        return

    try:
        from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
    except ImportError:
        print("[metrics] prometheus_client not installed; skipping push", file=sys.stderr)
        return

    try:
        registry = CollectorRegistry()

        g_by_severity = Gauge(
            "compliance_findings_by_severity",
            "Findings from the most recent scan, by severity",
            ["severity"],
            registry=registry,
        )
        g_by_action = Gauge(
            "compliance_findings_by_action",
            "Findings from the most recent run, by action taken",
            ["action"],
            registry=registry,
        )
        g_total = Gauge(
            "compliance_findings_total",
            "Total findings from the most recent scan",
            registry=registry,
        )
        g_duration = Gauge(
            "compliance_scan_duration_seconds",
            "Duration of the most recent run in seconds",
            registry=registry,
        )
        g_last_run = Gauge(
            "compliance_last_run_timestamp_seconds",
            "Unix timestamp of the most recent run",
            registry=registry,
        )

        sev_counts: dict[str, int] = {}
        act_counts: dict[str, int] = {}
        for f in result.findings:
            sev = f.severity.value
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            act = f.action_taken or "none"
            act_counts[act] = act_counts.get(act, 0) + 1

        for severity, count in sev_counts.items():
            g_by_severity.labels(severity=severity).set(count)
        for action, count in act_counts.items():
            g_by_action.labels(action=action).set(count)

        g_total.set(len(result.findings))
        g_duration.set(duration_seconds)
        g_last_run.set(time.time())

        push_to_gateway(url, job=job, registry=registry)
        print(f"[metrics] pushed {len(result.findings)} findings to {url}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001 — metrics must never break the run
        print(f"[metrics] push failed (non-fatal): {e}", file=sys.stderr)
