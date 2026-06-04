# Phase 4 — Metrics & Grafana

Wires the agent's run results into the Prometheus/Grafana stack via Pushgateway.

## 1. Apply the code changes

From the repo root:

```bash
python3 patches/apply_metrics.py
```

This (idempotently):
- adds a metrics push to `src/main.py` (after the act phase),
- adds `prometheus-client` to `pyproject.toml`.

It also expects the new module `src/metrics/__init__.py` (included).

## 2. Rebuild & redeploy with metrics enabled

The Pushgateway was installed by `kind-setup.sh` at
`http://prometheus-pushgateway.monitoring:9091`.

```bash
docker build -t compliance-agent:latest .
kind load docker-image compliance-agent:latest --name compliance-demo

helm upgrade --install compliance-agent ./helm/compliance-agent \
  --namespace compliance \
  --set metrics.enabled=true \
  --set metrics.pushgatewayUrl=http://prometheus-pushgateway.monitoring:9091 \
  --reuse-values
```

Trigger a run (name-agnostic):

```bash
kubectl create job --from=cronjob/$(kubectl get cronjob -n compliance -o jsonpath='{.items[0].metadata.name}') run-metrics -n compliance
kubectl logs -n compliance -l job-name=run-metrics | grep metrics
```

You should see: `[metrics] pushed N findings to http://prometheus-pushgateway...`

## 3. Confirm metrics landed

```bash
kubectl port-forward -n monitoring svc/prometheus-pushgateway 9091:9091
```

Open http://localhost:9091 — you should see the `compliance_*` metrics under job `compliance-agent`.

## 4. Import the Grafana dashboard

```bash
kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80
```

Open http://localhost:3000 (admin / admin), then **Dashboards → New → Import**,
upload `monitoring/grafana-dashboard.json`, and select the **Prometheus**
datasource when prompted.

Optional — auto-provision instead of manual import (kube-prometheus-stack's
sidecar watches for labeled ConfigMaps):

```bash
kubectl create configmap compliance-dashboard -n monitoring \
  --from-file=compliance-agent.json=monitoring/grafana-dashboard.json
kubectl label configmap compliance-dashboard -n monitoring grafana_dashboard=1
```

The dashboard appears under Dashboards within ~1 minute.

## Metrics exposed

| Metric | Type | Labels |
|---|---|---|
| `compliance_findings_total` | gauge | — |
| `compliance_findings_by_severity` | gauge | `severity` |
| `compliance_findings_by_action` | gauge | `action` |
| `compliance_scan_duration_seconds` | gauge | — |
| `compliance_last_run_timestamp_seconds` | gauge | — |
