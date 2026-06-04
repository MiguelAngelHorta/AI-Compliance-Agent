#!/usr/bin/env bash
# Create a local Kind cluster and install the demo tooling:
#   - Trivy Operator   (runtime vulnerability + misconfig scanning)
#   - kube-prometheus-stack (Prometheus + Grafana)
#   - Prometheus Pushgateway (for CronJob/batch metrics)
#
# Prereqs: docker, kind, kubectl, helm
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-compliance-demo}"

echo "==> Creating Kind cluster '${CLUSTER_NAME}'"
if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "    Cluster already exists, skipping."
else
  kind create cluster --name "${CLUSTER_NAME}" --wait 120s
fi

echo "==> Adding Helm repos"
helm repo add aqua https://aquasecurity.github.io/helm-charts/ >/dev/null
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null
helm repo update >/dev/null

echo "==> Installing Trivy Operator (namespace: trivy-system)"
helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system --create-namespace \
  --set="trivy.ignoreUnfixed=true" \
  --wait

echo "==> Installing kube-prometheus-stack (namespace: monitoring)"
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --set grafana.adminPassword=admin \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --wait

echo "==> Installing Prometheus Pushgateway (namespace: monitoring)"
helm upgrade --install prometheus-pushgateway prometheus-community/prometheus-pushgateway \
  --namespace monitoring \
  --set serviceMonitor.enabled=true \
  --wait

cat <<EOF

✅ Cluster '${CLUSTER_NAME}' is ready.

Next:
  ./scripts/kind-deploy.sh

Access Grafana (user: admin / pass: admin):
  kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80
  open http://localhost:3000

View Trivy vulnerability reports:
  kubectl get vulnerabilityreports -A
  kubectl get configauditreports -A
EOF
