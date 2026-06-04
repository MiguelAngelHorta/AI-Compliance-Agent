#!/usr/bin/env bash
# Build the agent image, load it into Kind, install the Helm chart, and
# trigger one run immediately so you don't have to wait for the schedule.
#
# Credentials (LOCAL DEMO ONLY) are read from your shell environment if set:
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, GITHUB_REPO, MASK_SALT
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-compliance-demo}"
IMAGE="compliance-agent:latest"
RELEASE="compliance-agent"
NAMESPACE="${NAMESPACE:-compliance}"
CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/helm/compliance-agent"

echo "==> Building image ${IMAGE}"
docker build -t "${IMAGE}" .

echo "==> Loading image into Kind cluster '${CLUSTER_NAME}'"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

# Assemble optional --set flags for credentials, only if present in the env.
SET_ARGS=()
if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  SET_ARGS+=( --set secret.create=true )
  SET_ARGS+=( --set secret.awsAccessKeyId="${AWS_ACCESS_KEY_ID}" )
  SET_ARGS+=( --set secret.awsSecretAccessKey="${AWS_SECRET_ACCESS_KEY}" )
  SET_ARGS+=( --set secret.maskSalt="${MASK_SALT:-$(openssl rand -hex 16)}" )
else
  echo "    NOTE: no AWS creds in env — agent will run but scanners will fail to auth."
fi
if [[ -n "${GITHUB_TOKEN:-}" && -n "${GITHUB_REPO:-}" ]]; then
  SET_ARGS+=( --set github.enabled=true )
  SET_ARGS+=( --set github.repo="${GITHUB_REPO}" )
  SET_ARGS+=( --set secret.githubToken="${GITHUB_TOKEN}" )
fi

echo "==> Installing Helm release '${RELEASE}' (namespace: ${NAMESPACE})"
helm upgrade --install "${RELEASE}" "${CHART_DIR}" \
  --namespace "${NAMESPACE}" --create-namespace \
  "${SET_ARGS[@]}"

echo "==> Triggering an immediate run"
JOB="${RELEASE}-manual-$(date +%s)"
kubectl create job --from="cronjob/${RELEASE}" "${JOB}" -n "${NAMESPACE}"

echo
echo "Follow logs:"
echo "  kubectl logs -n ${NAMESPACE} -l job-name=${JOB} -f"
