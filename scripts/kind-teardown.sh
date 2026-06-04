#!/usr/bin/env bash
# Tear down the local demo cluster.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-compliance-demo}"

echo "==> Deleting Kind cluster '${CLUSTER_NAME}'"
kind delete cluster --name "${CLUSTER_NAME}"
echo "✅ Done."
