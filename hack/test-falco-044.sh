#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# Test Falco 0.44.0 + falcosidekick 2.34.0 on existing local Gardener environment.
#
# Prerequisites:
#   - Local Gardener dev environment running
#   - Existing shoot 'falco-test' or will create one
#
# Usage:
#   ./hack/test-falco-044.sh

set -o errexit
set -o pipefail
set -o nounset

REPO_ROOT="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
GARDENER_DIR="${GARDENER_DIR:-$HOME/go/src/github.com/gardener/gardener}"

export KUBECONFIG_RUNTIME="${GARDENER_DIR}/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig"
export KUBECONFIG_VIRTUAL="${GARDENER_DIR}/dev-setup/kubeconfigs/virtual-garden/kubeconfig"

SHOOT_NAME="falco-test"
SHOOT_NAMESPACE="garden-local"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

wait_for_condition() {
    local description="$1"
    local check_cmd="$2"
    local timeout="${3:-300}"
    local interval="${4:-5}"

    info "Waiting for: ${description} (timeout: ${timeout}s)"
    local elapsed=0
    while ! eval "$check_cmd" &>/dev/null; do
        if [ "$elapsed" -ge "$timeout" ]; then
            error "Timeout waiting for: ${description}"
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    info "Done: ${description}"
}

# ---------------------------------------------------------------------------
# Step 0: Verify Gardener is running
# ---------------------------------------------------------------------------
info "Verifying Gardener virtual garden is accessible..."
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl get seeds &>/dev/null || error "Virtual garden not accessible."
info "Virtual garden OK."

# ---------------------------------------------------------------------------
# Step 1: Redeploy extension with Falco 0.44.0 support
# ---------------------------------------------------------------------------
info "Redeploying Falco extension with 0.44.0 support..."
cd "$REPO_ROOT"
KUBECONFIG="$KUBECONFIG_RUNTIME" make extension-up

wait_for_condition "Falco extension ready" \
    "KUBECONFIG='$KUBECONFIG_RUNTIME' kubectl get extensions.operator.gardener.cloud extension-shoot-falco-service -o jsonpath='{.status.conditions[?(@.type==\"Installed\")].status}' | grep -q True" \
    300

info "Extension redeployed."

# ---------------------------------------------------------------------------
# Step 2: Update FalcoProfile with 0.44.0
# ---------------------------------------------------------------------------
info "Applying updated FalcoProfile..."
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl apply -f "$REPO_ROOT/falco/falco-profile.yaml"
info "FalcoProfile updated."

# ---------------------------------------------------------------------------
# Step 3: Update shoot to Falco 0.44.0
# ---------------------------------------------------------------------------
info "Patching shoot '${SHOOT_NAME}' to Falco 0.44.0..."

# Check if shoot exists
if ! KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl -n "$SHOOT_NAMESPACE" get shoot "$SHOOT_NAME" &>/dev/null; then
    error "Shoot '${SHOOT_NAME}' does not exist. Run hack/test-e2e-opensearch.sh first to create it."
fi

KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl -n "$SHOOT_NAMESPACE" patch shoot "$SHOOT_NAME" --type=merge -p '{
  "spec": {
    "extensions": [
      {
        "type": "shoot-falco-service",
        "providerConfig": {
          "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
          "kind": "FalcoServiceConfig",
          "falcoVersion": "0.44.0",
          "destinations": [
            {
              "name": "opensearch",
              "resourceSecretName": "opensearch-config"
            }
          ]
        }
      }
    ]
  }
}'

# Trigger reconcile
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl -n "$SHOOT_NAMESPACE" annotate shoot "$SHOOT_NAME" "gardener.cloud/operation=reconcile" --overwrite

info "Waiting for shoot reconcile..."
wait_for_condition "Shoot reconciled with Falco 0.44.0" \
    "KUBECONFIG='$KUBECONFIG_VIRTUAL' kubectl -n $SHOOT_NAMESPACE get shoot $SHOOT_NAME -o jsonpath='{.status.lastOperation.state}' | grep -q Succeeded" \
    600 10

info "Shoot reconciled."

# ---------------------------------------------------------------------------
# Step 4: Get shoot kubeconfig and verify Falco version
# ---------------------------------------------------------------------------
info "Retrieving shoot kubeconfig..."
SHOOT_KUBECONFIG="/tmp/${SHOOT_NAME}-kubeconfig"
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl create -f - --raw "/apis/core.gardener.cloud/v1beta1/namespaces/${SHOOT_NAMESPACE}/shoots/${SHOOT_NAME}/adminkubeconfig" <<'ADMINREQ' 2>/dev/null | python3 -c "import sys, json, base64; data = json.load(sys.stdin); print(base64.b64decode(data['status']['kubeconfig']).decode())" > "$SHOOT_KUBECONFIG"
{
  "apiVersion": "authentication.gardener.cloud/v1alpha1",
  "kind": "AdminKubeconfigRequest",
  "spec": {
    "expirationSeconds": 86400
  }
}
ADMINREQ

wait_for_condition "Falco pods running" \
    "KUBECONFIG='$SHOOT_KUBECONFIG' kubectl -n kube-system get pods -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].status.phase}' | grep -q Running" \
    180

# Verify it's actually 0.44.0
FALCO_IMAGE=$(KUBECONFIG="$SHOOT_KUBECONFIG" kubectl -n kube-system get pods -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null)
info "Falco image: ${FALCO_IMAGE}"

if echo "$FALCO_IMAGE" | grep -q "0.44.0"; then
    info "VERIFIED: Falco 0.44.0 is running!"
else
    warn "Unexpected Falco image: ${FALCO_IMAGE}"
fi

# Check falcosidekick version
SIDEKICK_IMAGE=$(KUBECONFIG="$SHOOT_KUBECONFIG" kubectl -n kube-system get pods -l app.kubernetes.io/name=falcosidekick -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null)
info "Falcosidekick image: ${SIDEKICK_IMAGE}"

# ---------------------------------------------------------------------------
# Step 5: Run event generator and verify events
# ---------------------------------------------------------------------------
info "Running Falco event generator..."
KUBECONFIG="$SHOOT_KUBECONFIG" kubectl delete pod falco-event-generator --ignore-not-found 2>/dev/null || true
KUBECONFIG="$SHOOT_KUBECONFIG" kubectl run falco-event-generator \
    --image=falcosecurity/event-generator:latest \
    --restart=Never \
    -- run

info "Waiting for events to generate..."
sleep 40

# Check OpenSearch for events with falco_version 0.44.0
EVENT_COUNT=$(KUBECONFIG="$SHOOT_KUBECONFIG" kubectl -n default exec deploy/opensearch -- \
    curl -s "http://localhost:9200/falco*/_count" 2>/dev/null | grep -oP '"count":\K[0-9]+' || echo "0")

if [ "${EVENT_COUNT:-0}" -gt 0 ]; then
    info "SUCCESS: Found ${EVENT_COUNT} Falco events in OpenSearch!"

    # Verify events have falco_version 0.44.0
    HAS_044=$(KUBECONFIG="$SHOOT_KUBECONFIG" kubectl -n default exec deploy/opensearch -- \
        curl -s 'http://localhost:9200/falco*/_search' -H 'Content-Type: application/json' \
        -d '{"query":{"match":{"output_fields.falco_version":"0.44.0"}},"size":1}' 2>/dev/null | grep -oP '"total":\{"value":\K[0-9]+' || echo "0")

    if [ "${HAS_044:-0}" -gt 0 ]; then
        info "VERIFIED: Events with falco_version=0.44.0 found in OpenSearch!"
    else
        warn "Events exist but none with falco_version=0.44.0 yet (may be cached from previous version)"
    fi
else
    warn "No events in OpenSearch. Check falcosidekick logs."
fi

echo ""
info "============================================"
info "Falco 0.44.0 test complete"
info "  Falco image:        ${FALCO_IMAGE}"
info "  Falcosidekick image: ${SIDEKICK_IMAGE}"
info "  Events in OpenSearch: ${EVENT_COUNT:-0}"
info "============================================"
