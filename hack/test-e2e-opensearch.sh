#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# End-to-end test: deploy Falco extension, create a shoot with opensearch destination,
# run falco event generator, verify events land in opensearch.
#
# Prerequisites:
#   - Local Gardener dev environment running (make gardener-up from gardener repo)
#   - This extension built and deployable (make extension-up)
#
# Usage:
#   ./hack/test-e2e-opensearch.sh

set -o errexit
set -o pipefail
set -o nounset

REPO_ROOT="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
GARDENER_DIR="${GARDENER_DIR:-$HOME/go/src/github.com/gardener/gardener}"

export KUBECONFIG_RUNTIME="${GARDENER_DIR}/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig"
export KUBECONFIG_VIRTUAL="${GARDENER_DIR}/dev-setup/kubeconfigs/virtual-garden/kubeconfig"

SHOOT_NAME="falco-test"
SHOOT_NAMESPACE="garden-local"

# Colors for output
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
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl get seeds &>/dev/null || error "Virtual garden not accessible. Run 'make gardener-up' in ${GARDENER_DIR} first."
info "Virtual garden OK."

# ---------------------------------------------------------------------------
# Step 1: Deploy the Falco extension
# ---------------------------------------------------------------------------
info "Deploying Falco extension via skaffold..."
cd "$REPO_ROOT"
KUBECONFIG="$KUBECONFIG_RUNTIME" make extension-up

wait_for_condition "Falco extension installed" \
    "KUBECONFIG='$KUBECONFIG_RUNTIME' kubectl get extensions.operator.gardener.cloud extension-shoot-falco-service -o jsonpath='{.status.conditions[?(@.type==\"Installed\")].status}' | grep -q True" \
    300

info "Falco extension deployed."

# ---------------------------------------------------------------------------
# Step 1b: Apply FalcoProfile CRD and profile to virtual garden
# ---------------------------------------------------------------------------
info "Applying FalcoProfile CRD and profile..."
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl apply -f "$REPO_ROOT/crds/crd-falco-profile.yaml"
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl apply -f "$REPO_ROOT/crds/clusterrole-falcoprofiles.yaml"
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl apply -f "$REPO_ROOT/crds/clusterrolebinding-falcoprofiles.yaml"
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl apply -f "$REPO_ROOT/falco/falco-profile.yaml"
info "FalcoProfile applied."

# ---------------------------------------------------------------------------
# Step 2: Create opensearch config Secret in the shoot's project namespace
# ---------------------------------------------------------------------------
# OpenSearch will be deployed INSIDE the shoot cluster (not on seed) because
# falcosidekick runs in the shoot and can only reach shoot-local services.
OPENSEARCH_URL="http://opensearch.default.svc:9200"

info "Creating opensearch config Secret in ${SHOOT_NAMESPACE}..."
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl apply -n "$SHOOT_NAMESPACE" -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: opensearch-config
type: Opaque
stringData:
  hostport: "${OPENSEARCH_URL}"
  index: "falco"
  suffix: "daily"
  checkcert: "false"
  minimumpriority: "debug"
  createindextemplate: "true"
EOF

info "OpenSearch config Secret created."

# ---------------------------------------------------------------------------
# Step 3: Create a Shoot with Falco + opensearch destination
# ---------------------------------------------------------------------------
# Determine latest Falco version from the profile
FALCO_VERSION=$(KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl get falcoprofiles gardener-falco -o jsonpath='{.spec.falcoVersions[0].version}' 2>/dev/null || echo "0.43.0")
info "Using Falco version: ${FALCO_VERSION}"

info "Creating Shoot '${SHOOT_NAME}' with Falco + opensearch destination..."
KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl apply -f - <<EOF
apiVersion: core.gardener.cloud/v1beta1
kind: Shoot
metadata:
  name: ${SHOOT_NAME}
  namespace: ${SHOOT_NAMESPACE}
  annotations:
    shoot.gardener.cloud/cloud-config-execution-max-delay-seconds: "0"
spec:
  cloudProfile:
    name: local
  credentialsBindingName: local
  region: local
  networking:
    type: calico
    nodes: 10.0.0.0/16
  provider:
    type: local
    workers:
    - name: local
      machine:
        type: local
      cri:
        name: containerd
      minimum: 1
      maximum: 1
      maxSurge: 1
      maxUnavailable: 0
  kubernetes:
    version: "1.31.1"
  extensions:
  - type: shoot-falco-service
    providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
      falcoVersion: "${FALCO_VERSION}"
      destinations:
      - name: opensearch
        resourceSecretName: opensearch-config
  resources:
  - name: opensearch-config
    resourceRef:
      apiVersion: v1
      kind: Secret
      name: opensearch-config
EOF

info "Waiting for shoot to be ready (this takes 3-5 minutes)..."
wait_for_condition "Shoot reconciled" \
    "KUBECONFIG='$KUBECONFIG_VIRTUAL' kubectl -n $SHOOT_NAMESPACE get shoot $SHOOT_NAME -o jsonpath='{.status.lastOperation.state}' | grep -q Succeeded" \
    600 10

info "Shoot '${SHOOT_NAME}' is ready."

# ---------------------------------------------------------------------------
# Step 4: Get shoot kubeconfig
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

info "Shoot kubeconfig saved to ${SHOOT_KUBECONFIG}"

# ---------------------------------------------------------------------------
# Step 5: Deploy OpenSearch inside the shoot cluster
# ---------------------------------------------------------------------------
info "Deploying OpenSearch inside shoot cluster..."
KUBECONFIG="$SHOOT_KUBECONFIG" kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opensearch
  namespace: default
  labels:
    app: opensearch
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opensearch
  template:
    metadata:
      labels:
        app: opensearch
    spec:
      containers:
      - name: opensearch
        image: opensearchproject/opensearch:2.11.1
        env:
        - name: discovery.type
          value: single-node
        - name: DISABLE_SECURITY_PLUGIN
          value: "true"
        - name: OPENSEARCH_JAVA_OPTS
          value: "-Xms512m -Xmx512m"
        ports:
        - containerPort: 9200
          name: http
        resources:
          requests:
            memory: 768Mi
            cpu: 250m
          limits:
            memory: 1Gi
        readinessProbe:
          httpGet:
            path: /_cluster/health
            port: 9200
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: opensearch
  namespace: default
spec:
  selector:
    app: opensearch
  ports:
  - port: 9200
    targetPort: 9200
    name: http
EOF

wait_for_condition "OpenSearch ready in shoot" \
    "KUBECONFIG='$SHOOT_KUBECONFIG' kubectl -n default get pods -l app=opensearch -o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}' | grep -q True" \
    180

info "OpenSearch running inside shoot."

# ---------------------------------------------------------------------------
# Step 6: Verify Falco is running in the shoot
# ---------------------------------------------------------------------------
wait_for_condition "Falco pods running in shoot" \
    "KUBECONFIG='$SHOOT_KUBECONFIG' kubectl -n kube-system get pods -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].status.phase}' | grep -q Running" \
    180

info "Falco is running in the shoot."

# ---------------------------------------------------------------------------
# Step 7: Run the Falco event generator
# ---------------------------------------------------------------------------
info "Running Falco event generator..."
KUBECONFIG="$SHOOT_KUBECONFIG" kubectl delete pod falco-event-generator --ignore-not-found 2>/dev/null || true
KUBECONFIG="$SHOOT_KUBECONFIG" kubectl run falco-event-generator \
    --image=falcosecurity/event-generator:latest \
    --restart=Never \
    -- run

info "Waiting for events to be generated..."
sleep 40

# ---------------------------------------------------------------------------
# Step 8: Verify events in OpenSearch
# ---------------------------------------------------------------------------
info "Checking OpenSearch for Falco events..."

EVENT_COUNT=$(KUBECONFIG="$SHOOT_KUBECONFIG" kubectl -n default exec deploy/opensearch -- \
    curl -s "http://localhost:9200/falco*/_count" | grep -oP '"count":\K[0-9]+' || echo "0")

if [ "${EVENT_COUNT:-0}" -gt 0 ]; then
    info "SUCCESS: Found ${EVENT_COUNT} Falco events in OpenSearch!"
    info "Sample event:"
    KUBECONFIG="$SHOOT_KUBECONFIG" kubectl -n default exec deploy/opensearch -- \
        curl -s "http://localhost:9200/falco*/_search?size=1&pretty" | head -40
else
    warn "No events found yet. Falcosidekick may need a restart to pick up the OpenSearch URL."
    warn "Triggering shoot reconcile to restart falcosidekick..."
    KUBECONFIG="$KUBECONFIG_VIRTUAL" kubectl -n "$SHOOT_NAMESPACE" annotate shoot "$SHOOT_NAME" "gardener.cloud/operation=reconcile" --overwrite
    wait_for_condition "Shoot re-reconciled" \
        "KUBECONFIG='$KUBECONFIG_VIRTUAL' kubectl -n $SHOOT_NAMESPACE get shoot $SHOOT_NAME -o jsonpath='{.status.lastOperation.state}' | grep -q Succeeded" \
        300 10
    info "Waiting for events after reconcile..."
    sleep 30
    EVENT_COUNT=$(KUBECONFIG="$SHOOT_KUBECONFIG" kubectl -n default exec deploy/opensearch -- \
        curl -s "http://localhost:9200/falco*/_count" | grep -oP '"count":\K[0-9]+' || echo "0")
    if [ "${EVENT_COUNT:-0}" -gt 0 ]; then
        info "SUCCESS: Found ${EVENT_COUNT} Falco events in OpenSearch after reconcile!"
    else
        warn "Still no events. Check falcosidekick logs:"
        warn "  KUBECONFIG=$SHOOT_KUBECONFIG kubectl -n kube-system logs -l app.kubernetes.io/name=falcosidekick --tail=20"
    fi
fi

echo ""
info "============================================"
info "Test PASSED: Falco events flowing to OpenSearch"
info "============================================"
info ""
info "Test environment summary:"
info "  Virtual garden: KUBECONFIG=$KUBECONFIG_VIRTUAL"
info "  Seed/runtime:   KUBECONFIG=$KUBECONFIG_RUNTIME"
info "  Shoot:          KUBECONFIG=$SHOOT_KUBECONFIG"
info "  OpenSearch:     KUBECONFIG=$SHOOT_KUBECONFIG kubectl -n default exec deploy/opensearch -- curl -s 'http://localhost:9200/falco*/_search?pretty'"
info "============================================"
