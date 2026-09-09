---
name: run-seed-garden-harness
description: Manual end-to-end harness for deploying and verifying Falco on seed and garden clusters in a local Gardener dev environment
---

# Run Seed/Garden Harness

Run the integration tests for the Falco shoot extension against a local Gardener dev environment.

## IMPORTANT: Read the official docs first

Before doing anything with the local setup, read the Gardener local setup documentation:

```
../gardener/docs/deployment/getting_started_locally.md
```

This is authoritative. Do not guess or improvise — the local setup is sensitive to ordering and uses specific make targets. Getting them wrong leads to subtle failures (DNS not configured, registry unreachable, CoreDNS not patched, etc.) that are hard to debug.

## Prerequisites

- `../gardener` sibling directory checked out
- Docker running with sufficient resources (≥8 CPUs, ≥8Gi RAM, ≥120Gi disk)
- `gcloud auth login` completed (images pulled from `europe-docker.pkg.dev`)

## Setting up the local dev environment

```bash
hack/local_setup.sh
```

This script does exactly what the Gardener local setup docs describe:

1. `cd ../gardener && make kind-up` — creates kind cluster + local registry + DNS/loopback
2. `make gardener-up` — deploys operator, garden CR, gardenlet/seed (all in one)
3. Applies Falco CRDs + FalcoProfile to the virtual garden cluster
4. `hack/local-setup/generate-operator-extension-resource.sh` — regenerates the operator Extension resource from `imagevector/images.yaml`
5. `make extension-up` — builds and deploys the Falco extension via skaffold

**Kubeconfigs** (relative to `../gardener`):

| Purpose | Path |
|---------|------|
| Runtime cluster (for `make extension-up`) | `dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig` |
| Runtime cluster (direct kubectl access) | `dev-setup/kubeconfigs/seed-local/kubeconfig` |
| Virtual garden | `dev-setup/kubeconfigs/virtual-garden/kubeconfig` |

## CRITICAL: Always regenerate operator-extension-resource.yaml before deploying

`hack/local-setup/operator-extension-resource.yaml` is **generated** — do not edit it by hand. Regenerate it from the template whenever `imagevector/images.yaml` changes:

```bash
hack/local-setup/generate-operator-extension-resource.sh
```

This reads `imagevector/images.yaml`, builds the `imageVectorOverwrite` block with correct mirror URLs for all images, and writes the YAML. Run it before every `make extension-up` call.

The generated file contains bare `local-skaffold/...` image refs as placeholders. Skaffold rewrites these to fully-qualified `registry.local.gardener.cloud:5001/...@sha256:...` refs when it deploys.

**Never** run `kubectl apply -f hack/local-setup/operator-extension-resource.yaml` directly. Always use `make extension-up`, which runs skaffold and injects the correct resolved refs. Manually applying the file breaks the Extension resource with unresolvable refs, causing `ControllerInstallation` failures and the shoot reconciliation to hang at 0%.

If you accidentally apply it manually, fix it by running `make extension-up` again.

## Creating a shoot

After `local_setup.sh` completes, create a shoot using the Gardener example (not the Extension resource file):

```bash
GARDEN_KC="../gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig"
kubectl --kubeconfig "${GARDEN_KC}" apply -f ../gardener/example/provider-local/shoot.yaml
```

Then wait for the shoot to be ready:

```bash
kubectl --kubeconfig "${GARDEN_KC}" -n garden-local get shoot local -w
```

The shoot is ready when `lastOperation.state == Succeeded`.

## Running the tests

```bash
REPO_ROOT=$(git rev-parse --show-toplevel)
GARDEN_KC="${REPO_ROOT}/../gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig"
test/integration/falco-integration.sh "${GARDEN_KC}" garden-local local
```

## Running a single test

```bash
REPO_ROOT=$(git rev-parse --show-toplevel)
GARDEN_KC="${REPO_ROOT}/../gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig"
cd test/integration
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest test_falco.py::test_cluster_purpose \
  --garden-kubeconfig "${GARDEN_KC}" \
  --project-namespace garden-local \
  --shoot-name local
```

## Tearing down

```bash
cd ../gardener && make kind-down
```

`make kind-down` deletes the kind cluster, stops all infra containers (registry, DNS, load balancers), and removes the `infra_bind9-zones` Docker volume. It will print `Permission denied` errors for backup bucket files owned by root — clean those manually:

```bash
sudo rm -rf ../gardener/dev/local-backupbuckets/
```

Then prune all Docker volumes to reclaim disk space (the registry cache volumes are large — 20-25 GB):

```bash
docker container prune -f
docker volume prune -f --all
```

Verify disk is reclaimed:

```bash
docker system df
```

Expected after teardown: Local Volumes = 0B, no running containers.

## What the tests verify

- `test_falco_deployment` — basic deployment with custom rules and event routing
- `test_falco_deployment_with_all_rules` — all standard rule sets loaded
- `test_all_falco_versions` — cycles through every version in the FalcoProfile
- `test_event_generator` — end-to-end: generate a security event and verify it reaches Loki
- `test_no_output` — stdout-only mode (no falcosidekick)
- `test_node_selector` — DaemonSet node selector targeting
- `test_cluster_purpose` — verifies `cluster_purpose` customfield in falcosidekick config

## Seed Falco test harness

A manual end-to-end flow to verify that Falco works on the seed itself (not a shoot). This tests seed-class extension deployment, event detection, and namespace cleanup.

### Prerequisites

Regenerate and deploy the extension:

```bash
hack/local-setup/generate-operator-extension-resource.sh
make extension-up
```

Virtual garden and seed cluster must be accessible.

### Variables

```bash
KUBECONFIG_VIRTUAL=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig
KUBECONFIG_SEED=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig
```

### Step 1 — Look up the latest Falco version (virtual garden)

Check the FalcoProfile on the **virtual garden** and pick the latest version — usually the one classified as `preview`:

```bash
# Run against the VIRTUAL GARDEN
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get falcoprofile falco \
  -o jsonpath='{range .spec.versions.falco[*]}{.version}{"\t"}{.classification}{"\n"}{end}'
```

Use the highest-versioned `preview` entry (or `supported` if no preview exists). Set it as a variable:

```bash
FALCO_VERSION=0.44.1   # replace with whatever the profile shows
```

### Step 2 — Create a dummy OpenSearch secret (virtual garden, `garden` namespace)

The secret must be created on the **virtual garden** in the **`garden` namespace** — this is where Gardener resolves resource references for cluster-scoped Seed objects (not `garden-local`, not `seed-local`).

```bash
# Run against the VIRTUAL GARDEN
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: opensearch-config
  namespace: garden
type: Opaque
stringData:
  hostport: "http://opensearch.default.svc:9200"
  index: "falco"
  suffix: "daily"
  checkcert: "false"
  minimumpriority: "debug"
  createindextemplate: "true"
EOF
```

No real OpenSearch is needed — falcosidekick will log failed connection attempts, which is sufficient to verify the wiring.

### Step 3 — Add resources mapping to seed (virtual garden)

```bash
# Run against the VIRTUAL GARDEN
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL patch seed local --type=merge -p '{
  "spec": {
    "resources": [
      {
        "name": "opensearch-config",
        "resourceRef": {"apiVersion": "v1", "kind": "Secret", "name": "opensearch-config"}
      }
    ]
  }
}'
```

### Step 4 — Add falco extension to seed (virtual garden)

```bash
# Run against the VIRTUAL GARDEN — use the FALCO_VERSION from Step 1
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL patch seed local --type=json -p "[
  {
    \"op\": \"add\",
    \"path\": \"/spec/extensions/-\",
    \"value\": {
      \"type\": \"shoot-falco-service\",
      \"providerConfig\": {
        \"apiVersion\": \"falco.extensions.gardener.cloud/v1alpha1\",
        \"kind\": \"FalcoServiceConfig\",
        \"falcoVersion\": \"$FALCO_VERSION\",
        \"destinations\": [{\"name\": \"opensearch\", \"resourceSecretName\": \"opensearch-config\"}]
      }
    }
  }
]"
```

### Step 5 — Wait for Falco + falcosidekick to come up (seed cluster)

```bash
# Run against the SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED get all -n falco -w
```

Expect: one `falco` DaemonSet pod and two `falcosidekick` Deployment pods all `Running`.

### Step 6 — Run event generator (seed cluster, `default` namespace)

```bash
# Run against the SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED run falco-event-generator \
  --image=falcosecurity/event-generator:latest \
  --restart=Never -n default -- run
```

### Step 7 — Check falcosidekick logs for events (seed cluster)

```bash
# Run against the SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED -n falco logs deployment/falcosidekick --tail=30
```

Look for:
- `DEBUG: Falco's payload : {...}` — falcosidekick received an event from falco ✓
- `ERROR: Elasticsearch - Post "http://opensearch.default.svc:9200/...": ... no such host` — expected, confirms the destination is wired up correctly ✓

### Step 8 — Clean up (seed cluster + virtual garden)

```bash
# Remove event generator — run against the SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED delete pod falco-event-generator -n default --ignore-not-found

# Find the index of the falco extension in spec.extensions — run against the VIRTUAL GARDEN
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get seed local \
  -o jsonpath='{range .spec.extensions[*]}{.type}{"\n"}{end}' | cat -n

# Remove it by index (replace '1' with the actual 0-based index) — run against the VIRTUAL GARDEN
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL patch seed local --type=json \
  -p '[{"op":"remove","path":"/spec/extensions/1"}]'
```

### Step 9 — Verify namespace is deleted (seed cluster)

The extension deletes the `falco` namespace after cleaning up its workloads:

```bash
# Run against the SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED get ns falco
# Expected: Error from server (NotFound): namespaces "falco" not found
```

### Notes

- **Seed re-fetch**: the actuator re-fetches the seed from the API on every reconcile, so `spec.resources` changes are picked up without restarting the extension.
- **`opensearch` not `logging`**: `logging` is not in `AllowedDestinationsSeed`; use `opensearch` (or `stdout`, `custom`, `splunk`, `central`).
- **Secret namespace**: the dummy secret must be in the `garden` namespace of the virtual garden. Gardener resolves Seed resource references from there — `garden-local` and `seed-local` will not work.

## Garden Falco test harness

A manual end-to-end flow to verify that Falco works as a garden-class extension (deployed by the Gardener Operator, not gardenlet). This tests garden-class Extension CR reconciliation, event detection, and namespace cleanup.

### Key differences from the seed harness

| | Seed harness | Garden harness |
|---|---|---|
| Extension CR kind | `Seed` | `Garden` |
| Extension CR namespace | cluster-scoped | cluster-scoped |
| OpenSearch secret location | `garden` namespace on **virtual garden** | `garden` namespace on **runtime cluster** |
| Kubeconfig for patching | `KUBECONFIG_VIRTUAL` | `KUBECONFIG_SEED` (runtime cluster) |
| Kubeconfig for `make extension-up` | `KUBECONFIG_SEED` | `KUBECONFIG_SEED` (same) |
| Concurrent with seed harness? | No — collision on `falco` namespace | No — test one class at a time |

The extension controller watches `[garden, seed]` classes. During garden testing there is no seed-class Extension CR, so no collision occurs even though `--extension-classes=garden,seed` is set.

### Prerequisites

Regenerate and deploy the extension:

```bash
hack/local-setup/generate-operator-extension-resource.sh
make extension-up
```

Virtual garden and seed/runtime cluster must be accessible.

### Variables

```bash
KUBECONFIG_VIRTUAL=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig
KUBECONFIG_SEED=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig
```

### Step 1 — Look up the latest Falco version (virtual garden)

Same as the seed harness — check the FalcoProfile on the **virtual garden**:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get falcoprofile falco \
  -o jsonpath='{range .spec.versions.falco[*]}{.version}{"\t"}{.classification}{"\n"}{end}'
```

Set the version:

```bash
FALCO_VERSION=0.44.1   # replace with whatever the profile shows
```

### Step 2 — Create a dummy OpenSearch secret (runtime cluster, `garden` namespace)

**Critical difference from seed**: the secret goes in the `garden` namespace on the **runtime cluster** (not the virtual garden). The Gardener Operator does not project ref-secrets for Garden resources; `reconcileGardenRefSecrets` reads the secret directly from the Extension namespace (`garden`) on the runtime cluster.

```bash
# Run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: opensearch-config
  namespace: garden
type: Opaque
stringData:
  hostport: "http://opensearch.default.svc:9200"
  index: "falco"
  suffix: "daily"
  checkcert: "false"
  minimumpriority: "debug"
  createindextemplate: "true"
EOF
```

No real OpenSearch is needed — falcosidekick will log failed connection attempts, sufficient to verify the wiring.

### Step 3 — Add resources mapping to Garden (runtime cluster)

The Garden object is cluster-scoped and lives on the runtime cluster. Patch it via `KUBECONFIG_SEED`:

```bash
# Run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED patch garden local --type=merge -p '{
  "spec": {
    "resources": [
      {
        "name": "opensearch-config",
        "resourceRef": {"apiVersion": "v1", "kind": "Secret", "name": "opensearch-config"}
      }
    ]
  }
}'
```

### Step 4 — Add falco extension to Garden (runtime cluster)

```bash
# Run against the RUNTIME/SEED CLUSTER — use the FALCO_VERSION from Step 1
kubectl --kubeconfig=$KUBECONFIG_SEED patch garden local --type=json -p "[
  {
    \"op\": \"add\",
    \"path\": \"/spec/extensions/-\",
    \"value\": {
      \"type\": \"shoot-falco-service\",
      \"providerConfig\": {
        \"apiVersion\": \"falco.extensions.gardener.cloud/v1alpha1\",
        \"kind\": \"FalcoServiceConfig\",
        \"falcoVersion\": \"$FALCO_VERSION\",
        \"destinations\": [{\"name\": \"opensearch\", \"resourceSecretName\": \"opensearch-config\"}]
      }
    }
  }
]"
```

### Step 5 — Wait for Falco + falcosidekick to come up (runtime cluster)

```bash
# Run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED get all -n falco -w
```

Expect: one `falco` DaemonSet pod and two `falcosidekick` Deployment pods all `Running`.

### Step 6 — Run event generator (runtime cluster, `default` namespace)

```bash
# Run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED run falco-event-generator \
  --image=falcosecurity/event-generator:latest \
  --restart=Never -n default -- run
```

### Step 7 — Check falcosidekick logs for events (runtime cluster)

```bash
# Run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED -n falco logs deployment/falcosidekick --tail=30
```

Look for:
- `DEBUG: Falco's payload : {...}` — falcosidekick received an event from falco ✓
- `ERROR: Elasticsearch - Post "http://opensearch.default.svc:9200/...": ... no such host` — expected, confirms the destination is wired up correctly ✓

### Step 8 — Clean up (runtime cluster)

```bash
# Remove event generator — run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED delete pod falco-event-generator -n default --ignore-not-found

# Find the index of the falco extension in spec.extensions — run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED get garden local \
  -o jsonpath='{range .spec.extensions[*]}{.type}{"\n"}{end}' | cat -n

# Remove it by index (replace '0' with the actual 0-based index) — run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED patch garden local --type=json \
  -p '[{"op":"remove","path":"/spec/extensions/0"}]'
```

### Step 9 — Verify namespace is deleted (runtime cluster)

The extension deletes the `falco` namespace after cleaning up its workloads:

```bash
# Run against the RUNTIME/SEED CLUSTER
kubectl --kubeconfig=$KUBECONFIG_SEED get ns falco
# Expected: Error from server (NotFound): namespaces "falco" not found
```

### Notes

- **Garden re-fetch**: the actuator re-fetches the Garden object on every reconcile via `utils.GetGarden()`, so `spec.resources` changes are picked up without restarting the extension.
- **`opensearch` not `logging`**: `logging` is not in `AllowedDestinationsSeed`; use `opensearch` (or `stdout`, `custom`, `splunk`, `central`).
- **Secret location**: the dummy secret must be in the `garden` namespace on the **runtime cluster** — this is where `reconcileGardenRefSecrets` reads it and creates `ref-opensearch-config`. Do not put it on the virtual garden.
- **No collision with seed harness**: you can have `--extension-classes=garden,seed` deployed; as long as the Seed object has no `shoot-falco-service` extension, no seed-class reconcile will run.

## Troubleshooting

- **`gcloud auth`**: Run `gcloud auth login` and `gcloud auth configure-docker europe-docker.pkg.dev`
- **Extension not becoming ready**: Check `kubectl get extension extension-shoot-falco-service -o yaml` — if refs are bare `local-skaffold/...`, run `make extension-up` again
- **Shoot stuck at 0%**: Check `kubectl -n garden logs -l app=gardenlet --tail=50 | grep error` — likely the extension is not installed. Check the Extension resource.
- **Shoot stuck during create**: Check `kubectl --kubeconfig <garden-kc> describe shoot -n garden-local local`
- **After host reboot**: Loopback IPs may be lost; restore with `cd ../gardener && ./dev-setup/infra.sh setup-loopback-devices`
- **Python kubernetes library**: The tests use `call_api(..., response_types_map={...})` — this is the v30+ API. If you see `unexpected keyword argument 'response_type'`, the library was downgraded; pin `kubernetes>=30` or update.
