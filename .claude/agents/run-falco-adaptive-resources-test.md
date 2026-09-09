---
name: run-falco-adaptive-resources-test
description: Manual end-to-end harness for testing the FalcoAdaptiveResources feature on a local Gardener dev environment (per-pool DaemonSet approach)
---

# Run Falco AdaptiveResources Integration Test

This harness tests the `AdaptiveResources` feature: per-pool Falco DaemonSets sized from cloud profile machine types via formula expressions. It runs against the local Gardener dev environment.

## Context

The `AdaptiveResources` feature was implemented on branch `realmain`. It:
- Renders one `falco-<pool-name>` DaemonSet per worker pool, resources computed from formulas + cloud profile machine type capacity
- Renders a `falco-default` DaemonSet for nodes without a pool label (DoesNotExist affinity)
- Puts all per-pool DaemonSets in a separate ManagedResource `extension-shoot-falco-service-adaptive`
- The standard single `falco` DaemonSet is NOT created when `AdaptiveResources` is configured

## Variables

```bash
KUBECONFIG_VIRTUAL=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig
KUBECONFIG_SEED=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig
GARDEN_KC="$KUBECONFIG_VIRTUAL"
PROJECT_NS=garden-local
SHOOT_NAME=local
REPO_ROOT=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener-extension-shoot-falco-service
```

## What this test does

1. **Deploy the extension** with the new `AdaptiveResources` code (`make extension-up`)
2. **Create a shoot** named `local` in `garden-local` (if not already present)
3. **Patch the cloud profile** to add `local-large` machine type (4 CPU, 32Gi)
4. **Add a second worker pool** `local-large` (min=0, max=0 — no actual nodes needed) to the shoot
5. **Deploy Falco with `adaptiveResources`** formulas:
   - `cpuRequest: "NodeCPU < 2 ? 200.0 : (NodeCPU < 4 ? 400.0 : 800.0)"`
   - `memoryRequest: "NodeMemoryGi * 16.0"`
6. **Wait for shoot reconcile** to complete
7. **Verify in the shoot cluster** (`kube-system`):
   - `falco-local` DaemonSet exists (1 CPU pool → 200m cpuRequest)
   - `falco-local-large` DaemonSet exists (4 CPU pool → 800m cpuRequest)
   - `falco-default` DaemonSet exists (DoesNotExist affinity)
   - Old single `falco` DaemonSet is ABSENT
8. **Verify resource values** on each per-pool DaemonSet
9. **Remove the second worker pool** `local-large` from the shoot + trigger reconcile
10. **Verify** `falco-local-large` DaemonSet is gone; `falco-local` and `falco-default` remain
11. **Tear down Falco** entirely; verify all adaptive DaemonSets are gone
12. **Cleanup**: remove `local-large` machine type from cloud profile; remove worker pool

## CRITICAL: Start with a clean environment

**Always start fresh.** Do not attempt to debug a broken dev environment by patching deployments, removing finalizers, or manually editing ManagedResources. This leads to cascading issues with resource-manager ownership conflicts, stuck ControllerInstallations, and stale replicasets. Tear down and rebuild instead.

### Tear down (if environment exists)

Do not wait for `make kind-down` to finish gracefully — it can hang. Use the hard path:

```bash
# Stop and remove all containers immediately (no grace period)
docker ps -q | xargs -r docker stop -t 0
docker ps -aq | xargs -r docker rm -f

# Remove all volumes (the registry and kind volumes fill disk fast — 20-25 GB each)
docker volume ls -q | xargs -r docker volume rm -f

# Remove leftover backup bucket files owned by root
sudo rm -rf /mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev/local-backupbuckets/

# Verify disk is reclaimed
docker system df
```

Expected after teardown: no running containers, Local Volumes = 0B (or near zero).

### Rebuild from scratch

```bash
cd /mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener-extension-shoot-falco-service
hack/local_setup.sh
```

This script runs the full setup in order:
1. `cd ../gardener && make kind-up` — creates kind cluster, local registry, DNS
2. `make gardener-up` — deploys operator, garden CR, gardenlet/seed
3. Applies Falco CRDs + FalcoProfile to the virtual garden cluster
4. `hack/local-setup/generate-operator-extension-resource.sh` — regenerates the operator Extension resource
5. `KUBECONFIG=$KUBECONFIG_SEED make extension-up` — builds and deploys via skaffold

Wait for the setup to complete (5-10 minutes). Then verify:

```bash
KUBECONFIG_VIRTUAL=/mnt/d040949/home/ccloud/go/src/github.com/gardener/gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get seed local
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get controllerinstallation | grep falco
```

Expected: seed `Ready=True`, falco ControllerInstallation `Installed=True, Healthy=True`.

### NEVER manually apply operator-extension-resource.yaml

`hack/local-setup/operator-extension-resource.yaml` contains bare `local-skaffold/...` image refs as placeholders. Skaffold rewrites these to fully-qualified `registry.local.gardener.cloud:5001/...@sha256:...` refs on deploy. Manually running `kubectl apply -f hack/local-setup/operator-extension-resource.yaml` injects the bare refs directly, causing `ImagePullBackOff` in the extension deployment and a broken ManagedResource that cannot be fixed by patching — only a full teardown+rebuild recovers from this. Always use `make extension-up`.

---

## Step-by-step procedure

### Step 0 — Check prerequisites

```bash
# Confirm kind cluster is running
docker ps --format "{{.Names}}" | grep gardener-local

# Confirm virtual garden is reachable
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get seed local

# Confirm Falco FalcoProfile exists
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get falcoprofile falco \
  -o jsonpath='{range .spec.versions.falco[*]}{.version}{"\t"}{.classification}{"\n"}{end}'
```

Pick a supported/preview Falco version for the test. Prefer `0.44.1` (preview) or `0.42.1` (supported).

### Step 1 — Build and deploy the extension

```bash
cd $REPO_ROOT
hack/local-setup/generate-operator-extension-resource.sh
KUBECONFIG=$KUBECONFIG_SEED make extension-up
```

Wait for the ControllerInstallation to become healthy:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get controllerinstallation \
  -l extensions.gardener.cloud/controllerinstallation=extension-shoot-falco-service -w 2>/dev/null || \
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get controllerinstallation 2>&1 | grep falco
```

Expect: `Installed=True, Healthy=True`.

### Step 2 — Create a shoot (if absent)

Check if shoot already exists:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME 2>&1
```

If absent, create it:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL apply -f ../gardener/example/provider-local/shoot.yaml
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME -w
```

Wait for `lastOperation.state == Succeeded`.

### Step 3 — Get shoot kubeconfig

```bash
SHOOT_KC=/tmp/shoot-local-kc.yaml
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL \
  create -f - --raw "/apis/core.gardener.cloud/v1beta1/namespaces/$PROJECT_NS/shoots/$SHOOT_NAME/adminkubeconfig" <<'EOF' \
  | python3 -c "import sys, json, base64; d=json.load(sys.stdin); open('/tmp/shoot-local-kc.yaml','w').write(base64.b64decode(d['status']['kubeconfig']).decode())"
{"apiVersion":"authentication.gardener.cloud/v1alpha1","kind":"AdminKubeconfigRequest","spec":{"expirationSeconds":86400}}
EOF
```

Verify:

```bash
kubectl --kubeconfig=$SHOOT_KC get nodes
```

### Step 4 — Patch cloud profile: add `local-large` machine type

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL patch cloudprofile local --type=json -p '[
  {
    "op": "add",
    "path": "/spec/machineTypes/-",
    "value": {
      "name": "local-large",
      "cpu": "4",
      "gpu": "0",
      "memory": "32Gi",
      "architecture": "amd64",
      "usable": true
    }
  }
]'
```

Verify:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get cloudprofile local \
  -o jsonpath='{.spec.machineTypes[*].name}'
```

Expected: `local local-large`.

### Step 5 — Add `local-large` worker pool to shoot (min/max=0)

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS patch shoot $SHOOT_NAME --type=json -p '[
  {
    "op": "add",
    "path": "/spec/provider/workers/-",
    "value": {
      "name": "local-large",
      "machine": {"type": "local-large"},
      "cri": {"name": "containerd"},
      "minimum": 0,
      "maximum": 0,
      "maxSurge": 0,
      "maxUnavailable": 0
    }
  }
]'
```

Trigger reconcile and wait:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS \
  annotate shoot $SHOOT_NAME "gardener.cloud/operation=reconcile" --overwrite
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME -w
```

Wait for `Succeeded`.

### Step 6 — Deploy Falco with AdaptiveResources

Use `falco-version: 0.44.1` (or latest supported/preview from Step 0).

Formula logic:
- `local` pool: 1 CPU → `NodeCPU < 2` → **200m** cpuRequest, `1 CPU * 16 = 16` → **16Mi** memoryRequest... wait, `NodeMemoryGi=8` for local so `8*16=128` → **128Mi**.
- `local-large` pool: 4 CPU → `NodeCPU >= 4` → **800m** cpuRequest, `NodeMemoryGi=32` → `32*16=512` → **512Mi**.

```bash
FALCO_VERSION=0.44.1  # or 0.42.1

kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS patch shoot $SHOOT_NAME --type=json -p "$(cat <<'ENDPATCH'
[
  {
    "op": "add",
    "path": "/spec/extensions",
    "value": [
      {
        "type": "shoot-falco-service",
        "providerConfig": {
          "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
          "kind": "FalcoServiceConfig",
          "falcoVersion": "FALCO_VER",
          "rules": {"standard": ["falco-rules"]},
          "destinations": [{"name": "stdout"}],
          "falcoConfig": {
            "adaptiveResources": {
              "formulas": {
                "cpuRequest": "NodeCPU < 2 ? 200.0 : (NodeCPU < 4 ? 400.0 : 800.0)",
                "memoryRequest": "NodeMemoryGi * 16.0"
              }
            }
          }
        }
      }
    ]
  }
]
ENDPATCH
)" 2>/dev/null || true
```

**Note**: If the shoot already has extensions (from a previous test run), use `"op":"replace"` instead of `"op":"add"`. Check first:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME \
  -o jsonpath='{.spec.extensions[*].type}'
```

If empty, use `add`. If `shoot-falco-service` is present, use `replace` with index 0.

Actually, the safest approach is to use a merge patch:

```bash
FALCO_VERSION=0.44.1

kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS patch shoot $SHOOT_NAME --type=merge -p "{
  \"spec\": {
    \"extensions\": [
      {
        \"type\": \"shoot-falco-service\",
        \"providerConfig\": {
          \"apiVersion\": \"falco.extensions.gardener.cloud/v1alpha1\",
          \"kind\": \"FalcoServiceConfig\",
          \"falcoVersion\": \"$FALCO_VERSION\",
          \"rules\": {\"standard\": [\"falco-rules\"]},
          \"destinations\": [{\"name\": \"stdout\"}],
          \"falcoConfig\": {
            \"adaptiveResources\": {
              \"formulas\": {
                \"cpuRequest\": \"NodeCPU < 2 ? 200.0 : (NodeCPU < 4 ? 400.0 : 800.0)\",
                \"memoryRequest\": \"NodeMemoryGi * 16.0\"
              }
            }
          }
        }
      }
    ]
  }
}"
```

Trigger reconcile:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS \
  annotate shoot $SHOOT_NAME "gardener.cloud/operation=reconcile" --overwrite
```

Wait for shoot to reconcile:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME -w
```

### Step 7 — Verify per-pool DaemonSets in shoot cluster

```bash
# List all DaemonSets in kube-system
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonsets | grep falco
```

Expected output:
```
falco-default      0         0         0       ...   (no matching nodes, DoesNotExist affinity)
falco-local        1         1         1       ...   (running on the 1 local node)
falco-local-large  0         0         0       ...   (pool has 0 nodes)
```

**Verify `falco` DaemonSet is ABSENT:**

```bash
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonset falco 2>&1
# Expected: Error from server (NotFound)
```

### Step 8 — Verify resource values

```bash
# falco-local should have 200m cpu request (1 CPU pool)
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonset falco-local \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="falco")].resources}'
```

Expected: `{"requests":{"cpu":"200m","memory":"128Mi"}}`

```bash
# falco-local-large should have 800m cpu request (4 CPU pool)
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonset falco-local-large \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="falco")].resources}'
```

Expected: `{"requests":{"cpu":"800m","memory":"512Mi"}}`

```bash
# falco-default should have DoesNotExist affinity
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonset falco-default \
  -o jsonpath='{.spec.template.spec.affinity.nodeAffinity}' | python3 -m json.tool
```

Expected: contains `"operator": "DoesNotExist"` on the `worker.gardener.cloud/pool` key.

```bash
# falco-local should have nodeSelector for pool 'local'
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonset falco-local \
  -o jsonpath='{.spec.template.spec.nodeSelector}'
```

Expected: `{"worker.gardener.cloud/pool":"local"}`

### Step 9 — Remove the second worker pool and verify DaemonSet removal

Find the index of `local-large` in the workers array:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME \
  -o jsonpath='{range .spec.provider.workers[*]}{.name}{"\n"}{end}' | cat -n
```

Remove it (use the 0-based index, e.g. `1` if it's the second entry):

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS patch shoot $SHOOT_NAME --type=json -p '[
  {"op": "remove", "path": "/spec/provider/workers/1"}
]'
```

Trigger reconcile:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS \
  annotate shoot $SHOOT_NAME "gardener.cloud/operation=reconcile" --overwrite
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME -w
```

After reconcile, verify in the shoot cluster:

```bash
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonsets | grep falco
```

Expected: `falco-local-large` is GONE. `falco-local` and `falco-default` remain.

### Step 10 — Tear down Falco entirely

Remove the extension from the shoot:

```bash
# Remove the shoot-falco-service extension (it's at index 0 if no other extensions)
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS patch shoot $SHOOT_NAME --type=json -p '[
  {"op": "remove", "path": "/spec/extensions/0"}
]'
```

Trigger reconcile:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS \
  annotate shoot $SHOOT_NAME "gardener.cloud/operation=reconcile" --overwrite
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL -n $PROJECT_NS get shoot $SHOOT_NAME -w
```

Verify all Falco DaemonSets gone:

```bash
kubectl --kubeconfig=$SHOOT_KC -n kube-system get daemonsets | grep falco
# Expected: no output
```

### Step 11 — Cleanup: remove `local-large` machine type from cloud profile

```bash
# Find the index of local-large in machineTypes
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get cloudprofile local \
  -o jsonpath='{range .spec.machineTypes[*]}{.name}{"\n"}{end}' | cat -n
```

Remove it (replace `1` with the actual 0-based index):

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL patch cloudprofile local --type=json -p '[
  {"op": "remove", "path": "/spec/machineTypes/1"}
]'
```

Verify:

```bash
kubectl --kubeconfig=$KUBECONFIG_VIRTUAL get cloudprofile local \
  -o jsonpath='{.spec.machineTypes[*].name}'
# Expected: local
```

## Troubleshooting

- **Extension not healthy after `make extension-up`**: Check `kubectl --kubeconfig=$KUBECONFIG_SEED get pods -n extension-shoot-falco-service-garden-local-* 2>/dev/null || kubectl --kubeconfig=$KUBECONFIG_SEED get pods -A | grep falco`
- **Shoot stuck in reconcile**: Check `kubectl --kubeconfig=$KUBECONFIG_VIRTUAL describe shoot -n $PROJECT_NS $SHOOT_NAME` for error conditions. Check `kubectl --kubeconfig=$KUBECONFIG_SEED logs -l app=gardenlet -n garden --tail=100 | grep -i falco`
- **ManagedResource not applying**: Check `kubectl --kubeconfig=$KUBECONFIG_SEED get managedresources -A | grep falco`. The adaptive one is named `extension-shoot-falco-service-adaptive`.
- **Validator rejecting config**: Run the patch and check error. Make sure both `resources` and `adaptiveResources` are NOT set simultaneously.
- **Wrong resource values**: The formula uses `NodeCPU` (float) and `NodeMemoryGi` (float). For `local` pool: CPU=1, MemoryGi=8. For `local-large`: CPU=4, MemoryGi=32.

## Expected final state

After the test:
- Cloud profile `local` has only machine type `local` (restored)
- Shoot `local` has only one worker pool `local` (restored)
- No Falco DaemonSets in kube-system
- No Falco extension in shoot spec
