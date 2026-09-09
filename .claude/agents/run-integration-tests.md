---
name: run-integration-tests
description: Run Falco extension integration tests against a local Gardener development environment
---

# Run Integration Tests

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
4. `make extension-up` — builds and deploys the Falco extension via skaffold

**Kubeconfigs** (relative to `../gardener`):

| Purpose | Path |
|---------|------|
| Runtime cluster (kind) | `dev-setup/kubeconfigs/runtime/kubeconfig` |
| Virtual garden | `dev-setup/kubeconfigs/virtual-garden/kubeconfig` |

## CRITICAL: Never apply operator-extension-resource.yaml manually

`hack/local-setup/operator-extension-resource.yaml` contains bare `local-skaffold/...` image refs as placeholders. Skaffold rewrites these to fully-qualified `registry.local.gardener.cloud:5001/...@sha256:...` refs when it deploys.

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

## What the tests verify

- `test_falco_deployment` — basic deployment with custom rules and event routing
- `test_falco_deployment_with_all_rules` — all standard rule sets loaded
- `test_all_falco_versions` — cycles through every version in the FalcoProfile
- `test_event_generator` — end-to-end: generate a security event and verify it reaches Loki
- `test_no_output` — stdout-only mode (no falcosidekick)
- `test_node_selector` — DaemonSet node selector targeting
- `test_cluster_purpose` — verifies `cluster_purpose` customfield in falcosidekick config

## Troubleshooting

- **`gcloud auth`**: Run `gcloud auth login` and `gcloud auth configure-docker europe-docker.pkg.dev`
- **Extension not becoming ready**: Check `kubectl get extension extension-shoot-falco-service -o yaml` — if refs are bare `local-skaffold/...`, run `make extension-up` again
- **Shoot stuck at 0%**: Check `kubectl -n garden logs -l app=gardenlet --tail=50 | grep error` — likely the extension is not installed. Check the Extension resource.
- **Shoot stuck during create**: Check `kubectl --kubeconfig <garden-kc> describe shoot -n garden-local local`
- **After host reboot**: Loopback IPs may be lost; restore with `cd ../gardener && ./dev-setup/infra.sh setup-loopback-devices`
- **Python kubernetes library**: The tests use `call_api(..., response_types_map={...})` — this is the v30+ API. If you see `unexpected keyword argument 'response_type'`, the library was downgraded; pin `kubernetes>=30` or update.
