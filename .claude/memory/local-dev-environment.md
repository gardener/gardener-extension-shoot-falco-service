---
name: local-dev-environment
description: "How to set up and troubleshoot the local Gardener dev environment for the Falco extension, including kubeconfig paths, deployment commands, and common failures"
metadata: 
  node_type: memory
  type: reference
  originSessionId: 1dabdd3f-b2ee-4599-af9d-c4de6be5ce1e
---

## Local Gardener Dev Environment

### Kubeconfig paths

- **Runtime/seed cluster**: `~/go/src/github.com/gardener/gardener/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig`
- **Virtual garden**: `~/go/src/github.com/gardener/gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig`
- **Shoot kubeconfig**: obtained via AdminKubeconfigRequest subresource (see [[e2e-testing-opensearch]])

### Deploying the extension

```bash
KUBECONFIG=~/go/src/github.com/gardener/gardener/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig make extension-up
```

This builds the binary, packages the chart as OCI, pushes to `registry.local.gardener.cloud:5001`, and deploys via skaffold. The chart is baked into the extension image — any chart change requires a full `make extension-up`.

### Applying FalcoProfile (required before creating shoots with Falco)

```bash
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl apply -f crds/crd-falco-profile.yaml
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl apply -f crds/clusterrole-falcoprofiles.yaml
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl apply -f crds/clusterrolebinding-falcoprofiles.yaml
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl apply -f falco/falco-profile.yaml
```

### Triggering a shoot reconcile

```bash
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl -n garden-local annotate shoot <name> "gardener.cloud/operation=reconcile" --overwrite
```

For retrying after error:
```bash
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl -n garden-local annotate shoot <name> "gardener.cloud/operation=retry" --overwrite
```

### Getting shoot kubeconfig

```bash
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl create -f - --raw "/apis/core.gardener.cloud/v1beta1/namespaces/garden-local/shoots/<name>/adminkubeconfig" <<'EOF' | python3 -c "import sys, json, base64; data = json.load(sys.stdin); print(base64.b64decode(data['status']['kubeconfig']).decode())" > /tmp/<name>-kubeconfig
{
  "apiVersion": "authentication.gardener.cloud/v1alpha1",
  "kind": "AdminKubeconfigRequest",
  "spec": { "expirationSeconds": 86400 }
}
EOF
```

There's also `~/bin/kshoot` which wraps this with 2-hour caching.

### Deleting a shoot

```bash
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl -n garden-local annotate shoot <name> "confirmation.gardener.cloud/deletion=true" --overwrite
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl -n garden-local delete shoot <name>
```
