---
name: e2e-testing-opensearch
description: "How to run end-to-end tests with Falco and OpenSearch destination on local Gardener, including the shoot manifest, OpenSearch deployment, and event verification"
metadata: 
  node_type: memory
  type: reference
  originSessionId: 1dabdd3f-b2ee-4599-af9d-c4de6be5ce1e
---

## E2E Testing with OpenSearch

### Scripts

- `hack/test-e2e-opensearch.sh` — Full e2e: deploys extension, creates shoot with Falco + OpenSearch, runs event generator, verifies events
- `hack/test-falco-044.sh` — Upgrades existing shoot to Falco 0.44.0 and verifies

### Architecture

```
Shoot cluster:
  kube-system/falco (DaemonSet) → detects syscall events
  kube-system/falcosidekick (Deployment, 2 replicas) → forwards to OpenSearch
  default/opensearch (Deployment) → receives and indexes events
```

OpenSearch MUST be inside the shoot because falcosidekick runs in the shoot and can't reach seed-internal services.

### Correct Shoot manifest

```yaml
apiVersion: core.gardener.cloud/v1beta1
kind: Shoot
metadata:
  name: falco-test
  namespace: garden-local
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
      falcoVersion: "0.44.0"
      destinations:
      - name: opensearch
        resourceSecretName: opensearch-config
  resources:                              # REQUIRED - maps resourceSecretName to actual Secret
  - name: opensearch-config
    resourceRef:
      apiVersion: v1
      kind: Secret
      name: opensearch-config
```

Key points:
- API group is `falco.extensions.gardener.cloud/v1alpha1` (NOT `service.falco.extensions.gardener.cloud`)
- `spec.resources` MUST be present to map the `resourceSecretName` to the actual Secret
- K8s version must match what's in the local CloudProfile (e.g. `1.31.1`)
- FalcoProfile CRD + profile must be applied to virtual garden before shoot creation

### OpenSearch config Secret (in garden-local namespace)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: opensearch-config
  namespace: garden-local
type: Opaque
stringData:
  hostport: "http://opensearch.default.svc:9200"
  index: "falco"
  suffix: "daily"
  checkcert: "false"
  minimumpriority: "debug"
  createindextemplate: "true"
```

### OpenSearch deployment (inside shoot)

Deploy single-node OpenSearch 2.11.1 with security plugin disabled:
```yaml
image: opensearchproject/opensearch:2.11.1
env:
- name: discovery.type
  value: single-node
- name: DISABLE_SECURITY_PLUGIN
  value: "true"
- name: OPENSEARCH_JAVA_OPTS
  value: "-Xms512m -Xmx512m"
```

### Verifying events

From within the shoot (or via port-forward):
```bash
# Count events
curl -s 'http://localhost:9200/falco*/_count'

# List indices
curl -s 'http://localhost:9200/_cat/indices?v'

# Show events
curl -s 'http://localhost:9200/falco*/_search?size=10&pretty'

# Filter by Falco version
curl -s 'http://localhost:9200/falco*/_search?pretty' -H 'Content-Type: application/json' \
  -d '{"query":{"match":{"output_fields.falco_version":"0.44.0"}},"size":5}'
```

### Port-forward for browser access

On the dev machine:
```bash
KUBECONFIG=/tmp/falco-test-kubeconfig kubectl port-forward -n default svc/opensearch 9200:9200
```

From local Mac:
```bash
ssh -N -L 9200:localhost:9200 <user>@<dev-host>
```

### Running the event generator

```bash
kshoot run falco-event-generator --image=falcosecurity/event-generator:latest --restart=Never -- run
```
