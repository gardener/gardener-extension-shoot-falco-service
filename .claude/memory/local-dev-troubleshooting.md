---
name: local-dev-troubleshooting
description: "Common failures in local Gardener dev environment and their fixes — network policies, disk pressure, stuck machines, extension connectivity"
metadata: 
  node_type: memory
  type: reference
  originSessionId: 1dabdd3f-b2ee-4599-af9d-c4de6be5ce1e
---

## Common Issues and Fixes

### Extension pods can't reach virtual garden API (i/o timeout)

**Symptom**: Extension pods in `extension-extension-shoot-falco-service-*` namespace crash with connection timeout to the virtual garden API (172.18.x.x LoadBalancer IP).

**Root cause**: In local kind setup, the virtual garden API is exposed via a LoadBalancer IP in the private range (172.18.0.0/12). The extension pods need the network policy label `networking.gardener.cloud/to-private-networks: allowed`.

**Fix**: Already applied in `charts/gardener-extension-shoot-falco-service/templates/deployment.yaml` — the pod template includes:
```yaml
networking.gardener.cloud/to-private-networks: allowed
networking.resources.gardener.cloud/to-virtual-garden-istio-ingress-istio-ingressgateway-inte-02e09: allowed
networking.resources.gardener.cloud/to-all-shoots-kube-apiserver-tcp-443: allowed
```

### Disk pressure on kind node

**Symptom**: Worker machines get `DiskPressure` condition, machines stuck in `Terminating`, shoot reconcile fails with "machine deployments not ready".

**Fix**:
```bash
docker system prune -f
docker image prune -a -f
docker exec gardener-local-control-plane crictl rmi --prune
```

Check with: `docker exec gardener-local-control-plane df -h /`
Target: below 80% usage.

### Machine stuck in Terminating

**Symptom**: `kubectl -n shoot--local--falco-test get machines` shows machine in `Terminating` state indefinitely.

**Fix** (if drain is stuck and won't resolve):
```bash
KUBECONFIG=$KUBECONFIG_RUNTIME kubectl -n shoot--local--falco-test patch machine <name> --type=merge -p '{"metadata":{"finalizers":null}}'
```

If the shoot is completely broken, it's often faster to delete and recreate:
```bash
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl -n garden-local annotate shoot falco-test "confirmation.gardener.cloud/deletion=true" --overwrite
KUBECONFIG=$KUBECONFIG_VIRTUAL kubectl -n garden-local delete shoot falco-test
```

### Extension reconcile fails: "custom webhook secretRef not found in resources"

**Symptom**: Shoot creation fails at ~51% with error "could not generate falco configuration: custom webhook secretRef opensearch-config not found in resources".

**Root cause**: The Shoot manifest references `resourceSecretName: opensearch-config` in the destination but doesn't declare it in `spec.resources`.

**Fix**: Add to the Shoot spec:
```yaml
spec:
  resources:
  - name: opensearch-config
    resourceRef:
      apiVersion: v1
      kind: Secret
      name: opensearch-config
```

### Falcosidekick can't reach OpenSearch on the seed

**Symptom**: Falcosidekick logs show DNS resolution failure for `opensearch.<ns>.svc` or connection refused.

**Root cause**: Falcosidekick runs inside the shoot cluster. In local Gardener, shoot pods have their own network namespace and CoreDNS — they can't resolve seed-internal service names.

**Fix**: Deploy OpenSearch inside the shoot cluster (in `default` namespace) and set the opensearch-config Secret's `hostport` to `http://opensearch.default.svc:9200`.

### Falcosidekick startup error: OTLP.Logs.Headers unmarshalling

**Symptom**: `[ERROR] Error unmarshalling config: 'OTLP.Logs.Headers' expected type 'string', got unconvertible type 'map[string]interface{}'`

**Root cause**: Chart values template for falcosidekick passes an empty map `{}` for OTLP headers instead of an empty string or omitting the field entirely.

**Fix**: Fix in the falcosidekick chart values template (charts within the extension).
