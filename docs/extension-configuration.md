# Gardener Falco Extension Configuration

The Gardener Falco extension consists of two components:
- The extension binary (`gardener-extension-shoot-falco-service`)
- The admission binary (`gardener-extension-admission-shoot-falco-service`), which includes mutating and validating webhooks as well as the maintenance controller.

## Extension: `gardener-extension-shoot-falco-service`

The extension binary uses a non-standard configuration parameter, `--config-file`, which points to a configuration YAML file as shown below:

```yaml
apiVersion: falco.extensions.config.gardener.cloud/v1alpha1
kind: Configuration
falco:
  certificateLifetime: 2100h
  certificateRenewAfter: 1600h
  priorityClassName: gardener-shoot-system-900
  falcoVPA:
    minAllowed:
      memory: "512Mi"
      cpu: "100m"
    maxAllowed:
      memory: "1Gi"
      cpu: "200m"
  defaultRequests:
    memory: "512Mi"
    cpu: "100m"
  # defaultLimits:
  #   memory: "2Gi"
  #   cpu: "500m"
  centralStorage:
    tokenLifetime: "720h"
    url: <ingestor URL>
    tokenIssuerPrivateKey: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
  clusterIdentityToken:
    tokenIssuerPrivateKey: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
    tokenLifetime: "168h"
  globalDefaultDestinations:
  - name: central-splunk
    falcosidekickOutput:
      key: splunk
      value:
        host: "https://splunk-hec.example.com/services/collector/event"
        token: "my-hec-token"
        checkcert: true
  - name: central-elastic
    falcosidekickOutput:
      key: elasticsearch
      value:
        hostport: "https://elasticsearch.example.com:9200"
        index: "falco"
        suffix: "daily"
        username: "falco"
        password: "secret"
```

- `certificateLifetime`: Lifetime of certificates generated for communication between Falco and Falcosidekick.
- `certificateRenewAfter`: Time period after which certificates are renewed.
- `priorityClassName`: Priority class used for Falco when deployed.
- `falcoVPA`: Default VPA (Vertical Pod Autoscaler) bounds for the Falco DaemonSet (see below).
  - `minAllowed`: Minimum resources VPA can recommend (floor). VPA will not scale below these values.
  - `maxAllowed`: Maximum resources VPA can recommend (ceiling). VPA will not scale above these values.
- `defaultRequests`: Default resource requests for Falco pods. These are always set on the Falco container.
  - `memory`: Memory request (default: "512Mi")
  - `cpu`: CPU request (default: "100m")
- `defaultLimits`: Optional default resource limits for Falco pods. No limits are set by default.
  - `memory`: Memory limit
  - `cpu`: CPU limit
- `centralStorage`: Optional configuration for central event storage (see below)
  - `tokenLifetime`: Lifetime of the JWT token generated during each reconcile for sending events to central storage.
  - `url`: URL of the Falco event ingestor.
  - `tokenIssuerPrivateKey`: Private key used for issuing the JWT token.
- `clusterIdentityToken`: Optional configuration for per-shoot JWT tokens used with the `<<.ClusterIdentityToken>>` template variable in global default destinations.
  - `tokenIssuerPrivateKey`: PEM-encoded RSA private key for signing tokens.
  - `tokenLifetime`: Lifetime of the issued token (default: 168h / 7 days).
- `globalDefaultDestinations`: Optional list of operator-provided Falcosidekick output destinations (see below).

## Vertical Pod Autoscaler (VPA)

A VPA is always deployed alongside the Falco DaemonSet in shoot clusters. It automatically adjusts resource requests based on actual usage, ensuring Falco pods are right-sized without manual intervention.

### How It Works

- **UpdateMode: Recreate** — VPA evicts and recreates pods when adjusting resources. The Gardener resource-manager webhook may mutate this to `InPlaceOrRecreate` if supported.
- **controlledResources:** `[memory, cpu]` — VPA manages both memory and CPU.
- **controlledValues: RequestsOnly** — VPA adjusts only requests, not limits. This avoids OOMKill issues when limits are set.
- **minAllowed** acts as a floor — VPA will never recommend resources below this value.
- **maxAllowed** acts as a ceiling — VPA will never recommend resources above this value.

### Defaults

The extension ships with hardcoded defaults that apply when no explicit configuration is provided:

| Setting | Default |
|---------|---------|
| `falcoVPA.minAllowed.memory` | 512Mi |
| `falcoVPA.minAllowed.cpu` | 100m |
| `falcoVPA.maxAllowed.memory` | 1Gi |
| `falcoVPA.maxAllowed.cpu` | 200m |
| `defaultRequests.memory` | 512Mi |
| `defaultRequests.cpu` | 100m |
| `defaultLimits` | none |

Operators can override these defaults in the extension configuration. Shoot owners can further override VPA bounds per shoot (see [Falco Configuration](falco-configuration.md)).

### Configuration Hierarchy

For each setting, the effective value is resolved as:

1. **Shoot manifest** (user override, highest priority)
2. **Extension configuration** (operator default)
3. **Hardcoded constant** (built-in fallback)

### Design Rationale

- **No limits by default**: Aligns with Gardener practice. Limits can cause OOMKill when memory usage spikes temporarily. VPA with `RequestsOnly` ensures the scheduler allocates sufficient resources without hard-capping.
- **minAllowed equals requests**: The minimum VPA recommendation matches the pod requests. This prevents VPA from scaling Falco below its minimum working set.
- **Always on**: VPA is not optional because Falco resource usage is highly workload-dependent. Without VPA, operators must over-provision to avoid resource starvation.

## Central Storage

Falcosidekick can optionally send events to a central storage location. This requires a central storage setup based on the following projects:

- [falco-event-ingestor](https://github.com/gardener/falco-event-ingestor)
- [falco-event-provider](https://github.com/gardener/falco-event-provider)
- [falco-event-db-schema](https://github.com/gardener/falco-event-db-schema)

If central storage is configured, users can set `central` as the destination for Falco events.

## Global Default Destinations

Operators can define Falcosidekick output destinations that are automatically injected into all shoots and seeds. This allows operators to enforce centralized event forwarding (e.g., to a central Splunk or Elasticsearch instance) without requiring each shoot owner to manually configure them.

### Configuration

Each global default destination is defined with:

| Field | Description |
|-------|-------------|
| `name` | A unique name identifying this destination. Must not conflict with standard destination names (`logging`, `custom`, `central`, `stdout`, `otlp`, `opensearch`, `splunk`). |
| `falcosidekickOutput.key` | The Falcosidekick output key (e.g., `splunk`, `webhook`, `elasticsearch`, `loki`, `otlp`). Each key can only be used once across all global defaults. |
| `falcosidekickOutput.value` | The configuration map passed to Falcosidekick for that output. Supports template variables (see below). |

### Template Variables

The `falcosidekickOutput.value` field supports Go templates with `<<` and `>>` delimiters. Available variables:

| Variable | Description |
|----------|-------------|
| `<<.SeedIngressDomain>>` | The seed's ingress domain |
| `<<.ServiceAccountToken>>` | A service account token placeholder (replaced at reconcile time) |
| `<<.ClusterIdentityToken>>` | A per-shoot JWT token signed with the configured private key (requires `clusterIdentityToken` config) |

Example using templates:

```yaml
globalDefaultDestinations:
- name: central-loki
  falcosidekickOutput:
    key: loki
    value:
      hostport: "https://loki.<<.SeedIngressDomain>>"
      endpoint: "/loki/api/v1/push"
      checkcert: false
      customheaders:
        Authorization: "Bearer <<.ServiceAccountToken>>"
```

### Injection Behavior

The admission mutating webhook handles global default destination injection with the following rules:

1. **On CREATE**: Global default destinations are injected into the shoot's (or seed's) Falco configuration. If the shoot already defines a destination using the same Falcosidekick output key (e.g., shoot has `splunk` and a global default also uses `splunk`), the global default is still injected but with `enabled: false` to avoid conflicts.

2. **On UPDATE**: If the shoot already had a Falco configuration before the update, no new global defaults are injected (the shoot is considered already initialized). However, stale global defaults (those no longer present in the extension config) are automatically removed.

3. **Disabled destinations**: Destinations with `enabled: false` are skipped during reconciliation — they do not produce any Falcosidekick output configuration. This allows shoot owners to disable an operator-injected destination.

### Project Opt-Out

A Gardener project can opt out of global default destination injection by annotating its namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: garden-my-project
  annotations:
    falco.gardener.cloud/skip-default-destinations: "true"
```

When this annotation is present, no global defaults are injected for shoots in that project.

## Additional Seed Managed Resources

Operators can configure additional Helm charts to be deployed as ManagedResources on the seed cluster. This is useful for deploying provider-specific components.

### Configuration

The `additional.seedManagedResources` field accepts a list of Helm charts to deploy:

```yaml
apiVersion: falco.extensions.config.gardener.cloud/v1alpha1
kind: Configuration
falco:
  additional:
    seedManagedResources:
    - name: my-nginx
      helm:
        ociRepository:
          ref: registry:tag
        values:
          replicaCount: 2
```

| Field | Description |
|-------|-------------|
| `name` | A unique name for the resource. Must be a valid DNS label (lowercase, alphanumeric, hyphens, max 63 characters). Used as a suffix in the ManagedResource name (`falco-additional-<name>`). |
| `helm.ociRepository.ref` | Full OCI artifact reference for the Helm chart (required). |
| `helm.values` | Optional Helm values passed to the chart during rendering. |

### Validation

The admission validating webhook enforces:

- No two enabled destinations may use the same Falcosidekick output key. For example, a shoot cannot have both `splunk` (standard) and `central-splunk` (global default with `key: splunk`) enabled simultaneously.
- Global default destination names are accepted by the validator even though they are not in the standard destinations list.
- Disabled destinations are excluded from output key conflict checks.

### Shoot Owner Interaction

Shoot owners see global default destinations in their `FalcoServiceConfig` like any other destination:

```yaml
apiVersion: falco.extensions.gardener.cloud/v1alpha1
kind: FalcoServiceConfig
destinations:
- name: logging
- name: central-splunk
- name: central-elastic
  enabled: false
```

A shoot owner can disable an operator-injected destination by setting `enabled: false` on it. They cannot remove it — if they do, it will be re-injected on the next mutation (CREATE path). On UPDATE, already-initialized shoots are not re-injected, so removing a global default destination name from the list is effectively the same as the operator removing it from the config.

## Admission Webhook: `gardener-extension-admission-shoot-falco-service`

The webhook can be configured to enforce usage restrictions:

- The extension may only deploy Falco in clusters where the Gardener project namespace is annotated with:

  ```yaml
  falco.gardener.cloud/enabled: "true"
  ```

- The "central" storage option may only be configured from shoot clusters if their project namespace is annotated with:

  ```yaml
  falco.gardener.cloud/centralized-logging: "true"
  ```

These restrictions can be enabled by passing the `--restricted-usage` and `--restricted-centralized-logging` flags to the webhook binary.
