# Falco Configuration

## Introduction

Falco can be enabled and configured in the `extensions` section of the shoot manifest. The minimal configuration is:

```yaml
  - type: shoot-falco-service
```

Alternatively, you can specify a provider configuration:

```yaml
  - type: shoot-falco-service
    providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
```

This configuration deploys Falco into the `kube-system` namespace of the shoot cluster. Defaults for Falco versions, Falco rules, and event storage are applied according to the landscape configuration. For most deployments, the defaults are:

- The latest supported Falco version
- The [Falco rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) ruleset, possibly with extensions to avoid false positives in an empty cluster
- The `logging` destination

The configuration above will be expanded to:

```yaml
    - type: shoot-falco-service
      providerConfig:
        kind: FalcoServiceConfig
        apiVersion: falco.extensions.gardener.cloud/v1alpha1
        falcoVersion: 0.40.0
        autoUpdate: true
        rules:
          standard:
          - falco-rules
        destinations:
        - name: logging
```

## Configuration Details

Below is the full configuration, explained in detail:

```yaml
  - type: shoot-falco-service
    providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
      # Optional: uses the latest version tagged as "supported" if omitted
      falcoVersion: 0.40.0
      # Optional: defaults to true
      autoUpdate: true|false
      # Optional
      nodeSelector:
        key: value
      # Optional: defaults to false
      heartbeatEvent: true|false
      rules:
        # Standard rules from https://github.com/falcosecurity/rules/tree/main/rules
        standard:
        - falco-rules
        - falco-incubating-rules
        - falco-sandbox-rules
        # Custom rules
        custom:
        - resourceName: rules1
      destinations:
        # Possible values: stdout, logging, webhook
        - name: custom
          # Options, may be required to configure destination
          resourceSecretName: secret
```

### Versions and Update Strategy

The `falcoVersion` field specifies the Falco version from the non-expired versions configured in the [Falco profile](falco-profile.md). If omitted, the latest supported version is selected.

Setting `autoUpdate` to `false` allows users to opt out of automated Falco updates, for example, if certain rules are incompatible with newer Falco versions. When `autoUpdate` is `true`, the extension always updates Falco to the latest supported version in the Falco profile. No automated updates occur if `autoUpdate` is `false`, except when the configured version has expired (`expirationDate` is in the past). In that case, Falco is updated to the next non-expired version.

### Configuring Rules

The `rules` section configures both standard and custom Falco rules:

```yaml
      rules:
        standard:
        - falco-rules
        - falco-incubating-rules
        - falco-sandbox-rules
        # Custom rules
        custom:
        - resourceName: my-custom-rules
        - resourceName: more-custom-rules
        ...
```

Falco rules (`falco-rules`), incubating rules (`falco-incubating-rules`), and sandbox rules (`falco-sandbox-rules`) are provided by the [Falco community](https://github.com/falcosecurity/rules). The Falco rules have been extended to avoid false positives in an empty Kubernetes cluster managed by Gardener. Note that incubating and sandbox rules may still emit false positives. Only the listed values are accepted; rule files do not depend on each other.

The standard rules can be extended or replaced by custom rules. Custom
rules in the Gardener setup can be stored in a ConfigMap and applied to the
same Gardener project as the cluster shoot manifest. The ConfigMap must be
configured as a resource in the cluster as described
[here](https://github.com/gardener/gardener/blob/44e5d3ad6060633ee14a1013306e5f1191d2b523/example/90-shoot.yaml#L380).

The `my-custom-rules` name above requires an entry with the same name in the
`resources` section of the shoot manifest:

```yaml
  resources:
  - name: my-custom-rules
    resourceRef:
      apiVersion: v1
      kind: ConfigMap
      name: my-custom-rules-configmap
```

This entry refers to a ConfigMap named `my-custom-rules-configmap`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-custom-rules-configmap
  namespace: garden-myproject
data:
  myrules.yaml: |-
    # Custom rules go here
    ...
  myrules-extended.yaml: |-
    # More custom rules
    ...
```

Each key (e.g., `myrules.yaml` or `myrules-extended.yaml`) results in one rules file. You can create a ConfigMap like the above with:

```bash
kubectl create configmap my-custom-rules-configmap --from-file=myrules.yaml \
            --from-file=myrules-extended.yaml
```

If ConfigMap size is restricted, you can add gzipped rule files. File names must end with `.gz`; other compression formats are not supported.

```bash
gzip myrules.yaml
gzip myrules-extended.yaml
kubectl create configmap my-custom-rules-configmap --from-file=myrules.yaml.gz \
            --from-file=myrules-extended.yaml.gz
```

Note: The maximum size of an unzipped rule file is 1MB, and there is a limit of 10 rule files per ConfigMap.

Ordering is important, as Falco rules may extend other rules that must be defined first. The order is:

1. Falco rules (if specified)
2. Falco incubating rules (if specified)
3. Falco sandbox rules (if specified)
4. Files from the first custom rule ConfigMap specified in the `customRules` array (ordered lexicographically by filename)
5. Files from the second custom rule ConfigMap
...

If no `rules` key is specified, the `falco-rules` standard rules are set by default; otherwise, no defaults are applied.

### Configuring Destinations

Falco can post events to several internal and external storage providers:

- `stdout`: Write events to the pod log only
- `central`: Post events to a central storage, if offered by the infrastructure provider
- `logging`: Post events to the local cluster logging stack
- `custom`: Post events to a custom web server

More details for each destination are described below.

The `custom` destination requires additional configuration:

```yaml
      destinations:
      - name: custom
        resourceSecretName: custom-secret
```

The `resourceSecretName` references a secret defined in the `resources` section of the shoot manifest:

```yaml
  resources:
  - name: custom-secret
    resourceRef:
      apiVersion: v1
      kind: Secret
      name: my-custom-secret-config
```

The secret contains the following values:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-webhook-secret-config
  namespace: <project namespace in garden cluster>
stringData:
  address: "" # URL
  method: POST
  checkcerts: true | false
  customHeaders: |
    Authorization: Bearer <token>
    header1: value1
    ...
```

### Other Options

`FalcoServiceConfig` supports additional options:

```yaml
      # Optional
      nodeSelector:
        key: value
        key2: value2
      # Optional: defaults to false
      heartbeatEvent: true|false
```

The `nodeSelector` option specifies node selectors for Falco pods, following the Kubernetes API [specification](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector). Only nodes matching the specified labels will run Falco pods.

The `heartbeatEvent` option enables or disables the heartbeat event, which is a periodic event sent by Falco to indicate it is running and healthy. This is useful for monitoring.

## Destinations

This section provides details about event destinations, use cases, and implementation.

You can configure up to two destinations, provided one of them is `stdout`.

## Do Not Forward Falco Events (`stdout` Option)

Events are logged to Falco pod stdout and not forwarded. Falcosidekick is not deployed if `stdout` is the only event destination. Users can deploy custom tools to scrape pod logs and store events.

Note: Writing logs to stdout forwards events to the cluster Vali database, as logs from pods in the `kube-system` namespace are generally stored there. Event details may not be stored in an optimal way for analysis. Use the `logging` destination if you plan to analyze events.

## Store Events in the Cluster Logging Stack (`logging` Option)

Falco events are forwarded to the cluster Vali logging database using the Falcosidekick [Loki output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/loki.md).

Events can be queried in the Vali section of the cluster Plutono UI using:

```logql
{rule=~".+", tags=~".+", source=~".+"}
```

More details on possible queries can be found in the [LogQL documentation](https://grafana.com/docs/loki/latest/query/).

Note: Events may be retained for a short period and could be overwritten if the Vali database experiences disk pressure. Replicating events to another location may be necessary.

## Custom Destination (`custom` Option)

This option forwards Falco events to user-configurable destinations, such as a SIEM system. It requires a destination configuration in a secret referenced by `resourceSecretName`. The secret's contents configure the Falcosidekick [webhook output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/webhook.md).

## Store Events Centrally (`central` Option)

Note: Central storage is optional and may not be provided as part of the Gardener landscape installation.

Falco events are forwarded to central storage via the Falcosidekick [webhook output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/webhook.md).

The [Falco event ingestor](https://github.com/gardener/falco-event-ingestor) provides a REST API to receive Falco events, validates event integrity, stores events in an SQL database, and implements configurable rate limiting per cluster to prevent overload.

The [Falco event provider](https://github.com/gardener/falco-event-provider) offers a REST API to access the database. Cluster users must present a valid token (with Viewer access for the Gardener project namespace) to retrieve Falco events for their cluster.
