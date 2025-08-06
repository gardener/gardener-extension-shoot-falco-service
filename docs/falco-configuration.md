# Falco configuration

# Introduction

Falco can be enabled and configured in the extensions section of the shoot
manifest. This is the minimal configuration necessary:

```yaml
  - type: shoot-falco-service
```

This is also possible:

```yaml
  - type: shoot-falco-service
    providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
```

This configuration will deploy Falco into the kube-system namespace of the
shoot cluster. Defaults for Falco versions, Falco rules, as well as event
storage will be applied according to the landscape configuration. We assume
that for most deployments the defaults will be

- the latest currently available Falco version
- the [falco rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
ruleset, possible with some extensions to avoid false positive events in an
empty cluster
- the `logging` destination

This means that the configuration above will be expanded to

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

# Configuration details

This is the full configuration which is explained in more detail below.

```yaml
  - type: shoot-falco-service
    providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
      # optional, will use the latest version tagged as "supported"
      falcoVersion: 0.40.0
      # optional, defaults to true
      autoUpdate: true|false
      # optional
      nodeSelector:
        key: value
      # optional, defaults to false
      heartbeatEvent: true|false
      rules:
        # standard rules from https://github.com/falcosecurity/rules/tree/main/rules
        standard:
        - falco-rules
        - falco-incubating-rules
        - falco-sandbox-rules
        # custom rules
        custom:
        - resourceName: rules1
      destinations:
        # possible values are: stdout, logging, webhook
        - name: custom
          # options, may be required to configure destination
          resourceSecretName: secret
```

## Versions and Update strategy

With `falcoVersion` the Falco version can be specified from one of the
non-expired Falco versions configured in the [Falco profile](falco-profile.md). If
omitted, the latest version tagged as supported will be chosen from the Falco
profile.

With `autoUpdate` set to `false` users can opt out of automated Falco updates,
for example, if there is a possibility that certain Falco rules are not compatible
with a newer Falco version. When `autoUpdate` is set to true the extension will
always update Falco to the latest Falco version which is tagged as supported
in the Falco profile. No automated Falco updates will be applied if `autoUpdate`
is set to false. The only exception to this policy is when the configured Falco
version has expired (`expirationDate` is in the past). The Falco version will
then be updated to the next non-expired version.

## Configuring rules

The `rules` section can be used to configure both, standard Falco rules as
well as custom rules:

```yaml
      rules:
        standard:
        - falco-rules
        - falco-incubating-rules
        - falco-sandbox-rules
        # custom rules
        custom:
        - resourceName: my-custom-rules
        - resourceName: more-curstom-rules
        ...
```

Falco rules (`falco-rules`), Falco incubating rules (`falco-incubating-rules`),
and Falco sandbox rules (`falco-sandbox-rules`) are provided by the
[Falco community](https://github.com/falcosecurity/rules). The Falco rules have
been extended not to emit any false positive events in an empty Kubernetes
cluster managed by Gardener. Note, that this extension has not been done for
incubating- and sandbox rules which will likely emit false positive events even
in an empty cluster. The extension does not except other values than those
listed above. The rule files do not depend on each other.

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

This entry refers to a ConfigMap with name `my-custom-rules-configmap`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-custom-rules-configmap
  namespace: garden-myproject
data:
  myrules.yaml: |-
    # custom rules go here
    ...
  myrules-extended.yaml: |-
    # more custom rules
    ...
```

Each key (e.g. `myrules.yaml` or `myrules-extended.yaml`) results in one rule file.
A ConfigMap like the one above can be created by executing the following command:

```bash
kubectl create configmap my-custom-rules-configmap --from-file=myrules.yaml
            --from-file=myrules-extended.yaml
```

As Gardener operators may restrict the size of the ConfigMaps in project
namespaces, it is possible add gzipped rule files. Note that file names must end
with `.gz` and other compression formats are not supported.

```bash
gzip myrules.yaml
gzip myrules-extended.yaml
kubectl create configmap my-custom-rules-configmap --from-file=myrules.yaml.gz
            --from-file=myrules-extended.yaml.gz
```

Note that there is a maximum size of an unzipped rule file of 1MB. There is also
a limit of 10 rule files per ConfigMap.

Ordering is important as Falco rules may extend other rules that must be
defined before being referenced. The ordering is as follows:

1. Falco rules (if specified)
2. Falco incubating rules (if specified)
3. Falco Sandbox rules (if specified)
4. Files from the first custom rule config map specified in the `customRules` array.
The ordering is based lexicographical string comparison of the contained
files.
5. Files from the second custom rule ConfigMap.
...

If no rules key is specified the `falco-rules` standard rules will be set,
otherwise no defaults will be set.

## Configuring destinations

Falco can be configured to post events to several internal and external
storage providers:

- `stdout`:  do not post the events anywhere, just write them to the pod log
- `central`: post event to a central storage which might be offered by the
infrastructure provider
- `logging`: post events to the local cluster logging stack
- `custom`: post events to a custom web server.

More details for the destination options are described below.

Out of these configurations `custom` requires additional configuration:

```yaml
      destinations:
      - name: custom
        resourceSecretName: custom-secret
```

The `resourceSecretName` references a secret which must be defined in the resources
section of the shoot manifest:

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
  namespace: <<project namespace in garden cluster>>
stringData:
  address: "" # URL
  method: POST
  checkcerts: true | false
  customHeaders: |
    Authorization: Bearer <<token>>
    header1: value1
    ...
```

## Other Options

The `FalcoServiceConfig` supports additional options:

```yaml
      # optional
      nodeSelector:
        key: value
        key2: value2
      # optional, defaults to false
      heartbeatEvent: true|false
```

The `nodeSelector` option allows you to specify node selectors for the Falco pods and follows the Kubernetes API [specification](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector). Only nodes matching the specified labels will run the Falco pods.

The `heartbeatEvent` option enables or disables the heartbeat event, which is a periodic event sent by Falco to indicate that it is running and healthy. This can be useful for monitoring purposes.

# Destinations

This section provides details for the event destinations, describes possible
use cases, and outlines their implementations.

It is generally possible to configure two destinations if one of them is
`stdout`.

## Do not forward Falco events (option `stdout`)

Events are logged to Falco pod stdout but not forwarded. Falcosidekick will
not be deployed if `stdout` is the only event destination. Users can deploy
custom tools to scrape pod logs to store events.

Note: writing logs to stdout will forward events to the cluster vali database
as logs from pods in the `kube-system` namespace are generally stored there.
Event details may not be stored in an optimal way that allows event
analysis. Use the `logging` destination if you plan to analyze events.

## Store events in the cluster logging stack (option `logging`)

Falco Events will be forwarded to the cluster vali logging database using the
Falcosidekick [Loki output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/loki.md).

Events can be queried in the Vali section of the cluster Plutono UI using:
```
{rule=~".+", tags=~".+", source=~".+"}
```

More detailed on possible queries can be found in the
[LogQL documentation](https://grafana.com/docs/loki/latest/query/).

Note that events may be kept for a short period of time only and may be
overwritten in case of disk pressure of the vali database. It may be
necessary to replicate events to another location.

## Custom destination (option `custom`)

This option allows forwarding of Falco events to user configurable destinations,
for example a SIEM system. This option requires a destination configuration
in a secret referenced with `resourceSecretName`. The contents of the secret is
used to configure the Falcosidekick
[webhook output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/webhook.md).

## Store events centrally (option `central`)

Note: central storage is optional and may not be provided as part of the Gardener
landscape installation.

Falco events are forwarded to a central storage via the Falcosidekick
[webhook output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/webhook.md).

The [Falco event ingestor](https://github.com/gardener/falco-event-ingestor) provides a REST API to receive Falco events. It validates event integrity, stores events in an SQL database, and implements configurable rate limiting per cluster to prevent overload.

The [Falco event provider](https://github.com/gardener/falco-event-provider) offers a REST API to access the database. Cluster users must present a valid token (with Viewer access for the Gardener project namespace) to retrieve Falco events for their cluster.
