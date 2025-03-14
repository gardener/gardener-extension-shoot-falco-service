# Falco configuration

## Introduction

Falco can be enabled and configured in the extensions sec tion in the shoot manifest. This
is the minimal configuration necessary:

```yaml
  - type: shoot-falco-service
    providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
```

This configuration will deploy Falco in a default configuration which is based
on available Falco versions and platfrom settings. We anticipate that for most
deployemnts the defaults will be

- the latest currently available Falco version
- the [falco rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
ruleset, possible with some extensions to avoid false positive events in an 
empty cluster
- the `cluster` storage option

This means that the configuration above will be expanded to

```yaml
    - type: shoot-falco-service
      providerConfig:
        kind: FalcoServiceConfig
        apiVersion: falco.extensions.gardener.cloud/v1alpha1
        falcoVersion: 0.39.2
        autoUpdate: true
        resources: gardener
        gardener:
          useFalcoRules: true
          useFalcoIncubatingRules: false
          useFalcoSandboxRules: false
        output:
          logFalcoEvents: false
          eventCollector: cluster
```

## Configuration details

These are all configuration options which are exaplained below.

```yaml
  - type: shoot-falco-service
    providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
      # optional, will use the latest version tagged as "supported"
      falcoVersion: 0.40.0
      # optional, will always default to true
      autoUpdate: true|false
      # optional, "gardener" or "falcoctl", will default to "gardener"
      resources: gardener
      gardener:
        # optional, defaults to true
        useFalcoRules: true
        # optional, defaults to false
        useFalcoIncubatingRules: false
        # optional, defaults to false
        useFalcoSandboxRules: false
        # references configmaps in project namespace containing custom rules
        customRules:
        - rules1
      falcoctl:
        # Falcoctl configuration as defined in 
        indexes:
        - name: ...
          url: ...
        # allowed values are "plugins" and "rulesfile"
        allowdTypes:
        - plugins
        - rulesfile
        # optional, install rules and/or plugins during falco pod startup
        install:
          resolveDeps: reue|false
          refs:
          # list of artifacts to be installed
          - falco-rules:3
        follow:
          # list of artifacts to be updated
          refs:
          - falco-rules:3
          # how often to check for updates
          every: 6h
      # Configure where to store events
      output:
        # this setting make Falco post evente to standard outut (visible in pod log)
        logFalcoEvents: true|false
        # 
        eventCollector: cluster|central|custom|none
        # "custom" required webhook configuration
        customWebhook:
          secretRef: webhook-secret
```

## Versions and Update strategy

With `falcoVersion` the Falco version can be specified from one of the 
non-expired Falco versions configured in the [Falco profile](falco-profile.md). If
omitted, the latest version tagged as supported will be chosen from the Falco
profile.

With `autoUpdate` set to `false` users can opt out of automated Falco updates,
for example if there is a possibility that certain Falco rules are not compatible
with a newer Falco version. When `autoUpdate` is set to true the extension will
always update Falco to the latest Falco version which is tagged as supported
in the Falco profile. No automated Falco updates will be applied if `autoUpdate`
is set to false. The only exception to this policy is when the configured Falco 
version has expired (`expirationDate` is in the past). The Falco version will 
then be updated to the next non-expired version.

## Configuring rules and plugins

The `resources` setting specifies whether Falco rules are managed by Gardener
(`gardener`) or whether rules are managed by Falcoctl (`falcoctl`). The default
is `gardener`. The falcoctl configuration is described [here](falcoctl-configuration.md).

If `gardener` is configured the details can be specified in the `gardener`
section:

```yaml
      gardener:
        # optional, defaults to true
        useFalcoRules: true
        # optional, defaults to false
        useFalcoIncubatingRules: false
        # optional, defaults to false
        useFalcoSandboxRules: false
        # references configmaps in project namespace containing custom rules
        customRules:
        - my-custom-rules
        - more-curstom-rules
        ...
```

Falco rules, Falco incubating rules, and Falco sandbox rules are rules developed
and provided by the [Falco community](https://github.com/falcosecurity/rules).
The Falco rules have been extended not to emit any false positive events in 
an empty Kubernetes cluster managed by Gardener. Note, that this extension 
has not been done for the incubating- and sandbox rules which will likely emit 
false positive events even in an empty cluster.

These rules can be extended or replaced by using the custom rules section. Custom
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
  myrules-extended.yaml |-
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

1. Falco rules (if set to true)
2. Falco incubating rules  (if set to true)
3. Falco Sandbox rules  (if set to true)
4. Files from the first custom rule config map specified in the `customRules` array. 
The ordering is based lexicographical string comparison of the contained 
files.
5. Files from the second custom rule ConfigMap.
...

## Configuring outputs

Note: this section outlines output configurations. More details about their
implementations can be found in the [Falco outputs](falco-outputs.md) section.

Falco can be configured to post events to several internal and external 
storage providers by configuring the `eventCollector`:

- `none`:  do not post the events anywhere, just write them to the pod log 
  (`logFalcoEvents` must be set to true)
- `central`: post event to a central storage which might be offered by the
infrastructure  provider
- `cluster`: post events to the local cluster logging stack
- `custom`: post events to a custom web server.

Out of these configurations `custom` requires additional configuration:

```yaml
      output:
        eventCollector: custom
        # "custom" requires webhook configuration
        customWebhook:
          secretRef: webhook-secret
```

The `secretRef` references a secret which must be defined in the resources 
section of the shoot manifest:

```yaml
  resources:
  - name: webhook-secret
    resourceRef:
      apiVersion: v1
      kind: Secret
      name: my-webhook-secret-config
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
