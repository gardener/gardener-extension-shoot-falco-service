# Gardener Falco Extension Configuration

The Gardner Falco extension consists of an extension binary
(`gardener-extension-shoot-falco-service`) as well as an admission binary
(`gardener-extension-admission-shoot-falco-service`) which contains a
mutating- and validating webhook as well as the maintenacne controller.

## The extension `gardener-extension-shoot-falco-service`

The extension binary uses a non-standard configuration parameter
`--config-file` whih points to a configuration YAML file as shown below:

```
apiVersion: falco.extensions.config.gardener.cloud/v1alpha1 
kind: Configuration
falco:
  certificateLifetime: 2100h
  cerfificateRenewAfter: 1600h
  priorityClassName: gardener-shoot-system-900
  centralStorage:
    tokenLifetime: "720h"
    url: << ingestor URL >>
    tokenIssuerPrivateKey: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
```

* `certificateLifetime`: Lifetime of certificates generated for communication between Falco and Falcosidekick.
* `certificateRenewAfter`: Time period after which certificates are renewed.
* `priorityClassName`: Priority class used for Falco when deployed.
* `centralStorage`: optional configuration for central event storage (see below)
  * `tokenLifetime`: Lifetime of the JWT token generated during each reconcile for sending events to central storage.
  * `ingestorURL`: URL of the Falco event ingestor
  * `tokenIssuerPrivateKey`: Private key used for issuing the JWT token.

## Central storage

Falcosidekick can optionally send events to a central storage location. This 
requires a central storage setup based on the following projects:

- [falco-event-ingestor](https://github.com/gardener/falco-event-ingestor)
- [falco-event-provider](https://github.com/gardener/falco-event-provider)
- [falco-event-db-schema](https://github.com/gardener/falco-event-db-schema)

If this is set users can configure `central` as the destination for Falco
events.

## The webhook `gardener-extension-admission-shoot-falco-service`

The webhook can be configured to enforce usage restrictions:

- The extension may only deploy Falco in clusters where the gardener project 
namespace is annotated with

```yaml
falco.gardener.cloud/enabled=true
```

- The "central" storage option may only be configured from shoot clusters if 
their project namespace is annotated with 

```yaml
falco.gardener.cloud/centralized-logging=true
```

The restrictions can be enabled by passing `--restricted-usage` and
`--restricted-centralized-logging` to the webhook binary.
