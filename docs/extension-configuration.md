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
  centralStorage:
    tokenLifetime: "720h"
    url: <ingestor URL>
    tokenIssuerPrivateKey: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
```

- `certificateLifetime`: Lifetime of certificates generated for communication between Falco and Falcosidekick.
- `certificateRenewAfter`: Time period after which certificates are renewed.
- `priorityClassName`: Priority class used for Falco when deployed.
- `centralStorage`: Optional configuration for central event storage (see below)
  - `tokenLifetime`: Lifetime of the JWT token generated during each reconcile for sending events to central storage.
  - `url`: URL of the Falco event ingestor.
  - `tokenIssuerPrivateKey`: Private key used for issuing the JWT token.

## Central Storage

Falcosidekick can optionally send events to a central storage location. This requires a central storage setup based on the following projects:

- [falco-event-ingestor](https://github.com/gardener/falco-event-ingestor)
- [falco-event-provider](https://github.com/gardener/falco-event-provider)
- [falco-event-db-schema](https://github.com/gardener/falco-event-db-schema)

If central storage is configured, users can set `central` as the destination for Falco events.

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
