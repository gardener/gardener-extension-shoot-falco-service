# Gardener Falco Extension Configuration

The Gardner Falco extension consists of an extension binary
(`gardener-extension-shoot-falco-service`) as well as an admission binary
(`gardener-extension-admission-shoot-falco-service`) which contains a
mutating- and validating webhook as well as the maintenacne controller.

## The extension

The extension binary uses a non-standard configuration parameter
`--config-file` whih points to a configuration YAML file as shown below:

```
apiVersion: falco.extensions.config.gardener.cloud/v1alpha1 
kind: Configuration 
falco: 
  certificateLifetime: 2100h
  cerfificateRenewAfter: 1600h
  priorityClassName: gardener-shoot-system-900
  tokenLifetime: "720h"
  ingestorURL: <<ingestor URL>>
  tokenIssuerPrivateKey: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
```

* `certificateLifetime`: Lifetime of certificates generated for communication between Falco and Falcosidekick.
* `certificateRenewAfter`: Time period after which certificates are renewed.
* `priorityClassName`: Priority class used for Falco when deployed.
* `tokenLifetime`: Lifetime of the JWT token generated during each reconcile for sending events to central storage.
* `ingestorURL`: URL of the Falco event ingestor.
* `tokenIssuerPrivateKey`: Private key used for issuing the JWT token.

## The webhook

The webhook can be configured to enforce usage restrictions:

- The extension may only deploy Falco in gardener projects annotated with

```yaml
falco.gardener.cloud/enabled=true
```

- The "central" storage option may only be configured from shoot clusters if 
their project is annotated with 

```yaml
falco.gardener.cloud/centralized-logging=true
```

The restrictions can be enabled by passing `--restricted-usage` and
`--restricted-centralized-logging` to the webhook binary.
