# [Gardner Extension for Falco](https://gardener.cloud)

This controller implements Gardener's extension contract for deploying and managing Falco in shoot clusters.

# Extension Resources

Example extension resource:

```
apiVersion: extensions.gardener.cloud/v1alpha1
kind: Extension
metadata:
  name: shoot-falco-service
  namespace: shoot--project--abc
spec:
  providerConfig:
    apiVersion: falco.extensions.gardener.cloud/v1alpha1
    kind: FalcoServiceConfig
    useFalcoIncubatingRules: true
    useFalcoSandboxRules: true
  type: shoot-falco-service
```
