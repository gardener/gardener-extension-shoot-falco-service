# Falco Profile

Similar to the cloud profile, the Falco profile resource in the Garden
cluster lists available Falco versions and supporting components such as 
Falcosidekick. This resource helps manage available versions for users and the
Gardener Falco extension.

```bash
$ kubectl get falcoprofile falco -o yaml
apiVersion: falco.gardener.cloud/v1alpha1
kind: FalcoProfile
metadata:
  name: falco
spec:
  images:
    falco:
    - repository: falcosecurity/falco-distroless
      tag: 0.39.1
      version: 0.39.1
    - repository: falcosecurity/falco-distroless
      tag: 0.39.2
      version: 0.39.2
    - repository: falcosecurity/falco
      tag: 0.40.0
      version: 0.40.0
    falcosidekick:
    - repository: falcosecurity/falcosidekick
      tag: 2.31.1
      version: 2.31.1
    [...]
  versions:
    falco:
    - classification: deprecated
      expirationDate: "2025-04-15T23:59:59Z"
      rulesVersion: 3.2.0
      version: 0.39.1
    - classification: supported
      rulesVersion: 3.2.0
      version: 0.39.2
    - classification: preview
      rulesVersion: 3.2.0
      version: 0.40.0
    falcoctl:
    - classification: deprecated
      version: 0.10.1
    - classification: supported
      version: 0.11.0
    falcosidekick:
    - classification: deprecated
      version: 2.29.0
    - classification: supported
      version: 2.30.0
    - classification: supported
      version: 2.31.1
```

Any of the non-expired Falco versions can be configured in the shoot manifest.
If no version is specified in the shoot manifest the latest Falco version
tagged as "supported" will be used.

The `falcosidekick` section is used internally by the extension.