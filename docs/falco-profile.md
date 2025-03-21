# Falco Profile

Similar to the cloud profile there is a Falco profile resource in the 
Garden cluster which lists available Falco versions and supporting 
components such as Falcosidekick and falcoctl. The purpose of this resource is
to maintain available version for the user as well as for the Gardener 
Falco extension.

```
$ kubectl get falcoprofile falco -o yaml
apiVersion: falco.gardener.cloud/v1alpha1
kind: FalcoProfile
metadata:
  name: falco
spec:
  images:
    falco:
    - repository: europe-docker.pkg.dev/sap-se-gcp-k8s-delivery/releases-public/registry-1_docker_io/falcosecurity/falco-distroless
      tag: sha256:10b156b272cd2334a808dd58e266db8b70a495df5316ab491369130c3bdaf011
      version: 0.39.1
    - repository: europe-docker.pkg.dev/sap-se-gcp-k8s-delivery/releases-public/registry-1_docker_io/falcosecurity/falco-distroless
      tag: sha256:4bf7144f69292997368ac9077fb509513d1946aa252854430c0c87299ed4f04e
      version: 0.39.2
    - repository: europe-docker.pkg.dev/sap-se-gcp-k8s-delivery/releases-public/registry-1_docker_io/falcosecurity/falco
      tag: sha256:2bf64100eafe0795860a7765e848627834cb2c185c0b736442f797f5381df698
      version: 0.40.0
    falcoctl:
    - repository: europe-docker.pkg.dev/sap-se-gcp-k8s-delivery/releases-public/registry-1_docker_io/falcosecurity/falcoctl
      tag: sha256:c10998f438f1dcf4a6fb1b3f58aeadf90f05949c3018b1b1caf464d72e13e52d
      version: 0.11.0
    [...]
    falcosidekick:
    - repository: europe-docker.pkg.dev/sap-se-gcp-k8s-delivery/releases-public/registry-1_docker_io/falcosecurity/falcosidekick
      tag: sha256:8d3d4658761bb80d1657f421274fcf3306038f380aef8ce730d2e115408f7876
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

The falcoctl and falcosidekick sections are used internally by the 
extension to select a suitable version.