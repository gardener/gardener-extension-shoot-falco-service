# Gardener Falco Extension - Managed Falco in shoot clusters

## Introduction

This extension consistently deploys Falco into shoot clusters, manages it, and 
provides several options to persist runtime events for further processing.
It can be enabled by users by simply adding an extension configuration to the 
shoot manifest. 

Falco is a cloud native runtime security tool for Linux operating systems. It
is designed to detect and alert on abnormal behavior and potential security 
threats in real-time [1]. We have deployed it in the Gardener landscape and
can confirm that it is well suited for detecting events that are not ordinary
runtime events. This includes but is not limited to debugging activities,
changing host configurations or installing software in containers. Apart from
legal debugging activities those types of events most likely indicate malicious
behavior.

Falco is a powerful runtime threat detection engine but comes with limited
means to deploy on many Kubernetes clusters or sophisticated event analysis
and visualization for many clusters. These features are usually provided by
commercial products: some of them rely on Falco as the threat detection
engine, for example from [Sysdig](https://sysdig.com/products/platform/) and
[Trend Micro](https://www.trendmicro.com/en_us/business/products/one-platform.html).

## Getting Started

For the most basic setup add the following default configuration in `.spec.extensions`
to the shoot manifest. It is sufficient to deploy Falco:

```yaml
spec:
  extensions:
  - providerConfig:
      apiVersion: falco.extensions.gardener.cloud/v1alpha1
      kind: FalcoServiceConfig
    type: shoot-falco-service
```

Based on this extension configuration the Falco extension will deploy the 
lasted Falco version configured as `supported` and ensure it is kept
up to date by always updating it to the latest available Falco version configured 
for the landscape. The ruleset will be managed by Gardener and will provide
[standard rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
which are designed to offer basic detection capabilities.
This is a tradeoff between sophisticated detection capabilities and the
number of false positive events. More rules mean
better threat detection capabilities but potentially tens of thousands of
false-positive events. The standard Falco ruleset has been tweaked not to emit 
any false positive events in an empty cluster managed by Gardener. Depending on 
the workload rule exception may need to be defined. 

To make sure everything works as expected generate some events by
running the following command on the shoot cluster:

```
$ kubectl run sample-events -it --rm  --image falcosecurity/event-generator -- run syscall --all
If you don't see a command prompt, try pressing enter.
INFO action executed                               action=syscall.KubernetesClientToolLaunchedInContainer
INFO sleep for 100ms                               action=syscall.ReadSshInformation
INFO action executed                               action=syscall.ReadSshInformation
INFO sleep for 100ms                               action=syscall.FindAwsCredentials
INFO action executed                               action=syscall.FindAwsCredentials
INFO sleep for 100ms                               action=syscall.DetectCryptoMinersUsingTheStratumProtocol
INFO action executed                               action=syscall.DetectCryptoMinersUsingTheStratumProtocol
INFO sleep for 100ms                               action=syscall.PotentialLocalPrivilegeEscalationViaEnvironmentVariablesMisuse
INFO action executed                               action=syscall.PotentialLocalPrivilegeEscalationViaEnvironmentVariablesMisuse
INFO sleep for 100ms                               action=syscall.DbProgramSpawnedProcess
INFO spawn as "mysqld"                             action=syscall.DbProgramSpawnedProcess args="^helper.ExecLs$"
INFO sleep for 100ms                               action=helper.ExecLs as=mysqld
INFO action executed                               action=helper.ExecLs as=mysqld
INFO sleep for 100ms                               action=syscall.WriteBelowRpmDatabase
INFO action executed                               action=syscall.WriteBelowRpmDatabase
INFO sleep for 100ms                               action=syscall.LaunchRemoteFileCopyToolsInContainer
INFO sleep for 100ms                               action=syscall.LaunchIngressRemoteFileCopyToolsInContainer
[...]
```

Once messages appear let it run for a few seconds and then kill it with Ctrl+C.

By default, events are forwarded to the cluster logging stack where they are 
stored in the vali database. You can query the database via the cluster Plutono
with [LogQL queries](https://grafana.com/docs/loki/latest/query/) like the
following:

```
{rule=~".+", tags=~".+", source=~".+"}
```

## Further Details

This is a minimal configuration. There are several options to customize 
Falco deployments in shoot clusters. It is possible to select specific 
supported Falco versions, provide rule exceptions as well as custom rules, and 
configure various outputs for Falco events.

[Falco profiles](falco-profile.md) contain information on available Falco 
versions and their support status. A guide to all configuration options 
is [here](falco-configuration.md). [Falcoctl](falcoctl-configuration.md) is a
community project to configure Falco rules-, and plugins from a central repository.

The Gardener Falco extension is flexible with regards to storing Falco events.
The [Falco outputs](falco-outputs.md) document outlines current options and
default settings.