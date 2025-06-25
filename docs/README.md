# Gardener Falco Extension - Managed Falco in shoot clusters

## Introduction

This extension deploys and manages Falco in shoot clusters in a Gardener native
way, offering options to persist runtime events for further processing. Users
may enable it by adding an extension configuration to the shoot manifest.

Falco is a cloud-native runtime security tool for Linux, designed to detect
and alert on abnormal behavior and potential security threats in real-time
([falco.org](https://falco.org/)).
In our Gardener landscapes, it effectively detects unusual runtime events,
such as debugging activities, host configuration changes, or software
installations in containers. If not detected as part of legitimate debugging
activity, these events likely indicate malicious behavior.

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
  - type: shoot-falco-service
```

Based on this extension configuration the Falco extension will deploy the
latest Falco version configured as `supported` and ensure it is kept
up to date by always updating it to the latest available Falco version configured
for the landscape. The ruleset will be managed by Gardener and will provide
[standard rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
which are designed to offer basic detection capabilities.
This is a tradeoff between sophisticated detection capabilities and the
number of false positive events. More rules mean
better threat detection capabilities but potentially tens of thousands of
false-positive events. The standard Falco ruleset has been optimized not to emit
any false positive events in an empty cluster managed by Gardener. Depending on
the workload, rule exceptions may need to be defined.

To verify functionality, generate sample events by running the following command
within the shoot cluster:

``` bash
$ kubectl run sample-events -it --rm --image falcosecurity/event-generator -- run syscall --all

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

Once messages appear, let it run for a few seconds, and then end it with Ctrl+C.

By default, events are forwarded to the cluster logging stack and stored in the
Vali database. Query the database via Plutono using [LogQL queries](https://grafana.com/docs/loki/latest/query/),
such as:

```
{rule=~".+", tags=~".+", source=~".+"}
```

## Further Details

This minimal configuration can be customized further. Users can select specific
Falco versions, select from 3 rule files provided by the Falco community, add 
custom rules and specify event destinations. A full description of 
configuration options is available [here](falco-configuration.md).

[Falco profiles](falco-profile.md) contain information on available Falco 
versions and their support status.
