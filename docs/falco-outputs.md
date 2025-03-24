# Falco Outputs

## Do not forward Falco events (option `none`)

With this option, events are logged to Falco pod logs but not forwarded. Users can deploy custom tools to scrape pod logs and store events.

Falcosidekick is not deployed when this option is configured.

## Store events in the cluster logging stack (option `cluster`)

In this configuration, Falco events are forwarded to Falcosidekick, which uses the [Loki output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/loki.md) to send events to the cluster Vali database.

Events can be queried in the Vali section of the cluster Plutono UI using:
```
{rule=~".+", tags=~".+", source=~".+"}
```

More detailed on possible queries can be found in the 
[LogQL documentation](https://grafana.com/docs/loki/latest/query/).

## Store events centrally (option `central`)

Central storage is optional and may be provided as part of the Gardener landscape installation.

Falco events are forwarded to Falcosidekick, deployed alongside Falco. The [webhook output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/webhook.md) sends events to a central location configured by the Gardener installation. Events are forwarded using a cluster JWT token issued by the Falco extension.

The [Falco event ingestor](https://github.com/gardener/falco-event-ingestor) provides a REST API to receive Falco events. It validates event integrity, stores events in an SQL database, and implements configurable rate limiting per cluster to prevent overload.

The [Falco event provider](https://github.com/gardener/falco-event-provider) offers a REST API to access the database. Cluster users must present a valid token (with Viewer access for the Gardener project namespace) to retrieve Falco events for their cluster.
