# OpenSearch Deployment

This document describes how to set up OpenSearch for multi-landscape Falco event ingestion using the `opensearch/deploy.sh` script.

## Architecture

Multiple Gardener landscapes (e.g. staging, production) report Falco events into the same OpenSearch instance. The setup provides:

- **Per-landscape indices** with ISM-managed daily rollover and automatic retention
- **Ingest pipeline** that extracts `project`, `cluster`, and `landscape` from the Gardener `cluster_id` and routes documents to the correct landscape index
- **Write aliases** that allow ISM to create new rollover indices without requiring `auto_create_index: true`
- **Per-landscape tenants** in OpenSearch Dashboards with read-only dashboards
- **Combined tenant** for cross-landscape aggregated views
- **RBAC roles** with convention-based OIDC backend role mappings

### Data Flow

```
falcosidekick → landing index (e.g. "falco-events")
  → index template matches → attaches ingest pipeline
  → pipeline grok extracts landscape from cluster_id
  → pipeline sets _index to write alias (e.g. "falco-staging")
  → alias resolves to current write index (e.g. "falco-staging-000001")
  → ISM rolls over daily → creates "falco-staging-000002", etc.
```

## Prerequisites

- OpenSearch cluster with ISM plugin enabled
- Admin credentials with permissions to create pipelines, templates, indices, roles, and tenants
- `curl` and `jq` installed
- The `dashboard.ndjson` file (exported from OpenSearch Dashboards)

## Usage

```bash
# Deploy everything for a landscape (shared resources + landscape-specific):
./opensearch/deploy.sh \
    --host opensearch.example.com \
    --dashboards-host dashboards.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --landscape staging

# Deploy combined tenant (read access across all landscapes):
./opensearch/deploy.sh \
    --host opensearch.example.com \
    --dashboards-host dashboards.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --combined

# Deploy shared resources only (pipeline, template, ISM policy, shared writer role):
./opensearch/deploy.sh \
    --host opensearch.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --shared-only
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--host` | Yes | — | OpenSearch backend endpoint |
| `--dashboards-host` | For dashboards | — | OpenSearch Dashboards endpoint |
| `--user` | Yes | — | Admin username |
| `--pass-file` | Yes | — | Path to file containing the password |
| `--prefix` | Yes | — | Index prefix (e.g. `falco`, `oclaf`) |
| `--landscape` | For per-landscape | — | Landscape name (e.g. `staging`, `production`) |
| `--combined` | Flag | — | Deploy combined tenant (uses `<prefix>-*`) |
| `--shared-only` | Flag | — | Deploy only shared resources |
| `--retention` | No | 180 | Days before index deletion |

## What Gets Created

### Shared Resources (idempotent, deployed by all modes)

| Resource | Name | Purpose |
|----------|------|---------|
| Ingest pipeline | `<prefix>-ingest` | Grok + index routing |
| Index template | `<prefix>-template` | Mappings + pipeline attachment |
| ISM policy | `<prefix>-rollover` | Daily rollover + retention |
| Role | `<prefix>_writer` | Write access to all `<prefix>-*` |
| Role mapping | `<prefix>_writer` | Maps backend role `<prefix>-writer` |

### Per-Landscape Resources

| Resource | Name |
|----------|------|
| Bootstrap index | `<prefix>-<landscape>-000001` |
| Write alias | `<prefix>-<landscape>` |
| Reader role | `<prefix>_<landscape>_reader` |
| Writer role | `<prefix>_<landscape>_writer` |
| Tenant | `<prefix>_<landscape>` |
| Dashboards | Imported into tenant |
| Role mappings | For reader and writer |

### Combined Resources

| Resource | Name |
|----------|------|
| Reader role | `<prefix>_combined_reader` |
| Tenant | `<prefix>_combined` |
| Dashboards | Index pattern = `<prefix>-*` |
| Role mapping | For combined reader |

## OIDC Backend Role Convention

The script creates role mappings using this naming convention. Your OIDC provider must issue matching group claims:

| OpenSearch Role | Expected OIDC Backend Role | Access |
|----------------|---------------------------|--------|
| `<prefix>_<landscape>_reader` | `<prefix>-<landscape>-reader` | Read one landscape |
| `<prefix>_<landscape>_writer` | `<prefix>-<landscape>-writer` | Write one landscape |
| `<prefix>_combined_reader` | `<prefix>-combined-reader` | Read all landscapes |
| `<prefix>_writer` | `<prefix>-writer` | Write all landscapes |

## Tenants and Dashboards

Tenants serve as environment selectors in OpenSearch Dashboards. Users switch between tenants via the tenant dropdown to view different landscapes.

- Dashboards are **read-only** for users (`kibana_all_read` permission)
- Users can still interact (filter, drill down, change time range) without modifying dashboard definitions
- Each tenant gets the same dashboard structure, pointed at a different index pattern
- The combined tenant uses `<prefix>-*` to show events from all landscapes

## Idempotency

The script is safe to run multiple times:

- Pipelines, templates, roles, and tenants are overwritten via PUT
- The bootstrap index is only created if the write alias doesn't already exist
- Dashboards are imported with `?overwrite=true`

## Adding a New Landscape

Simply run the script with the new landscape name:

```bash
./opensearch/deploy.sh \
    --host ... --user ... --pass-file ... \
    --prefix falco --landscape newenv \
    --dashboards-host ... --landing-index falco-events
```

The ISM policy and ingest pipeline already handle any landscape that appears in the `cluster_id` field.

## Verification

After deployment, verify:

1. Pipeline: `GET _ingest/pipeline/<prefix>-ingest`
2. Alias: `GET _alias/<prefix>-<landscape>`
3. ISM: `GET _plugins/_ism/explain/<prefix>-<landscape>-000001`
4. Test routing: index a document to the landing index with a valid `cluster_id` and confirm it appears in the correct landscape index
5. Dashboards: log in, switch to the landscape tenant, confirm the dashboard loads

## File Structure

```
opensearch/
├── deploy.sh                       # Main deployment script
├── grok-patterns.json              # Grok pattern for cluster_id parsing
└── templates/
    ├── dashboard.ndjson            # Source dashboard export (template)
    ├── pipeline.json.tmpl          # Ingest pipeline
    ├── index-template.json.tmpl    # Index template with mappings
    ├── ism-policy.json.tmpl        # ISM rollover + retention policy
    ├── bootstrap-index.json.tmpl   # Initial index with write alias
    ├── role-reader.json.tmpl       # Reader role
    ├── role-writer.json.tmpl       # Writer role
    ├── role-mapping.json.tmpl      # OIDC backend role mapping
    ├── tenant.json.tmpl            # Tenant definition
    ├── notification-channel.json.tmpl  # Slack notification channel
    ├── monitor-heartbeat.json.tmpl     # Missing heartbeat monitor
    └── monitor-critical-events.json.tmpl # Critical/emergency event monitor
```

## Alerting

The script can set up Slack-based alerting for a landscape:

```bash
./opensearch/deploy.sh \
    --host opensearch.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --landscape staging \
    --setup-alerting --slack-webhook-file ./slack-webhook.txt
```

This creates:

1. **Missing Heartbeat Monitor** — checks every 10 minutes, alerts if any cluster's last heartbeat is >20 minutes old
2. **Critical/Emergency Events Monitor** — checks every 5 minutes, alerts on any Critical or Emergency priority events with top rules and clusters in the message

Prerequisites:
- The landscape must already be deployed (alias must exist)
- A Slack incoming webhook URL (stored in a file, not committed to git)

## Anomaly Detection

OpenSearch includes a built-in Anomaly Detection plugin (Random Cut Forest algorithm) that learns "normal" patterns and alerts on deviations. This is recommended as a manual setup after sufficient data has been collected.

### Useful Detectors

| Detector | What it catches |
|----------|----------------|
| Event volume spike per cluster | Compromised node, misconfigured workload, runaway rule |
| New rule appearing | New attack pattern, or a rule enabled unexpectedly |
| Sudden drop to zero events | Falco/falcosidekick silently broken (complements heartbeat monitor) |
| Spike in a specific priority level | Escalation from mostly Warnings to lots of Criticals |

### Example: Event Volume Spike Detector

Create via Dashboards UI (Anomaly Detection → Create detector) or API:

```json
POST _plugins/_anomaly_detection/detectors
{
  "name": "falco-<landscape>-volume-spike",
  "description": "Detects unusual event volume per cluster",
  "indices": ["<prefix>-<landscape>-*"],
  "time_field": "@timestamp",
  "detection_interval": { "period": { "interval": 10, "unit": "MINUTES" } },
  "feature_attributes": [
    {
      "feature_name": "event_count",
      "feature_enabled": true,
      "aggregation_query": {
        "event_count": { "value_count": { "field": "@timestamp" } }
      }
    }
  ],
  "category_field": ["output_fields.cluster_id.keyword"],
  "window_delay": { "period": { "interval": 2, "unit": "MINUTES" } }
}
```

The `category_field` creates a high-cardinality detector — it learns a separate baseline per cluster, so a noisy cluster won't mask anomalies in a quiet one.

### Practical Considerations

- **Requires data history** — needs 1-2 weeks of data to learn what's "normal". Not useful on day one.
- **False positives** — new clusters, deployments, and legitimate workload changes will trigger it initially. Tuning takes time.
- **Resource usage** — high-cardinality detectors (per cluster) use more memory. Fine for tens of clusters, monitor carefully with hundreds.
- **Best created interactively** — the Dashboards UI allows previewing anomaly results before enabling, making it easier to tune thresholds.
- **Alerting integration** — once a detector is running, create a monitor that queries anomaly results and fires when the anomaly grade exceeds a threshold (e.g. >0.7).
