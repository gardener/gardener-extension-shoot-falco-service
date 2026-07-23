# OpenSearch Deployment

This document describes how to set up OpenSearch for multi-landscape Falco event ingestion using the `opensearch/deploy.sh` script.

## Architecture

Multiple Gardener landscapes (e.g. staging, production) report Falco events into the same OpenSearch instance. The setup provides:

- **Per-landscape indices** with ISM-managed daily rollover and automatic retention
- **Runtime fields** that extract `project`, `cluster`, and `landscape` from the Gardener `cluster_id` at query time (no ingest pipeline required)
- **Per-landscape tenants** in OpenSearch Dashboards with read-only dashboards
- **Combined tenant** for cross-landscape aggregated views
- **RBAC roles** with OIDC backend role mappings for human viewers and admins, and internal users for falcosidekick ingest

### Data Flow

```
falcosidekick (configured with index: falco-<landscape>, suffix: daily)
  → writes directly to falco-<landscape>-<date> (e.g. "falco-staging-2026.07.08")
  → index template matches falco-* → applies field mappings
  → ISM policy matches falco-*-* → daily rollover + 180d retention
  → runtime fields compute project/cluster/landscape from output_fields.cluster_id at query time
```

> **Note:** This setup does not use an OpenSearch ingest pipeline. `project`, `cluster`, and `landscape` are exposed as runtime fields computed via Painless script from `output_fields.cluster_id`. They are fully available in Discover, dashboards, and aggregations.

## Prerequisites

- OpenSearch cluster with ISM plugin enabled
- Admin credentials with permissions to create index templates, indices, roles, and tenants
- `curl` and `jq` installed
- The `dashboard.ndjson` file (exported from OpenSearch Dashboards)

## Usage

```bash
# Deploy everything for a landscape (shared resources + landscape-specific):
./opensearch/deploy.sh \
    --host opensearch.example.com \
    --dashboards-host dashboards.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --landscape staging \
    --backend-role-prefix btp-falco-storage

# Deploy combined tenant (read access across all landscapes):
./opensearch/deploy.sh \
    --host opensearch.example.com \
    --dashboards-host dashboards.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --combined \
    --backend-role-prefix btp-falco-storage

# Deploy shared resources only (index template, ISM policy):
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
| `--prefix` | Yes | — | Resource prefix for index names, role names, and tenant names (e.g. `falco`, `oclaf`) |
| `--backend-role-prefix` | For landscape/combined | `--prefix` | Prefix for OIDC group names as issued by the identity provider (e.g. `btp-falco-storage`). Maps to `<brp>-viewer` and `<brp>-admin`. |
| `--landscape` | For per-landscape | — | Landscape name (e.g. `dev`, `staging`, `production`) |
| `--combined` | Flag | — | Deploy combined tenant (uses `<prefix>-*`) |
| `--shared-only` | Flag | — | Deploy only shared resources |
| `--retention` | No | 180 | Days before index deletion |

## What Gets Created

### Shared Resources (idempotent, deployed by all modes)

| Resource | Name | Purpose |
|----------|------|---------|
| Index template | `<prefix>-template` | Mappings + runtime fields |
| ISM policy | `<prefix>-rollover` | Daily rollover + retention |

### Per-Landscape Resources

| Resource | Name |
|----------|------|
| Viewer role | `<prefix>_<landscape>_viewer` |
| Admin role | `<prefix>_<landscape>_admin` |
| Writer role | `<prefix>_<landscape>_writer` |
| Tenant | `<prefix>_<landscape>` |
| Dashboards | Imported into tenant |
| Role mappings | For viewer and admin (OIDC); writer mapped to internal users via `manage-writer-users.sh` |

### Combined Resources

| Resource | Name |
|----------|------|
| Viewer role | `<prefix>_combined_viewer` |
| Tenant | `<prefix>_combined` |
| Dashboards | Index pattern = `<prefix>-*` |
| Role mapping | For combined viewer |

## OIDC Backend Role Mapping

Human users authenticate via OIDC. OpenSearch extracts their group claims as backend roles and maps them to OpenSearch roles via the role mappings created by `deploy.sh`.

The backend role names are controlled by your identity provider — use `--backend-role-prefix` to specify the prefix your IdP uses. The script expects exactly two group names:

| OpenSearch Role | Expected OIDC Backend Role | Access |
|----------------|---------------------------|--------|
| `<prefix>_<landscape>_viewer` | `<backend-role-prefix>-viewer` | Read Falco events and dashboards for this landscape |
| `<prefix>_<landscape>_admin` | `<backend-role-prefix>-admin` | Full index and tenant access for this landscape |
| `<prefix>_combined_viewer` | `<backend-role-prefix>-viewer` | Read Falco events across all landscapes |

The `_writer` role (`<prefix>_<landscape>_writer`) is used exclusively by falcosidekick internal users and has no OIDC mapping. These users are managed separately via `manage-writer-users.sh`.

## Tenants and Dashboards

Tenants serve as environment selectors in OpenSearch Dashboards. Users switch between tenants via the tenant dropdown to view different landscapes.

- **Viewers** get `kibana_all_read` permission — they can filter, drill down, and change time ranges but cannot modify dashboard definitions
- **Admins** get `kibana_all_write` permission — full tenant access including creating, modifying, and deleting dashboards and saved objects
- Each tenant gets the same dashboard structure, pointed at a different index pattern
- The combined tenant uses `<prefix>-*` to show events from all landscapes

## Idempotency

The script is safe to run multiple times:

- Templates, roles, and tenants are overwritten via PUT
- The bootstrap index is only created if the write alias doesn't already exist
- Dashboards are imported with `?overwrite=true`

## Adding a New Landscape

Simply run the script with the new landscape name:

```bash
./opensearch/deploy.sh \
    --host ... --user ... --pass-file ... \
    --prefix falco --landscape newenv \
    --backend-role-prefix btp-falco-storage \
    --dashboards-host ...
```

The ISM policy handles any landscape — falcosidekick simply needs to be configured with `index: <prefix>-<landscape>` and `suffix: daily` for the target landscape.

## Verification

After deployment, verify:

1. Template: `GET _index_template/<prefix>-template`
2. ISM: `GET _plugins/_ism/policies/<prefix>-rollover`
3. Runtime fields: index a document with a valid `cluster_id` and confirm `project`, `cluster`, `landscape` are returned in a search
4. Dashboards: log in, switch to the landscape tenant, confirm the dashboard loads

## File Structure

```
opensearch/
├── deploy.sh                       # Main deployment script
├── manage-writer-users.sh          # Manages falcosidekick internal users per landscape
├── grok-patterns.json              # Cluster_id regex (used by runtime fields in index template)
└── templates/
    ├── dashboard.ndjson            # Source dashboard export (template)
    ├── pipeline.json.tmpl          # Ingest pipeline (no longer used, kept for reference)
    ├── index-template.json.tmpl    # Index template with mappings and runtime fields
    ├── ism-policy.json.tmpl        # ISM rollover + retention policy
    ├── bootstrap-index.json.tmpl   # Initial index with write alias
    ├── role-viewer.json.tmpl       # Viewer role (OIDC, read-only)
    ├── role-admin.json.tmpl        # Admin role (OIDC, full tenant+index access)
    ├── role-writer.json.tmpl       # Writer role (falcosidekick internal users)
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
