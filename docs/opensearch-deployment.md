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
    --host backend-sf-XXXX.example.com \
    --dashboards-host dashboards-sf-XXXX.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --landscape staging \
    --landing-index falco-events

# Deploy combined tenant (read access across all landscapes):
./opensearch/deploy.sh \
    --host backend-sf-XXXX.example.com \
    --dashboards-host dashboards-sf-XXXX.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --combined

# Deploy shared resources only (pipeline, template, ISM policy, shared writer role):
./opensearch/deploy.sh \
    --host backend-sf-XXXX.example.com \
    --user admin --pass-file ./secret.txt \
    --prefix falco --shared-only \
    --landing-index falco-events
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
| `--landing-index` | Yes | — | Index falcosidekick writes to |
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
    └── tenant.json.tmpl            # Tenant definition
```
