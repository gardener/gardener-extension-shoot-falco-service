#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATES_DIR="$SCRIPT_DIR/templates"

usage() {
    cat <<'EOF'
Usage:
  deploy.sh tenant --host <host> --dashboards-host <host> --prefix <prefix> \
                   --landscape <name> --backend-role-prefix <brp> \
                   --user <user> --pass-file <file> [--retention <days>] [--simulate]

  deploy.sh global-tenant --host <host> --dashboards-host <host> --prefix <prefix> \
                          --user <user> --pass-file <file> [--simulate]

  deploy.sh alerting --host <host> --prefix <prefix> --landscape <name> \
                     --user <user> --pass-file <file> \
                     --slack-webhook-file <file> [--simulate]

Subcommands:
  tenant         Deploy a landscape tenant: index template, roles, role mappings,
                 Dashboards tenant, and dashboards/index-pattern for one landscape.
  global-tenant  Deploy the combined view into the OpenSearch global tenant:
                 index template and dashboards with index pattern <prefix>-*.
  alerting       Set up Slack alerting monitors for a landscape.

Options:
  --host                  OpenSearch backend endpoint
  --dashboards-host       OpenSearch Dashboards endpoint
  --user                  Admin username
  --pass-file             Path to file containing the admin password
  --prefix                Resource prefix, e.g. 'falco'
  --landscape             Landscape name, e.g. 'dev', 'staging', 'live' (tenant/alerting only)
  --backend-role-prefix   OIDC backend role prefix, e.g. 'btp-falco-storage-staging'.
                          The script appends '-viewer' and '-admin' to derive role names.
  --slack-webhook-file    Path to file containing the Slack incoming webhook URL (alerting only)
  --retention             Days before index deletion (default: 180, tenant only)
  --simulate              Print requests that would be sent without executing them

Resources created by 'tenant':
  Index template:  <prefix>-template  (pattern <prefix>-*)
  Roles:           <prefix>_<landscape>_viewer / _admin / _writer
  Role mappings:   <brp>-viewer -> <prefix>_<landscape>_viewer
                   <brp>-admin  -> <prefix>_<landscape>_admin
  Tenant:          <prefix>_<landscape>
  Dashboards:      index pattern <prefix>-<landscape>-*, dashboard, saved searches

Resources created by 'global-tenant':
  Index template:  <prefix>-template  (pattern <prefix>-*)
  Dashboards:      index pattern <prefix>-*, dashboard, saved searches (global tenant)
EOF
    exit 1
}

# --- Argument parsing ---

SUBCOMMAND="${1:-}"
if [[ -z "$SUBCOMMAND" || "$SUBCOMMAND" == "--help" || "$SUBCOMMAND" == "-h" ]]; then
    usage
fi
shift

HOST=""
DASHBOARDS_HOST=""
USER=""
PASS_FILE=""
PREFIX=""
LANDSCAPE=""
BACKEND_ROLE_PREFIX=""
SLACK_WEBHOOK_FILE=""
SLACK_WEBHOOK_URL=""
RETENTION=180
SIMULATE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)                 HOST="$2";                 shift 2 ;;
        --dashboards-host)      DASHBOARDS_HOST="$2";      shift 2 ;;
        --user)                 USER="$2";                 shift 2 ;;
        --pass-file)            PASS_FILE="$2";            shift 2 ;;
        --prefix)               PREFIX="$2";               shift 2 ;;
        --landscape)            LANDSCAPE="$2";            shift 2 ;;
        --backend-role-prefix)  BACKEND_ROLE_PREFIX="$2";  shift 2 ;;
        --slack-webhook-file)   SLACK_WEBHOOK_FILE="$2";   shift 2 ;;
        --slack-webhook-url)    SLACK_WEBHOOK_URL="$2";    shift 2 ;;
        --retention)            RETENTION="$2";            shift 2 ;;
        --simulate)             SIMULATE=true;             shift ;;
        --help|-h)              usage ;;
        *) echo "ERROR: Unknown option: $1"; usage ;;
    esac
done

# --- Validation ---

case "$SUBCOMMAND" in
    tenant|global-tenant|alerting) ;;
    *) echo "ERROR: Unknown subcommand '$SUBCOMMAND'"; usage ;;
esac

[[ -z "$HOST" ]]   && { echo "ERROR: --host is required";   usage; }
[[ -z "$PREFIX" ]] && { echo "ERROR: --prefix is required"; usage; }

if [[ "$SIMULATE" == "false" ]]; then
    [[ -z "$USER" ]]      && { echo "ERROR: --user is required";      usage; }
    [[ -z "$PASS_FILE" ]] && { echo "ERROR: --pass-file is required"; usage; }
fi

if [[ "$SUBCOMMAND" == "tenant" ]]; then
    [[ -z "$LANDSCAPE" ]]          && { echo "ERROR: tenant requires --landscape";          usage; }
    [[ -z "$BACKEND_ROLE_PREFIX" ]] && { echo "ERROR: tenant requires --backend-role-prefix"; usage; }
    [[ -z "$DASHBOARDS_HOST" ]]    && { echo "ERROR: tenant requires --dashboards-host";    usage; }
fi

if [[ "$SUBCOMMAND" == "global-tenant" ]]; then
    [[ -z "$DASHBOARDS_HOST" ]] && { echo "ERROR: global-tenant requires --dashboards-host"; usage; }
fi

if [[ "$SUBCOMMAND" == "alerting" ]]; then
    [[ -z "$LANDSCAPE" ]] && { echo "ERROR: alerting requires --landscape"; usage; }
    if [[ -n "$SLACK_WEBHOOK_FILE" ]]; then
        [[ ! -f "$SLACK_WEBHOOK_FILE" ]] && { echo "ERROR: Slack webhook file not found: $SLACK_WEBHOOK_FILE"; exit 1; }
        SLACK_WEBHOOK_URL="$(cat "$SLACK_WEBHOOK_FILE")"
    fi
    [[ -z "$SLACK_WEBHOOK_URL" ]] && { echo "ERROR: alerting requires --slack-webhook-file"; usage; }
fi

# Read password
if [[ "$SIMULATE" == "false" ]]; then
    [[ ! -f "$PASS_FILE" ]] && { echo "ERROR: Password file not found: $PASS_FILE"; exit 1; }
    PASS="$(cat "$PASS_FILE")"
else
    PASS=""
fi

# Ensure https:// prefix
[[ "$HOST" != https://* && "$HOST" != http://* ]] && HOST="https://$HOST"
[[ -n "$DASHBOARDS_HOST" && "$DASHBOARDS_HOST" != https://* && "$DASHBOARDS_HOST" != http://* ]] && DASHBOARDS_HOST="https://$DASHBOARDS_HOST"

# --- Helper functions ---

os_api() {
    local method="$1"
    local path="$2"
    local body="${3:-}"

    if [[ "$SIMULATE" == "true" ]]; then
        echo ""
        echo "  [SIMULATE] $method $HOST/$path"
        if [[ -n "$body" ]]; then
            echo "$body" | jq -C . 2>/dev/null || echo "$body"
        fi
        return 0
    fi

    local args=(-s -w "\n%{http_code}" -X "$method" -u "$USER:$PASS" -H "Content-Type: application/json")
    [[ -n "$body" ]] && args+=(-d "$body")

    local response http_code response_body
    response=$(curl "${args[@]}" "$HOST/$path")
    http_code=$(echo "$response" | tail -1)
    response_body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        echo "  OK ($http_code)"
        return 0
    elif [[ "$http_code" == "404" && "$method" == "GET" ]]; then
        return 1
    else
        echo "  FAILED ($http_code): $response_body"
        return 2
    fi
}

dashboards_api() {
    local method="$1"
    local path="$2"
    local tenant="$3"
    local file="${4:-}"

    if [[ "$SIMULATE" == "true" ]]; then
        echo ""
        echo "  [SIMULATE] $method $DASHBOARDS_HOST/$path (tenant: $tenant)"
        [[ -n "$file" ]] && echo "  [SIMULATE] body: $file ($(wc -l < "$file") lines)"
        return 0
    fi

    local args=(-s -w "\n%{http_code}" -X "$method" -u "$USER:$PASS" -H "osd-xsrf: true" -H "securitytenant: $tenant")
    [[ -n "$file" ]] && args+=(--form "file=@$file;type=application/ndjson")

    local response http_code response_body
    response=$(curl "${args[@]}" "$DASHBOARDS_HOST/$path")
    http_code=$(echo "$response" | tail -1)
    response_body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        local success
        success=$(echo "$response_body" | jq -r '.success // true')
        if [[ "$success" == "false" ]]; then
            local errors
            errors=$(echo "$response_body" | jq -r '.errors // [] | map(.error.message // .error.type) | join(", ")')
            echo "  FAILED (import errors): $errors"
            echo "  Full response: $response_body"
            return 2
        fi
        echo "  OK ($http_code)"
        return 0
    else
        echo "  FAILED ($http_code): $response_body"
        return 2
    fi
}

render_template() {
    local template="$1"
    shift
    [[ ! -f "$template" ]] && { echo "ERROR: Template file not found: $template"; exit 1; }
    local content
    content=$(cat "$template")
    while [[ $# -gt 0 ]]; do
        content=$(echo "$content" | sed "s|{{${1}}}|${2}|g")
        shift 2
    done
    echo "$content"
}

import_dashboards() {
    local tenant="$1"
    local index_pattern_title="$2"
    local display_name="$3"
    local pattern_id="${tenant}-pattern"

    local dashboard_source="$TEMPLATES_DIR/dashboard.ndjson"
    local searches_source="$TEMPLATES_DIR/saved-searches.ndjson"
    [[ ! -f "$dashboard_source" ]] && { echo "  ERROR: $dashboard_source not found"; exit 1; }
    [[ ! -f "$searches_source" ]]  && { echo "  ERROR: $searches_source not found";  exit 1; }

    echo "  Importing dashboards to tenant '$tenant'..."

    local tmp_file tmp_searches
    tmp_file=$(mktemp --suffix=.ndjson)
    tmp_searches=$(mktemp --suffix=.ndjson)
    trap "rm -f $tmp_file $tmp_searches" RETURN

    jq -c '
        if .type == "index-pattern" then
            .id = "'"$pattern_id"'" |
            .attributes.title = "'"$index_pattern_title"'" |
            .attributes.fieldFormatMap = "{}" |
            del(.version)
        elif .type == "dashboard" then
            .attributes.title = (.attributes.title + " ('"$display_name"')") |
            (if .references then .references = [.references[] | if .type == "index-pattern" then .id = "'"$pattern_id"'" else . end] else . end) |
            del(.version)
        elif .type then
            .references = (if .references then [.references[] | if .type == "index-pattern" then .id = "'"$pattern_id"'" else . end] else [] end) |
            del(.version)
        else
            empty
        end
    ' "$dashboard_source" > "$tmp_file"

    echo -n "    Importing saved objects..."
    dashboards_api POST "api/saved_objects/_import?overwrite=true" "$tenant" "$tmp_file"

    jq -c '
        if .type == "index-pattern" then
            .id = "'"$pattern_id"'" |
            .attributes.title = "'"$index_pattern_title"'" |
            .attributes.fieldFormatMap = "{}" |
            del(.version)
        else
            empty
        end
    ' "$dashboard_source" > "$tmp_searches"

    jq -c '
        .references = [.references[] | if .type == "index-pattern" then .id = "'"$pattern_id"'" else . end] |
        del(.version)
    ' "$searches_source" >> "$tmp_searches"

    echo -n "    Importing saved searches..."
    dashboards_api POST "api/saved_objects/_import?overwrite=true" "$tenant" "$tmp_searches"

    trap - RETURN
    rm -f "$tmp_file" "$tmp_searches"
}

# --- Subcommand implementations ---

cmd_tenant() {
    echo "=== Deploying tenant: $LANDSCAPE (prefix: $PREFIX) ==="

    # 1. Index template
    echo -n "  Creating index template '$PREFIX-template'..."
    local template_body
    template_body=$(render_template "$TEMPLATES_DIR/index-template.json.tmpl" \
        "PREFIX" "$PREFIX")
    os_api PUT "_index_template/${PREFIX}-template" "$template_body"

    # 2. Viewer role
    echo -n "  Creating viewer role '${PREFIX}_${LANDSCAPE}_viewer'..."
    local viewer_body
    viewer_body=$(render_template "$TEMPLATES_DIR/role-viewer.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-${LANDSCAPE}-*" \
        "TENANT"        "${PREFIX}_${LANDSCAPE}")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_${LANDSCAPE}_viewer" "$viewer_body"

    # 3. Admin role
    echo -n "  Creating admin role '${PREFIX}_${LANDSCAPE}_admin'..."
    local admin_body
    admin_body=$(render_template "$TEMPLATES_DIR/role-admin.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-${LANDSCAPE}-*" \
        "TENANT"        "${PREFIX}_${LANDSCAPE}")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_${LANDSCAPE}_admin" "$admin_body"

    # 4. Writer role
    echo -n "  Creating writer role '${PREFIX}_${LANDSCAPE}_writer'..."
    local writer_body
    writer_body=$(render_template "$TEMPLATES_DIR/role-writer.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-${LANDSCAPE}-*")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_${LANDSCAPE}_writer" "$writer_body"

    # 5. Tenant
    echo -n "  Creating tenant '${PREFIX}_${LANDSCAPE}'..."
    local tenant_body
    tenant_body=$(render_template "$TEMPLATES_DIR/tenant.json.tmpl" \
        "DESCRIPTION" "Falco events for landscape: $LANDSCAPE")
    os_api PUT "_plugins/_security/api/tenants/${PREFIX}_${LANDSCAPE}" "$tenant_body"

    # 6. Role mappings
    echo -n "  Creating role mapping '${PREFIX}_${LANDSCAPE}_viewer' -> '${BACKEND_ROLE_PREFIX}-viewer'..."
    local viewer_mapping
    viewer_mapping=$(render_template "$TEMPLATES_DIR/role-mapping.json.tmpl" \
        "BACKEND_ROLE" "${BACKEND_ROLE_PREFIX}-viewer")
    os_api PUT "_plugins/_security/api/rolesmapping/${PREFIX}_${LANDSCAPE}_viewer" "$viewer_mapping"

    echo -n "  Creating role mapping '${PREFIX}_${LANDSCAPE}_admin' -> '${BACKEND_ROLE_PREFIX}-admin'..."
    local admin_mapping
    admin_mapping=$(render_template "$TEMPLATES_DIR/role-mapping.json.tmpl" \
        "BACKEND_ROLE" "${BACKEND_ROLE_PREFIX}-admin")
    os_api PUT "_plugins/_security/api/rolesmapping/${PREFIX}_${LANDSCAPE}_admin" "$admin_mapping"

    # 7. Dashboards
    import_dashboards "${PREFIX}_${LANDSCAPE}" "${PREFIX}-${LANDSCAPE}-*" "$LANDSCAPE"

    echo "=== Tenant '$LANDSCAPE' deployed ==="
    echo ""
}

cmd_global_tenant() {
    echo "=== Deploying global tenant (prefix: $PREFIX) ==="

    # 1. Index template
    echo -n "  Creating index template '$PREFIX-template'..."
    local template_body
    template_body=$(render_template "$TEMPLATES_DIR/index-template.json.tmpl" \
        "PREFIX" "$PREFIX")
    os_api PUT "_index_template/${PREFIX}-template" "$template_body"

    # 2. Dashboards into global tenant
    import_dashboards "global" "${PREFIX}-*" "global"

    echo "=== Global tenant deployed ==="
    echo ""
}

cmd_alerting() {
    echo "=== Setting up alerting for landscape: $LANDSCAPE (prefix: $PREFIX) ==="

    # Verify heartbeat events exist
    echo -n "  Checking for heartbeat events in '${PREFIX}-${LANDSCAPE}-*'..."
    local check_response hb_count
    check_response=$(curl -s -X POST -u "$USER:$PASS" -H "Content-Type: application/json" \
        "$HOST/${PREFIX}-${LANDSCAPE}-*/_search" \
        -d '{"size":0,"query":{"bool":{"filter":[{"term":{"rule.keyword":"Detect Falco Heartbeat"}}]}},"aggs":{"total":{"value_count":{"field":"@timestamp"}}}}')
    hb_count=$(echo "$check_response" | jq -r '.aggregations.total.value // 0')
    if [[ "$hb_count" == "0" ]]; then
        echo "  WARNING: No heartbeat events found. Monitor will not trigger until heartbeats arrive."
    else
        echo "  OK ($hb_count heartbeat events found)"
    fi

    # 1. Notification channel
    local channel_id="${PREFIX}-${LANDSCAPE}-slack"
    echo -n "  Creating notification channel '$channel_id'..."
    local channel_body
    channel_body=$(render_template "$TEMPLATES_DIR/notification-channel.json.tmpl" \
        "CHANNEL_ID"       "$channel_id" \
        "PREFIX"           "$PREFIX" \
        "SLACK_WEBHOOK_URL" "$SLACK_WEBHOOK_URL")
    os_api POST "_plugins/_notifications/configs" "$channel_body" || \
    os_api PUT  "_plugins/_notifications/configs/$channel_id" "$channel_body"

    # 2. Heartbeat monitor
    local monitor_name="${PREFIX} - Missing Heartbeat (${LANDSCAPE})"
    echo -n "  Checking for existing monitor '$monitor_name'..."
    local existing_monitor monitor_id
    existing_monitor=$(curl -s -X POST -u "$USER:$PASS" -H "Content-Type: application/json" \
        "$HOST/_plugins/_alerting/monitors/_search" \
        -d "{\"query\":{\"term\":{\"monitor.name.keyword\":\"$monitor_name\"}}}")
    monitor_id=$(echo "$existing_monitor" | jq -r '.hits.hits[0]._id // empty')

    local monitor_body
    monitor_body=$(render_template "$TEMPLATES_DIR/monitor-heartbeat.json.tmpl" \
        "PREFIX"     "$PREFIX" \
        "LANDSCAPE"  "$LANDSCAPE" \
        "CHANNEL_ID" "$channel_id")

    if [[ -n "$monitor_id" ]]; then
        echo " found ($monitor_id), updating..."
        echo -n "  Updating monitor..."
        os_api PUT "_plugins/_alerting/monitors/$monitor_id" "$monitor_body"
    else
        echo " not found, creating..."
        echo -n "  Creating monitor..."
        os_api POST "_plugins/_alerting/monitors" "$monitor_body"
    fi

    # 3. Critical/emergency events monitor
    local critical_monitor_name="${PREFIX} - Critical/Emergency Events (${LANDSCAPE})"
    echo -n "  Checking for existing monitor '$critical_monitor_name'..."
    local existing_critical critical_monitor_id
    existing_critical=$(curl -s -X POST -u "$USER:$PASS" -H "Content-Type: application/json" \
        "$HOST/_plugins/_alerting/monitors/_search" \
        -d "{\"query\":{\"term\":{\"monitor.name.keyword\":\"$critical_monitor_name\"}}}")
    critical_monitor_id=$(echo "$existing_critical" | jq -r '.hits.hits[0]._id // empty')

    local critical_body
    critical_body=$(render_template "$TEMPLATES_DIR/monitor-critical-events.json.tmpl" \
        "PREFIX"     "$PREFIX" \
        "LANDSCAPE"  "$LANDSCAPE" \
        "CHANNEL_ID" "$channel_id")

    if [[ -n "$critical_monitor_id" ]]; then
        echo " found ($critical_monitor_id), updating..."
        echo -n "  Updating monitor..."
        os_api PUT "_plugins/_alerting/monitors/$critical_monitor_id" "$critical_body"
    else
        echo " not found, creating..."
        echo -n "  Creating monitor..."
        os_api POST "_plugins/_alerting/monitors" "$critical_body"
    fi

    echo "=== Alerting setup complete ==="
    echo ""
}

# --- Dispatch ---

case "$SUBCOMMAND" in
    tenant)        cmd_tenant ;;
    global-tenant) cmd_global_tenant ;;
    alerting)      cmd_alerting ;;
esac

echo "Deployment complete."
