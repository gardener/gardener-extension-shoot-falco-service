#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATES_DIR="$SCRIPT_DIR/templates"

# Defaults
RETENTION=180
MODE=""
PREFIX=""
BACKEND_ROLE_PREFIX=""
LANDSCAPE=""
HOST=""
DASHBOARDS_HOST=""
USER=""
PASS_FILE=""
SLACK_WEBHOOK_URL=""
SLACK_WEBHOOK_FILE=""

usage() {
    cat <<'EOF'
Usage:
  deploy.sh --host <host> --user <user> --pass-file <file> --prefix <prefix> \
            --landscape <name> --backend-role-prefix <brp> \
            [--dashboards-host <host>] [--retention <days>]

  deploy.sh --host <host> --user <user> --pass-file <file> --prefix <prefix> \
            --combined --backend-role-prefix <brp> \
            [--dashboards-host <host>] [--retention <days>]

  deploy.sh --host <host> --user <user> --pass-file <file> --prefix <prefix> \
            --shared-only [--retention <days>]

  deploy.sh --host <host> --user <user> --pass-file <file> --prefix <prefix> \
            --setup-alerting --landscape <name> --slack-webhook-file <file>

Options:
  --host                  OpenSearch backend endpoint (required)
  --dashboards-host       OpenSearch Dashboards endpoint (required for dashboard deployment)
  --user                  Admin username (required)
  --pass-file             Path to file containing the password (required)
  --prefix                Resource prefix used for index names, role names, and tenant names,
                          e.g. 'falco' or 'oclaf' (required)
  --backend-role-prefix   Prefix for OIDC backend role names as issued by the identity provider,
                          e.g. 'btp-falco-storage'. Maps to roles '<brp>-viewer' and '<brp>-admin'.
                          Defaults to --prefix if not provided. (required for --landscape and --combined)
  --landscape             Landscape name, e.g. 'dev', 'staging', 'production' (per-landscape mode)
  --combined              Deploy combined tenant with read access to all landscapes
  --shared-only           Deploy only shared resources (ingest pipeline, index template, ISM policy)
  --setup-alerting        Create Slack notification channel and heartbeat monitor for a landscape
  --slack-webhook-file    Path to file containing the Slack incoming webhook URL (required for --setup-alerting)
  --retention             Days before index deletion (default: 180)

Roles created per landscape:
  <prefix>_<landscape>_viewer  Read-only access for OIDC users with backend role '<brp>-viewer'
  <prefix>_<landscape>_admin   Full tenant+index access for OIDC users with backend role '<brp>-admin'
  <prefix>_<landscape>_writer  Index write access for falcosidekick internal users (see manage-writer-users.sh)
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --dashboards-host) DASHBOARDS_HOST="$2"; shift 2 ;;
        --user) USER="$2"; shift 2 ;;
        --pass-file) PASS_FILE="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --backend-role-prefix) BACKEND_ROLE_PREFIX="$2"; shift 2 ;;
        --landscape) LANDSCAPE="$2"; if [[ -z "$MODE" ]]; then MODE="landscape"; fi; shift 2 ;;
        --combined) MODE="combined"; shift ;;
        --shared-only) MODE="shared"; shift ;;
        --setup-alerting) MODE="alerting"; shift ;;
        --slack-webhook-file) SLACK_WEBHOOK_FILE="$2"; shift 2 ;;
        --slack-webhook-url) SLACK_WEBHOOK_URL="$2"; shift 2 ;;
        --retention) RETENTION="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "ERROR: Unknown option: $1"; usage ;;
    esac
done

# Validate required params
[[ -z "$HOST" ]] && { echo "ERROR: --host is required"; usage; }
[[ -z "$USER" ]] && { echo "ERROR: --user is required"; usage; }
[[ -z "$PASS_FILE" ]] && { echo "ERROR: --pass-file is required"; usage; }
[[ -z "$PREFIX" ]] && { echo "ERROR: --prefix is required"; usage; }
[[ -z "$MODE" ]] && { echo "ERROR: One of --landscape, --combined, --shared-only, or --setup-alerting is required"; usage; }

if [[ "$MODE" == "landscape" && -z "$LANDSCAPE" ]]; then
    echo "ERROR: --landscape requires a landscape name"
    usage
fi

# Default backend role prefix to resource prefix if not provided
if [[ -z "$BACKEND_ROLE_PREFIX" ]]; then
    BACKEND_ROLE_PREFIX="$PREFIX"
fi

if [[ "$MODE" == "alerting" ]]; then
    if [[ -z "$LANDSCAPE" ]]; then
        echo "ERROR: --setup-alerting requires --landscape"
        usage
    fi
    if [[ -n "$SLACK_WEBHOOK_FILE" ]]; then
        if [[ ! -f "$SLACK_WEBHOOK_FILE" ]]; then
            echo "ERROR: Slack webhook file not found: $SLACK_WEBHOOK_FILE"
            exit 1
        fi
        SLACK_WEBHOOK_URL="$(cat "$SLACK_WEBHOOK_FILE")"
    fi
    if [[ -z "$SLACK_WEBHOOK_URL" ]]; then
        echo "ERROR: --setup-alerting requires --slack-webhook-file or --slack-webhook-url"
        usage
    fi
fi

# Read password from file
if [[ ! -f "$PASS_FILE" ]]; then
    echo "ERROR: Password file not found: $PASS_FILE"
    exit 1
fi
PASS="$(cat "$PASS_FILE")"

# Ensure host has https:// prefix
if [[ "$HOST" != https://* && "$HOST" != http://* ]]; then
    HOST="https://$HOST"
fi
if [[ -n "$DASHBOARDS_HOST" && "$DASHBOARDS_HOST" != https://* && "$DASHBOARDS_HOST" != http://* ]]; then
    DASHBOARDS_HOST="https://$DASHBOARDS_HOST"
fi

# --- Helper functions ---

os_api() {
    local method="$1"
    local path="$2"
    local body="${3:-}"

    local args=(-s -w "\n%{http_code}" -X "$method" -u "$USER:$PASS" -H "Content-Type: application/json")
    if [[ -n "$body" ]]; then
        args+=(-d "$body")
    fi

    local response
    response=$(curl "${args[@]}" "$HOST/$path")
    local http_code
    http_code=$(echo "$response" | tail -1)
    local response_body
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

    local args=(-s -w "\n%{http_code}" -X "$method" -u "$USER:$PASS" -H "osd-xsrf: true" -H "securitytenant: $tenant")
    if [[ -n "$file" ]]; then
        args+=(--form "file=@$file")
    fi

    local response
    response=$(curl "${args[@]}" "$DASHBOARDS_HOST/$path")
    local http_code
    http_code=$(echo "$response" | tail -1)
    local response_body
    response_body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
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
    if [[ ! -f "$template" ]]; then
        echo "ERROR: Template file not found: $template"
        exit 1
    fi
    local content
    content=$(cat "$template")
    while [[ $# -gt 0 ]]; do
        local key="$1"
        local value="$2"
        content=$(echo "$content" | sed "s|{{${key}}}|${value}|g")
        shift 2
    done
    echo "$content"
}

# --- Deployment functions ---

deploy_shared() {
    echo "=== Deploying shared resources for prefix: $PREFIX ==="

    # 1. Index template
    echo -n "  Creating index template '$PREFIX-template'..."
    local template_body
    template_body=$(render_template "$TEMPLATES_DIR/index-template.json.tmpl" \
        "PREFIX" "$PREFIX")
    os_api PUT "_index_template/${PREFIX}-template" "$template_body"

    # 2. ISM policy (requires seq_no/primary_term for updates)
    echo -n "  Creating ISM policy '$PREFIX-rollover'..."
    local ism_body
    ism_body=$(render_template "$TEMPLATES_DIR/ism-policy.json.tmpl" \
        "PREFIX" "$PREFIX" \
        "RETENTION" "$RETENTION")

    local ism_response
    ism_response=$(curl -s -X GET -u "$USER:$PASS" -H "Content-Type: application/json" "$HOST/_plugins/_ism/policies/${PREFIX}-rollover")
    local seq_no primary_term
    seq_no=$(echo "$ism_response" | jq -r '._seq_no // empty')
    primary_term=$(echo "$ism_response" | jq -r '._primary_term // empty')

    if [[ -n "$seq_no" && -n "$primary_term" ]]; then
        os_api PUT "_plugins/_ism/policies/${PREFIX}-rollover?if_seq_no=${seq_no}&if_primary_term=${primary_term}" "$ism_body"
    else
        os_api PUT "_plugins/_ism/policies/${PREFIX}-rollover" "$ism_body"
    fi

    echo "=== Shared resources deployed ==="
    echo ""
}

deploy_landscape() {
    echo "=== Deploying landscape: $LANDSCAPE (prefix: $PREFIX, backend-role-prefix: $BACKEND_ROLE_PREFIX) ==="

    # 1. Viewer role (OIDC users with read access)
    echo -n "  Creating viewer role '${PREFIX}_${LANDSCAPE}_viewer'..."
    local viewer_body
    viewer_body=$(render_template "$TEMPLATES_DIR/role-viewer.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-${LANDSCAPE}-*" \
        "TENANT" "${PREFIX}_${LANDSCAPE}")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_${LANDSCAPE}_viewer" "$viewer_body"

    # 2. Admin role (OIDC users with full tenant+index access)
    echo -n "  Creating admin role '${PREFIX}_${LANDSCAPE}_admin'..."
    local admin_body
    admin_body=$(render_template "$TEMPLATES_DIR/role-admin.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-${LANDSCAPE}-*" \
        "TENANT" "${PREFIX}_${LANDSCAPE}")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_${LANDSCAPE}_admin" "$admin_body"

    # 3. Writer role (falcosidekick internal users, index write only)
    echo -n "  Creating writer role '${PREFIX}_${LANDSCAPE}_writer'..."
    local writer_body
    writer_body=$(render_template "$TEMPLATES_DIR/role-writer.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-${LANDSCAPE}-*")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_${LANDSCAPE}_writer" "$writer_body"

    # 4. Tenant
    echo -n "  Creating tenant '${PREFIX}_${LANDSCAPE}'..."
    local tenant_body
    tenant_body=$(render_template "$TEMPLATES_DIR/tenant.json.tmpl" \
        "DESCRIPTION" "Falco events for landscape: $LANDSCAPE")
    os_api PUT "_plugins/_security/api/tenants/${PREFIX}_${LANDSCAPE}" "$tenant_body"

    # 5. OIDC role mappings
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

    # 7. Dashboard deployment
    deploy_dashboards "${PREFIX}_${LANDSCAPE}" "${PREFIX}-${LANDSCAPE}-*" "$LANDSCAPE"

    echo "=== Landscape '$LANDSCAPE' deployed ==="
    echo ""
}

deploy_combined() {
    echo "=== Deploying combined tenant (prefix: $PREFIX, backend-role-prefix: $BACKEND_ROLE_PREFIX) ==="

    # 1. Combined viewer role
    echo -n "  Creating combined viewer role '${PREFIX}_combined_viewer'..."
    local viewer_body
    viewer_body=$(render_template "$TEMPLATES_DIR/role-viewer.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-*" \
        "TENANT" "${PREFIX}_combined")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_combined_viewer" "$viewer_body"

    # 2. Tenant
    echo -n "  Creating tenant '${PREFIX}_combined'..."
    local tenant_body
    tenant_body=$(render_template "$TEMPLATES_DIR/tenant.json.tmpl" \
        "DESCRIPTION" "Combined Falco events across all landscapes")
    os_api PUT "_plugins/_security/api/tenants/${PREFIX}_combined" "$tenant_body"

    # 3. Role mapping
    echo -n "  Creating role mapping '${PREFIX}_combined_viewer' -> '${BACKEND_ROLE_PREFIX}-viewer'..."
    local mapping_body
    mapping_body=$(render_template "$TEMPLATES_DIR/role-mapping.json.tmpl" \
        "BACKEND_ROLE" "${BACKEND_ROLE_PREFIX}-viewer")
    os_api PUT "_plugins/_security/api/rolesmapping/${PREFIX}_combined_viewer" "$mapping_body"

    # 4. Dashboard deployment
    deploy_dashboards "${PREFIX}_combined" "${PREFIX}-*" "combined"

    echo "=== Combined tenant deployed ==="
    echo ""
}

deploy_dashboards() {
    local tenant="$1"
    local index_pattern_title="$2"

    echo "  Deploying dashboards to tenant '$tenant'..."

    if [[ -z "$DASHBOARDS_HOST" ]]; then
        echo "    ERROR: --dashboards-host is required for dashboard deployment"
        exit 1
    fi

    local dashboard_source="$TEMPLATES_DIR/dashboard.ndjson"
    if [[ ! -f "$dashboard_source" ]]; then
        echo "    ERROR: $dashboard_source not found"
        exit 1
    fi

    local tmp_file
    tmp_file=$(mktemp --suffix=.ndjson)
    trap "rm -f $tmp_file" RETURN

    # Process dashboard NDJSON:
    # 1. Replace index pattern title
    # 2. Replace index pattern ID with a deterministic one
    # 3. Strip fieldFormatMap (contains instance-specific URLs from export)
    # 4. Update all internal references to the new pattern ID
    # 5. Add landscape/tenant name to dashboard title
    local pattern_id="${tenant}-pattern"
    local display_name="${3:-combined}"

    jq -c '
        if .type == "index-pattern" then
            .id = "'"$pattern_id"'" |
            .attributes.title = "'"$index_pattern_title"'" |
            .attributes.fieldFormatMap = "{}"
        elif .type == "dashboard" then
            .attributes.title = (.attributes.title + " ('"$display_name"')") |
            (if .references then .references = [.references[] | if .type == "index-pattern" then .id = "'"$pattern_id"'" else . end] else . end)
        elif .references then
            .references = [.references[] | if .type == "index-pattern" then .id = "'"$pattern_id"'" else . end]
        else
            .
        end
    ' "$dashboard_source" > "$tmp_file"

    echo -n "    Importing saved objects..."
    dashboards_api POST "api/saved_objects/_import?overwrite=true" "$tenant" "$tmp_file"

    # Import saved searches (merged with index pattern so references resolve)
    local searches_source="$TEMPLATES_DIR/saved-searches.ndjson"
    if [[ ! -f "$searches_source" ]]; then
        echo "    ERROR: $searches_source not found"
        exit 1
    fi

    local tmp_searches
    tmp_searches=$(mktemp --suffix=.ndjson)

    # Include the index pattern line first, then the searches with updated references
    jq -c '
        if .type == "index-pattern" then
            .id = "'"$pattern_id"'" |
            .attributes.title = "'"$index_pattern_title"'" |
            .attributes.fieldFormatMap = "{}"
        else
            empty
        end
    ' "$dashboard_source" > "$tmp_searches"

    jq -c '
        .references = [.references[] | if .type == "index-pattern" then .id = "'"$pattern_id"'" else . end]
    ' "$searches_source" >> "$tmp_searches"

    echo -n "    Importing saved searches..."
    dashboards_api POST "api/saved_objects/_import?overwrite=true" "$tenant" "$tmp_searches"

    rm -f "$tmp_searches"
    rm -f "$tmp_file"
    trap - RETURN
}

deploy_alerting() {
    echo "=== Setting up alerting for landscape: $LANDSCAPE (prefix: $PREFIX) ==="

    # Verify the landscape index/alias exists
    echo -n "  Checking landscape alias '$PREFIX-$LANDSCAPE' exists..."
    if ! os_api GET "_alias/${PREFIX}-${LANDSCAPE}" >/dev/null 2>&1; then
        echo "  ERROR: Alias '${PREFIX}-${LANDSCAPE}' does not exist. Deploy the landscape first."
        exit 1
    fi
    echo "  OK"

    # Verify heartbeat events exist in this landscape
    echo -n "  Checking for heartbeat events in '${PREFIX}-${LANDSCAPE}-*'..."
    local check_response
    check_response=$(curl -s -X POST -u "$USER:$PASS" -H "Content-Type: application/json" \
        "$HOST/${PREFIX}-${LANDSCAPE}-*/_search" \
        -d '{"size":0,"query":{"bool":{"filter":[{"term":{"rule.keyword":"Detect Falco Heartbeat"}}]}},"aggs":{"total":{"value_count":{"field":"@timestamp"}}}}')
    local hb_count
    hb_count=$(echo "$check_response" | jq -r '.aggregations.total.value // 0')
    if [[ "$hb_count" == "0" ]]; then
        echo "  WARNING: No heartbeat events found in '${PREFIX}-${LANDSCAPE}-*'. Monitor will not trigger until heartbeats arrive."
    else
        echo "  OK ($hb_count heartbeat events found)"
    fi

    # 1. Create or update notification channel
    local channel_id="${PREFIX}-${LANDSCAPE}-slack"
    echo -n "  Creating notification channel '$channel_id'..."
    local channel_body
    channel_body=$(render_template "$TEMPLATES_DIR/notification-channel.json.tmpl" \
        "CHANNEL_ID" "$channel_id" \
        "PREFIX" "$PREFIX" \
        "SLACK_WEBHOOK_URL" "$SLACK_WEBHOOK_URL")
    os_api POST "_plugins/_notifications/configs" "$channel_body" || \
    os_api PUT "_plugins/_notifications/configs/$channel_id" "$channel_body"

    # 2. Create heartbeat monitor
    # Check if monitor already exists (by name)
    local monitor_name="${PREFIX} - Missing Heartbeat (${LANDSCAPE})"
    echo -n "  Checking for existing monitor '$monitor_name'..."
    local existing_monitor
    existing_monitor=$(curl -s -X POST -u "$USER:$PASS" -H "Content-Type: application/json" \
        "$HOST/_plugins/_alerting/monitors/_search" \
        -d "{\"query\":{\"term\":{\"monitor.name.keyword\":\"$monitor_name\"}}}")
    local monitor_id
    monitor_id=$(echo "$existing_monitor" | jq -r '.hits.hits[0]._id // empty')

    local monitor_body
    monitor_body=$(render_template "$TEMPLATES_DIR/monitor-heartbeat.json.tmpl" \
        "PREFIX" "$PREFIX" \
        "LANDSCAPE" "$LANDSCAPE" \
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

    # 3. Create critical/emergency events monitor
    local critical_monitor_name="${PREFIX} - Critical/Emergency Events (${LANDSCAPE})"
    echo -n "  Checking for existing monitor '$critical_monitor_name'..."
    local existing_critical
    existing_critical=$(curl -s -X POST -u "$USER:$PASS" -H "Content-Type: application/json" \
        "$HOST/_plugins/_alerting/monitors/_search" \
        -d "{\"query\":{\"term\":{\"monitor.name.keyword\":\"$critical_monitor_name\"}}}")
    local critical_monitor_id
    critical_monitor_id=$(echo "$existing_critical" | jq -r '.hits.hits[0]._id // empty')

    local critical_body
    critical_body=$(render_template "$TEMPLATES_DIR/monitor-critical-events.json.tmpl" \
        "PREFIX" "$PREFIX" \
        "LANDSCAPE" "$LANDSCAPE" \
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

# --- Main execution ---

# Deploy shared resources first (idempotent) unless in alerting mode
if [[ "$MODE" != "alerting" ]]; then
    deploy_shared
fi

case "$MODE" in
    landscape)
        deploy_landscape
        ;;
    combined)
        deploy_combined
        ;;
    shared)
        echo "Shared-only mode: done."
        ;;
    alerting)
        deploy_alerting
        ;;
esac

echo "Deployment complete."
