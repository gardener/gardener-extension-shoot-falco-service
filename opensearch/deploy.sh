#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATES_DIR="$SCRIPT_DIR/templates"

# Defaults
RETENTION=180
MODE=""
PREFIX=""
LANDSCAPE=""
HOST=""
DASHBOARDS_HOST=""
USER=""
PASS_FILE=""
LANDING_INDEX=""

usage() {
    cat <<'EOF'
Usage:
  deploy.sh --host <host> --user <user> --pass-file <file> --prefix <prefix> \
            --landscape <name> [--dashboards-host <host>] [--landing-index <idx>] [--retention <days>]

  deploy.sh --host <host> --user <user> --pass-file <file> --prefix <prefix> \
            --combined [--dashboards-host <host>] [--landing-index <idx>] [--retention <days>]

  deploy.sh --host <host> --user <user> --pass-file <file> --prefix <prefix> \
            --shared-only [--landing-index <idx>] [--retention <days>]

Options:
  --host              OpenSearch backend endpoint (required)
  --dashboards-host   OpenSearch Dashboards endpoint (required for dashboard deployment)
  --user              Admin username (required)
  --pass-file         Path to file containing the password (required)
  --prefix            Index prefix, e.g. 'falco' or 'oclaf' (required)
  --landscape         Landscape name, e.g. 'staging', 'production' (per-landscape mode)
  --combined          Deploy combined tenant with access to all landscapes
  --shared-only       Deploy only shared resources (pipeline, template, ISM, writer role)
  --landing-index     Index that falcosidekick writes to (for template matching)
  --retention         Days before index deletion (default: 180)
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
        --landscape) LANDSCAPE="$2"; MODE="landscape"; shift 2 ;;
        --combined) MODE="combined"; shift ;;
        --shared-only) MODE="shared"; shift ;;
        --landing-index) LANDING_INDEX="$2"; shift 2 ;;
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
[[ -z "$MODE" ]] && { echo "ERROR: One of --landscape, --combined, or --shared-only is required"; usage; }

if [[ "$MODE" == "landscape" && -z "$LANDSCAPE" ]]; then
    echo "ERROR: --landscape requires a landscape name"
    usage
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

    # 1. Ingest pipeline
    echo -n "  Creating ingest pipeline '$PREFIX-ingest'..."
    local grok_patterns_file="$SCRIPT_DIR/grok-patterns.json"
    if [[ ! -f "$grok_patterns_file" ]]; then
        echo "ERROR: $grok_patterns_file not found"
        exit 1
    fi
    local grok_pattern
    grok_pattern=$(jq -r '.cluster_id_pattern' "$grok_patterns_file")
    local pipeline_body
    pipeline_body=$(render_template "$TEMPLATES_DIR/pipeline.json.tmpl" \
        "GROK_PATTERN" "$grok_pattern" \
        "PREFIX" "$PREFIX")
    os_api PUT "_ingest/pipeline/${PREFIX}-ingest" "$pipeline_body"

    # 2. Index template
    echo -n "  Creating index template '$PREFIX-template'..."
    local template_body
    template_body=$(render_template "$TEMPLATES_DIR/index-template.json.tmpl" \
        "PREFIX" "$PREFIX")
    os_api PUT "_index_template/${PREFIX}-template" "$template_body"

    # 3. ISM policy
    echo -n "  Creating ISM policy '$PREFIX-rollover'..."
    local ism_body
    ism_body=$(render_template "$TEMPLATES_DIR/ism-policy.json.tmpl" \
        "PREFIX" "$PREFIX" \
        "RETENTION" "$RETENTION")
    os_api PUT "_plugins/_ism/policies/${PREFIX}-rollover" "$ism_body"

    # 4. Shared writer role
    echo -n "  Creating shared writer role '${PREFIX}_writer'..."
    local writer_body
    writer_body=$(render_template "$TEMPLATES_DIR/role-writer.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-*")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_writer" "$writer_body"

    # 5. Shared writer role mapping
    echo -n "  Creating role mapping '${PREFIX}_writer'..."
    local mapping_body
    mapping_body=$(render_template "$TEMPLATES_DIR/role-mapping.json.tmpl" \
        "BACKEND_ROLE" "${PREFIX}-writer")
    os_api PUT "_plugins/_security/api/rolesmapping/${PREFIX}_writer" "$mapping_body"

    echo "=== Shared resources deployed ==="
    echo ""
}

deploy_landscape() {
    echo "=== Deploying landscape: $LANDSCAPE (prefix: $PREFIX) ==="

    # 1. Bootstrap index (only if alias doesn't exist)
    echo -n "  Checking alias '$PREFIX-$LANDSCAPE'..."
    if os_api GET "_alias/${PREFIX}-${LANDSCAPE}" >/dev/null 2>&1; then
        echo "  Alias already exists, skipping bootstrap"
    else
        echo " not found, bootstrapping..."
        echo -n "  Creating index '${PREFIX}-${LANDSCAPE}-000001' with write alias..."
        local bootstrap_body
        bootstrap_body=$(render_template "$TEMPLATES_DIR/bootstrap-index.json.tmpl" \
            "PREFIX" "$PREFIX" \
            "LANDSCAPE" "$LANDSCAPE")
        os_api PUT "${PREFIX}-${LANDSCAPE}-000001" "$bootstrap_body"
    fi

    # 2. Reader role
    echo -n "  Creating reader role '${PREFIX}_${LANDSCAPE}_reader'..."
    local reader_body
    reader_body=$(render_template "$TEMPLATES_DIR/role-reader.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-${LANDSCAPE}-*" \
        "TENANT" "${PREFIX}_${LANDSCAPE}")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_${LANDSCAPE}_reader" "$reader_body"

    # 3. Writer role
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

    # 5. Role mappings
    echo -n "  Creating role mapping '${PREFIX}_${LANDSCAPE}_reader'..."
    local reader_mapping
    reader_mapping=$(render_template "$TEMPLATES_DIR/role-mapping.json.tmpl" \
        "BACKEND_ROLE" "${PREFIX}-${LANDSCAPE}-reader")
    os_api PUT "_plugins/_security/api/rolesmapping/${PREFIX}_${LANDSCAPE}_reader" "$reader_mapping"

    echo -n "  Creating role mapping '${PREFIX}_${LANDSCAPE}_writer'..."
    local writer_mapping
    writer_mapping=$(render_template "$TEMPLATES_DIR/role-mapping.json.tmpl" \
        "BACKEND_ROLE" "${PREFIX}-${LANDSCAPE}-writer")
    os_api PUT "_plugins/_security/api/rolesmapping/${PREFIX}_${LANDSCAPE}_writer" "$writer_mapping"

    # 6. Dashboard deployment
    deploy_dashboards "${PREFIX}_${LANDSCAPE}" "${PREFIX}-${LANDSCAPE}-*"

    echo "=== Landscape '$LANDSCAPE' deployed ==="
    echo ""
}

deploy_combined() {
    echo "=== Deploying combined tenant (prefix: $PREFIX) ==="

    # 1. Combined reader role
    echo -n "  Creating combined reader role '${PREFIX}_combined_reader'..."
    local reader_body
    reader_body=$(render_template "$TEMPLATES_DIR/role-reader.json.tmpl" \
        "INDEX_PATTERN" "${PREFIX}-*" \
        "TENANT" "${PREFIX}_combined")
    os_api PUT "_plugins/_security/api/roles/${PREFIX}_combined_reader" "$reader_body"

    # 2. Tenant
    echo -n "  Creating tenant '${PREFIX}_combined'..."
    local tenant_body
    tenant_body=$(render_template "$TEMPLATES_DIR/tenant.json.tmpl" \
        "DESCRIPTION" "Combined Falco events across all landscapes")
    os_api PUT "_plugins/_security/api/tenants/${PREFIX}_combined" "$tenant_body"

    # 3. Role mapping
    echo -n "  Creating role mapping '${PREFIX}_combined_reader'..."
    local mapping_body
    mapping_body=$(render_template "$TEMPLATES_DIR/role-mapping.json.tmpl" \
        "BACKEND_ROLE" "${PREFIX}-combined-reader")
    os_api PUT "_plugins/_security/api/rolesmapping/${PREFIX}_combined_reader" "$mapping_body"

    # 4. Dashboard deployment
    deploy_dashboards "${PREFIX}_combined" "${PREFIX}-*"

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
    tmp_file=$(mktemp)
    trap "rm -f $tmp_file" RETURN

    # Process dashboard NDJSON:
    # 1. Replace index pattern title
    # 2. Replace index pattern ID with a deterministic one
    # 3. Strip fieldFormatMap (contains instance-specific URLs from export)
    # 4. Update all internal references to the new pattern ID
    local pattern_id="${tenant}-pattern"

    jq -c '
        if .type == "index-pattern" then
            .id = "'"$pattern_id"'" |
            .attributes.title = "'"$index_pattern_title"'" |
            .attributes.fieldFormatMap = "{}"
        elif .references then
            .references = [.references[] | if .type == "index-pattern" then .id = "'"$pattern_id"'" else . end]
        else
            .
        end
    ' "$dashboard_source" > "$tmp_file"

    echo -n "    Importing saved objects..."
    dashboards_api POST "api/saved_objects/_import?overwrite=true" "$tenant" "$tmp_file"

    rm -f "$tmp_file"
    trap - RETURN
}

# --- Main execution ---

# Always deploy shared resources first (idempotent)
deploy_shared

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
esac

echo "Deployment complete."
