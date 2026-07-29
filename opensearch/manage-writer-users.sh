#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

HOST=""
USER=""
PASS_FILE=""
PREFIX=""
LANDSCAPE=""
WRITER_PASS_FILE_1=""
WRITER_PASS_FILE_2=""

usage() {
    cat <<'EOF'
Usage:
  manage-writer-users.sh --host <host> --user <user> --pass-file <file> \
                         --prefix <prefix> --landscape <name> \
                         --writer-pass-file-1 <file> --writer-pass-file-2 <file>

Creates or updates two internal OpenSearch writer users for a landscape and maps
them to the landscape writer role. Re-run with a new password file to rotate one
user while the other remains active.

Options:
  --host                OpenSearch backend endpoint (required)
  --user                Admin username (required)
  --pass-file           Path to file containing the admin password (required)
  --prefix              Resource prefix, e.g. 'falco' (required)
  --landscape           Landscape name, e.g. 'dev', 'staging' (required)
  --writer-pass-file-1  Path to file containing password for writer user 1 (required)
  --writer-pass-file-2  Path to file containing password for writer user 2 (required)

Users created:
  ${PREFIX}-${LANDSCAPE}-writer-1
  ${PREFIX}-${LANDSCAPE}-writer-2

Role mapping updated:
  ${PREFIX}_${LANDSCAPE}_writer
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)               HOST="$2";               shift 2 ;;
        --user)               USER="$2";               shift 2 ;;
        --pass-file)          PASS_FILE="$2";          shift 2 ;;
        --prefix)             PREFIX="$2";             shift 2 ;;
        --landscape)          LANDSCAPE="$2";          shift 2 ;;
        --writer-pass-file-1) WRITER_PASS_FILE_1="$2"; shift 2 ;;
        --writer-pass-file-2) WRITER_PASS_FILE_2="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "ERROR: Unknown option: $1"; usage ;;
    esac
done

[[ -z "$HOST" ]]               && { echo "ERROR: --host is required";               usage; }
[[ -z "$USER" ]]               && { echo "ERROR: --user is required";               usage; }
[[ -z "$PASS_FILE" ]]          && { echo "ERROR: --pass-file is required";          usage; }
[[ -z "$PREFIX" ]]             && { echo "ERROR: --prefix is required";             usage; }
[[ -z "$LANDSCAPE" ]]          && { echo "ERROR: --landscape is required";          usage; }
[[ -z "$WRITER_PASS_FILE_1" ]] && { echo "ERROR: --writer-pass-file-1 is required"; usage; }
[[ -z "$WRITER_PASS_FILE_2" ]] && { echo "ERROR: --writer-pass-file-2 is required"; usage; }

for f in "$PASS_FILE" "$WRITER_PASS_FILE_1" "$WRITER_PASS_FILE_2"; do
    [[ ! -f "$f" ]] && { echo "ERROR: File not found: $f"; exit 1; }
done

PASS="$(cat "$PASS_FILE")"
WRITER_PASS_1="$(cat "$WRITER_PASS_FILE_1")"
WRITER_PASS_2="$(cat "$WRITER_PASS_FILE_2")"

if [[ "$HOST" != https://* && "$HOST" != http://* ]]; then
    HOST="https://$HOST"
fi

WRITER_USER_1="${PREFIX}-${LANDSCAPE}-writer-1"
WRITER_USER_2="${PREFIX}-${LANDSCAPE}-writer-2"
WRITER_ROLE="${PREFIX}_${LANDSCAPE}_writer"

os_api() {
    local method="$1"
    local path="$2"
    local body="${3:-}"

    local args=(-s -w "\n%{http_code}" -X "$method" -u "$USER:$PASS" -H "Content-Type: application/json")
    [[ -n "$body" ]] && args+=(-d "$body")

    local response http_code response_body
    response=$(curl "${args[@]}" "$HOST/$path")
    http_code=$(echo "$response" | tail -1)
    response_body=$(echo "$response" | sed '$d')

    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        echo "  OK ($http_code)"
        return 0
    else
        echo "  FAILED ($http_code): $response_body"
        return 2
    fi
}

echo "=== Managing writer users for ${PREFIX}/${LANDSCAPE} ==="

echo -n "  Creating/updating user '$WRITER_USER_1'..."
os_api PUT "_plugins/_security/api/internalusers/${WRITER_USER_1}" \
    "{\"password\": \"${WRITER_PASS_1}\"}"

echo -n "  Creating/updating user '$WRITER_USER_2'..."
os_api PUT "_plugins/_security/api/internalusers/${WRITER_USER_2}" \
    "{\"password\": \"${WRITER_PASS_2}\"}"

echo -n "  Updating role mapping '${WRITER_ROLE}'..."
os_api PUT "_plugins/_security/api/rolesmapping/${WRITER_ROLE}" \
    "{\"users\": [\"${WRITER_USER_1}\", \"${WRITER_USER_2}\"]}"

echo ""
echo "Done. Falcosidekick can authenticate with either:"
echo "  Username: $WRITER_USER_1  (password from $WRITER_PASS_FILE_1)"
echo "  Username: $WRITER_USER_2  (password from $WRITER_PASS_FILE_2)"
echo ""
echo "To rotate user 1: update $WRITER_PASS_FILE_1 and re-run this script."
echo "To rotate user 2: update $WRITER_PASS_FILE_2 and re-run this script."
