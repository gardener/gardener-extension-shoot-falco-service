#!/bin/bash
# Generate pipeline files for OpenSearch Dev Console
DIR="$(cd "$(dirname "$0")" && pwd)"
PATTERN=$(jq -r '.cluster_id_pattern' "$DIR/grok-patterns.json" | sed 's/\\/\\\\\\\\/g')

sed "s|{{CLUSTER_ID_PATTERN}}|$PATTERN|g" "$DIR/pipeline-register.json.tmpl" > "$DIR/pipeline-register.txt"
sed "s|{{CLUSTER_ID_PATTERN}}|$PATTERN|g" "$DIR/pipeline-simulate.json.tmpl" > "$DIR/pipeline-simulate.txt"

echo "Generated: pipeline-register.txt, pipeline-simulate.txt"
