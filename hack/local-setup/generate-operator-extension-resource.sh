#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# Generates hack/local-setup/operator-extension-resource.yaml from its template by building the
# imageVectorOverwrite block from imagevector/images.yaml.
#
# docker.io images (bare "org/image" repositories) are redirected to the SAP mirror:
#   europe-docker.pkg.dev/sap-se-gcp-k8s-delivery/releases-public/registry-1_docker_io/<org>/<image>
# Images already on europe-docker.pkg.dev (gardener-project) are used as-is.
# The falco-ops image is served locally by the kind registry and is always tag "latest".

set -euo pipefail

REPO_ROOT="$(readlink -f "$(dirname "${0}")/../..")"
IMAGES_YAML="${REPO_ROOT}/imagevector/images.yaml"
TMPL="${REPO_ROOT}/hack/local-setup/operator-extension-resource.yaml.tmpl"
OUT="${REPO_ROOT}/hack/local-setup/operator-extension-resource.yaml"
YQ="${REPO_ROOT}/hack/tools/bin/linux-amd64/yq"

MIRROR_PREFIX="europe-docker.pkg.dev/sap-se-gcp-k8s-delivery/releases-public/registry-1_docker_io"
FALCO_OPS_REPO="registry.local.gardener.cloud:5001/local-skaffold/falco-ops"

# Build the imageVectorOverwrite YAML block.
# Each entry is indented 10 spaces so it aligns correctly inside the | block in the template
# (the template itself uses 8-space indent for the imageVectorOverwrite key).
build_image_vector_overwrite() {
  local indent="          "  # 10 spaces
  echo "${indent}images:"

  local count
  count=$("${YQ}" e '.images | length' "${IMAGES_YAML}")

  for ((i = 0; i < count; i++)); do
    local name repo tag
    name=$("${YQ}" e ".images[${i}].name" "${IMAGES_YAML}")
    repo=$("${YQ}" e ".images[${i}].repository" "${IMAGES_YAML}")
    tag=$("${YQ}" e ".images[${i}].tag // \"\"" "${IMAGES_YAML}")

    if [[ "${name}" == "falco-ops" ]]; then
      # falco-ops is built and pushed locally by skaffold; always use the local kind registry.
      echo "${indent}- name: ${name}"
      echo "${indent}  repository: ${FALCO_OPS_REPO}"
      echo "${indent}  tag: latest"
      continue
    fi

    # Bare docker.io images (no registry prefix) go through the SAP mirror.
    if [[ "${repo}" != *"."* ]]; then
      repo="${MIRROR_PREFIX}/${repo}"
    fi

    echo "${indent}- name: ${name}"
    echo "${indent}  repository: ${repo}"
    if [[ -n "${tag}" && "${tag}" != "null" ]]; then
      echo "${indent}  tag: ${tag}"
    fi
    if [[ -n "$("${YQ}" e ".images[${i}].version // \"\"" "${IMAGES_YAML}")" ]]; then
      local version
      version=$("${YQ}" e ".images[${i}].version" "${IMAGES_YAML}")
      if [[ "${version}" != "null" ]]; then
        echo "${indent}  version: ${version}"
      fi
    fi
  done
}

IMAGE_VECTOR_OVERWRITE="$(build_image_vector_overwrite)"

# Substitute the placeholder — sed requires the replacement to be on one line,
# so we use awk to do a multi-line replacement.
awk -v block="${IMAGE_VECTOR_OVERWRITE}" '
/@@IMAGE_VECTOR_OVERWRITE@@/ { print block; next }
{ print }
' "${TMPL}" > "${OUT}"

echo "Generated ${OUT}"
