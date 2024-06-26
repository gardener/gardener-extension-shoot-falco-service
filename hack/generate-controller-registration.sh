#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e
set -o pipefail

function usage {
    cat <<EOM
Usage:
generate-controller-registration [options] <name> <chart-dir> <version> <dest> <kind-and-type> [kinds-and-types ...]

    -h, --help        Display this help and exit.
    --optional        Sets 'globallyEnabled: false' for controller resources of the controller registration.
    -e, --pod-security-enforce[=pod-security-standard]
                      Sets 'security.gardener.cloud/pod-security-enforce' annotation in the
                      controller registration. Defaults to 'baseline'.
    <name>            Name of the controller registration to generate.
    <chart-dir>       Location of the chart directory.
    <version>         Version to use for the Helm chart and the tag in the ControllerDeployment.
    <dest>            The destination file to write the registration YAML to.
    <kind-and-type>   A tuple of kind and type of the controller registration to generate.
                      Separated by ':'.
                      Example: OperatingSystemConfig:foobar
    <kinds-and-types> Further tuples of kind and type of the controller registration to generate.
                      Separated by ':'.
EOM
    exit 0
}

POD_SECURITY_ENFORCE="baseline"
while :; do
  case $1 in
    -h|--help)
      usage
      ;;
    --optional)
      MODE=$'\n    globallyEnabled: false'
      ;;
    -e|--pod-security-enforce)
      POD_SECURITY_ENFORCE=$2
      shift
      ;;
    --pod-security-enforce=*)
      POD_SECURITY_ENFORCE=${1#*=}
      ;;
    --)
      shift
      break
      ;;
    *)
      break
  esac
  shift
done

NAME="$1"
CHART_DIR="$2"
VERSION="$3"
DEST="$4"

# The following code is to make `helm package` idempotent: Usually, everytime `helm package` is invoked,
# it produces a different `.tgz` due to modification timestamps and some special shasums of gzip. We
# resolve this by unarchiving the `.tgz`, compressing it again with a constant `mtime` and no gzip
# checksums.
temp_dir="$(mktemp -d)"
temp_helm_home="$(mktemp -d)"
temp_extract_dir="$(mktemp -d)"
function cleanup {
    rm -rf "$temp_dir"
    rm -rf "$temp_helm_home"
    rm -rf "$temp_extract_dir"
}
trap cleanup EXIT ERR INT TERM

export HELM_HOME="$temp_helm_home"
[ "$(helm version --client --template "{{.Version}}" | head -c2 | tail -c1)" = "3" ] || helm init --client-only > /dev/null 2>&1
helm package "$CHART_DIR" --destination "$temp_dir" > /dev/null
tar -xzm -C "$temp_extract_dir" -f "$temp_dir"/*
chart="$(tar --sort=name -c --owner=root:0 --group=root:0 --mtime='UTC 2019-01-01' -C "$temp_extract_dir" "$(basename "$temp_extract_dir"/*)" | gzip -n | base64 | tr -d '\n')"

mkdir -p "$(dirname "$DEST")"

cat <<EOM > "$DEST"
---
apiVersion: core.gardener.cloud/v1beta1
kind: ControllerDeployment
metadata:
  name: $NAME
type: helm
providerConfig:
  chart: $chart
  values:
EOM

if [ -n "$(yq '.image.repository' "$CHART_DIR"/values.yaml)" ] ; then
  # image value specifies repository and tag separately, output the image stanza with the given version as tag value
  cat <<EOM >> "$DEST"
    image:
      tag: $VERSION
EOM
else
  # image value specifies a fully-qualified image reference, output the default image plus the given version as tag
  default_image="$(yq '.image' "$CHART_DIR"/values.yaml)"
  if [ -n "$VERSION" ] ; then
    # if a version is given, replace the default tag
    #default_image="${default_image%%:*}:$VERSION"
    :
  fi

  cat <<EOM >> "$DEST"
    image: 
      repository: $default_image
      tag: ${VERSION}
EOM
fi
cat <<EOM >> "$DEST"
---
apiVersion: core.gardener.cloud/v1beta1
kind: ControllerRegistration
metadata:
  name: $NAME
  annotations:
    security.gardener.cloud/pod-security-enforce: $POD_SECURITY_ENFORCE
spec:
  deployment:
    deploymentRefs:
    - name: $NAME
  resources:
  - globallyEnabled: false
    primary: true
    type: falco
    kind: Extension
    workerlessSupported: false
EOM

echo "Successfully generated controller registration at $DEST"
