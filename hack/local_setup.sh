#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o nounset
set -o pipefail
set -o errexit
set -x
repo_root="$(readlink -f $(dirname ${0})/..)"

# gardener_dir=$(go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack
gardener_dir=${repo_root}/../gardener

# gardener_version=$(go list -m -f '{{.Version}}' github.com/gardener/gardener)

cd ${gardener_dir}
echo ">>>>>>>>>>>>>>>>>>>> kind-single-node-up"
make kind-single-node-up
trap '{
  cd "$repo_root/gardener"
  export_artifacts "gardener-operator-local"
  make kind-single-node-down
}' EXIT
export KUBECONFIG=$repo_root/gardener/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig
echo "<<<<<<<<<<<<<<<<<<<< kind-single-node-up done"

echo ">>>>>>>>>>>>>>>>>>>> operator-up"
make operator-up
echo "<<<<<<<<<<<<<<<<<<<< operator-up done"

echo ">>>>>>>>>>>>>>>>>>>> operator-seed-up"
make operator-seed-up
echo "<<<<<<<<<<<<<<<<<<<< operator-seed-up done"

cd $repo_root

k apply -f crds/clusterrole-falcoprofiles.yaml
k apply -f crds/clusterrolebinding-falcoprofiles.yaml
k apply -f crds/crd-falco-profile.yaml
k apply -f falco/falco-profile.yaml

echo ">>>>>>>>>>>>>>>>>>>> extension-up"
make extension-up
echo "<<<<<<<<<<<<<<<<<<<< extension-up done"
