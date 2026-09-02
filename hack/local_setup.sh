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

cd "${gardener_dir}"
echo ">>>>>>>>>>>>>>>>>>>> kind-single-node-up"
make kind-single-node-up
trap '{
  cd "$gardener_dir"
  make kind-single-node-down
}' EXIT
export KUBECONFIG=$gardener_dir/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig
echo "<<<<<<<<<<<<<<<<<<<< kind-single-node-up done"

echo ">>>>>>>>>>>>>>>>>>>> gardener-up"
make gardener-up
echo "<<<<<<<<<<<<<<<<<<<< gardener-up done"

export KUBECONFIG=$repo_root/../gardener/dev-setup/kubeconfigs/virtual-garden/kubeconfig

cd "$repo_root"

kubectl apply -f crds/clusterrole-falcoprofiles.yaml
kubectl apply -f crds/clusterrolebinding-falcoprofiles.yaml
kubectl apply -f crds/crd-falco-profile.yaml
kubectl apply -f falco/falco-profile.yaml

export KUBECONFIG=$gardener_dir/dev-setup/gardenlet/components/kubeconfigs/seed-local/kubeconfig

echo ">>>>>>>>>>>>>>>>>>>> generate-operator-extension-resource"
hack/local-setup/generate-operator-extension-resource.sh
echo "<<<<<<<<<<<<<<<<<<<< generate-operator-extension-resource done"

echo ">>>>>>>>>>>>>>>>>>>> extension-up"
make extension-up
echo "<<<<<<<<<<<<<<<<<<<< extension-up done"
