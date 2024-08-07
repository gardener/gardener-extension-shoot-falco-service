#!/bin/bash

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -o errexit
set -o nounset
set -o pipefail
set -x

# setup virtual GOPATH
source "$GARDENER_HACK_DIR"/vgopath-setup.sh

CODE_GEN_DIR=$(go list -m -f '{{.Dir}}' k8s.io/code-generator)

# We need to explicitly pass GO111MODULE=off to k8s.io/code-generator as it is significantly slower otherwise,
# see https://github.com/kubernetes/code-generator/issues/100.
export GO111MODULE=off

rm -f $GOPATH/bin/*-gen

# profile

bash "${CODE_GEN_DIR}"/generate-internal-groups.sh \
  deepcopy,defaulter \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/client \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  "profile:v1alpha1" \
  --go-header-file "$(dirname $0)/LICENSE_BOILERPLATE.txt"

bash "${CODE_GEN_DIR}"/generate-internal-groups.sh \
  conversion \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/client \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  "profile:v1alpha1" \
  --extra-peer-dirs=github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/profile,github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/profile/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/conversion,k8s.io/apimachinery/pkg/runtime,github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1 \
  --go-header-file "$(dirname $0)/LICENSE_BOILERPLATE.txt"


bash "${CODE_GEN_DIR}"/generate-internal-groups.sh \
  deepcopy,defaulter \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/client \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  "config:v1alpha1" \
  --go-header-file "$(dirname $0)/LICENSE_BOILERPLATE.txt"

bash "${CODE_GEN_DIR}"/generate-internal-groups.sh \
  conversion \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/client \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  "config:v1alpha1" \
  --extra-peer-dirs=github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config,github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/conversion,k8s.io/apimachinery/pkg/runtime,github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1 \
  --go-header-file "$(dirname $0)/LICENSE_BOILERPLATE.txt"

bash "${CODE_GEN_DIR}"/generate-internal-groups.sh \
  deepcopy,defaulter \
  github.com/gardener/gardener-extension-shoot-falco-serviceo/pkg/client \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  "service:v1alpha1" \
  --go-header-file "$(dirname $0)/LICENSE_BOILERPLATE.txt"

  bash "${CODE_GEN_DIR}"/generate-internal-groups.sh \
  conversion \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/client \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis \
  "service:v1alpha1" \
  --extra-peer-dirs=github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service,github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/conversion,k8s.io/apimachinery/pkg/runtime \
  --go-header-file "$(dirname $0)/LICENSE_BOILERPLATE.txt"
