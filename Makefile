# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

uname                       := $(shell uname)

ENSURE_GARDENER_MOD         := $(shell go get github.com/gardener/gardener@$$(go list -m -f "{{.Version}}" github.com/gardener/gardener))
GARDENER_HACK_DIR           := $(shell go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack
EXTENSION_PREFIX            := gardener-extension
NAME                        := shoot-falco-service
ADMISSION_NAME              := admission-shoot-falco-service
REGISTRY                    := europe-docker.pkg.dev/gardener-project/public/gardener
IMAGE_PREFIX                := $(REGISTRY)/extensions
REPO_ROOT                   := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
IMAGE_PREFIX                := $(REGISTRY)/extensions
REPO_ROOT                   := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
HACK_DIR                    := $(REPO_ROOT)/hack
VERSION                     := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION           := $(VERSION)-$(shell git rev-parse HEAD)
LD_FLAGS                    := "-w $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh "" $(REPO_ROOT)/VERSION "$(EXTENSION_PREFIX)")"
LEADER_ELECTION             := false
IGNORE_OPERATION_ANNOTATION := true

WEBHOOK_CONFIG_PORT    := 8443
WEBHOOK_CONFIG_MODE    := url
ifeq ($(uname),Darwin)
  WEBHOOK_CONFIG_URL     := host.docker.internal:$(WEBHOOK_CONFIG_PORT)
else
  localip                := $(shell ip route get 1.2.3.4 | awk '{print $$7}')
  WEBHOOK_CONFIG_URL     := $(localip):$(WEBHOOK_CONFIG_PORT)
endif
EXTENSION_NAMESPACE    :=
WEBHOOK_PARAM := --webhook-config-url=$(WEBHOOK_CONFIG_URL)
ifeq ($(WEBHOOK_CONFIG_MODE), service)
  WEBHOOK_PARAM := --webhook-config-namespace=$(EXTENSION_NAMESPACE)
endif

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif

#########################################
# Tools                                 #
#########################################

TOOLS_DIR := $(HACK_DIR)/tools
include $(GARDENER_HACK_DIR)/tools.mk

GO_MISSPELL := $(TOOLS_BIN_DIR)/misspell
GO_MISSPELL_VERSION ?= v0.7.0

.PHONY: start
start:
	@LEADER_ELECTION_NAMESPACE=garden go run \
			cmd/$(EXTENSION_PREFIX)-$(NAME)/main.go \
			--config-file=./example/00-config.yaml \
			--leader-election=$(LEADER_ELECTION) \
			--log-level=debug

.PHONY: start-admission
start-admission:
	LEADER_ELECTION_NAMESPACE=garden go run \
		-ldflags $(LD_FLAGS) \
		./cmd/$(EXTENSION_PREFIX)-$(ADMISSION_NAME) \
		--webhook-config-server-host=0.0.0.0 \
		--webhook-config-server-port=$(WEBHOOK_CONFIG_PORT) \
		--webhook-config-mode=$(WEBHOOK_CONFIG_MODE) \
		--health-bind-address=:8082 \
		--metrics-bind-address=:8083 \
		--autonomous-shoot-cluster=false \
        $(WEBHOOK_PARAM)

.PHONY: start-admission-debug
start-admission-debug:
	LEADER_ELECTION_NAMESPACE=garden dlv debug \
                --listen=:2345 \
		./cmd/$(EXTENSION_PREFIX)-$(ADMISSION_NAME) \
		-- --webhook-config-server-host=0.0.0.0 \
		--webhook-config-server-port=$(WEBHOOK_CONFIG_PORT) \
		--webhook-config-mode=$(WEBHOOK_CONFIG_MODE) \
		--health-bind-address=:8082 \
		--metrics-bind-address=:8083 \
        $(WEBHOOK_PARAM)

#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################

.PHONY: install
install:
	@LD_FLAGS=$(LD_FLAGS) EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) \
	bash $(GARDENER_HACK_DIR)/install.sh ./...

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: docker-images
docker-images:
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(EXTENSION_PREFIX)-$(NAME):$(VERSION) -t $(IMAGE_PREFIX)/$(EXTENSION_PREFIX)-$(NAME):latest -f Dockerfile -m 6g --target $(EXTENSION_PREFIX)-$(NAME) .
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):$(VERSION) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):latest -f Dockerfile -m 6g --target $(EXTENSION_PREFIX)-$(ADMISSION_NAME) .

.PHONY: docker-push
docker-push:
	@docker push $(IMAGE_PREFIX)/$(NAME):$(VERSION)
	@docker push $(IMAGE_PREFIX)/$(NAME):latest

#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: tidy
tidy:
	@go mod tidy
	@mkdir -p $(REPO_ROOT)/.ci/hack && cp $(GARDENER_HACK_DIR)/.ci/* $(HACK_DIR)/generate-controller-registration.sh $(REPO_ROOT)/.ci/hack/ && chmod +xw $(REPO_ROOT)/.ci/hack/*
	@cp $(GARDENER_HACK_DIR)/cherry-pick-pull.sh $(HACK_DIR)/cherry-pick-pull.sh && chmod +xw $(HACK_DIR)/cherry-pick-pull.sh


.PHONY: clean
clean:
	@$(shell find ./example -type f -name "controller-registration.yaml" -exec rm '{}' \;)
	@bash $(GARDENER_HACK_DIR)/clean.sh ./cmd/... ./pkg/... ./imagevector/... ./falco/...

.PHONY: check-generate
check-generate:
	@bash $(GARDENER_HACK_DIR)/check-generate.sh $(REPO_ROOT)

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT) $(HELM) $(YQ)
	@bash $(GARDENER_HACK_DIR)/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/...  ./imagevector/... ./falco/...
	@bash $(GARDENER_HACK_DIR)/check-charts.sh ./charts

$(GO_MISSPELL):  $(call tool_version_file,$(GO_MISSPELL),$(GO_MISSPELL_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install github.com/golangci/misspell/cmd/misspell@$(GO_MISSPELL_VERSION)

spell: $(GO_MISSPELL)
	@bash $(HACK_DIR)/check-spell.sh $(GO_MISSPELL)

.PHONY: generate-controller-registration
generate-controller-registration:
	@bash $(HACK_DIR)/generate-controller-registration.sh extension-shoot-falco charts/$(EXTENSION_PREFIX)-$(NAME) 0.0.1 example/ControllerRegistration.yaml

.PHONY: generate
generate: $(CONTROLLER_GEN) $(GEN_CRD_API_REFERENCE_DOCS) $(EXTENSION_GEN) $(HELM) $(MOCKGEN) $(KUSTOMIZE) $(YQ) $(VGOPATH)
	@VGOPATH=$(VGOPATH) REPO_ROOT=$(REPO_ROOT) GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) hack/update-codegen.sh
	@VGOPATH=$(VGOPATH) REPO_ROOT=$(REPO_ROOT) GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) bash $(GARDENER_HACK_DIR)/generate-sequential.sh ./charts/... ./cmd/... ./example/... ./pkg/...
	@$(MAKE) format

.PHONY: format
format: $(GOIMPORTS) $(GOIMPORTSREVISER)
	@bash $(GARDENER_HACK_DIR)/format.sh ./cmd ./pkg ./imagevector ./falco

.PHONY: sast
sast: $(GOSEC)
	@bash $(GARDENER_HACK_DIR)/sast.sh

.PHONY: sast-report
sast-report: $(GOSEC)
	@bash $(GARDENER_HACK_DIR)/sast.sh --gosec-report true

.PHONY: test
test:
	@SKIP_FETCH_TOOLS=1 bash $(HACK_DIR)/test.sh ./cmd/... ./pkg/... ./falco/... ./imagevector

.PHONY: test-cov
test-cov:
	@SKIP_FETCH_TOOLS=1 bash $(GARDENER_HACK_DIR)/test-cover.sh ./cmd/... ./pkg/...

.PHONY: test-clean
test-clean:
	@bash $(GARDENER_HACK_DIR)/test-cover-clean.sh

.PHONY: generate-profile
generate-profile:
	@$(HACK_DIR)/generate-falco-profile  imagevector/images.yaml falco/falcoversions.yaml falco/falcosidekickversions.yaml >falco/falco-profile.yaml

.PHON: validate-imagevector
validate-imagevector:
	@$(HACK_DIR)/validate-imagevector.py imagevector/images.yaml

.PHONY: validate-falco-rules
validate-falco-rules:
	$(HACK_DIR)/validate-falco-rules falco/falco-profile.yaml falco/rules

.PHONY: verify
verify: check format test sast validate-imagevector spell

.PHONY: verify-extended
verify-extended: check-generate check format validate-imagevector generate-profile test sast-report spell
#verify-extended: check-generate check format test test-cov test-clean


.PHONY: extension-up extension-operator-up
extension-up extension-operator-up: export EXTENSION_VERSION = $(VERSION)
extension-up extension-operator-up: export SKAFFOLD_DEFAULT_REPO = garden.local.gardener.cloud:5001
extension-up extension-operator-up:  export SKAFFOLD_PUSH = true
extension-up extension-operator-up: export LD_FLAGS = $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION gardener-extension-shoot-falco-service)
extension-operator-up: export EXTENSION_GARDENER_HACK_DIR = $(GARDENER_HACK_DIR)
extension-operator-up extension-operator-down: export SKAFFOLD_FILENAME = skaffold-operator.yaml
extension-up extension-operator-up: $(SKAFFOLD) $(HELM) $(KUBECTL)
	$(SKAFFOLD) run --cache-artifacts=true

.PHONY: extension-down extension-operator-down
extension-down extension-operator-down:
	$(SKAFFOLD) delete
