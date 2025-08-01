# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM golang:1.24.5 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-shoot-falco-service

# Copy go mod and sum files
COPY go.mod go.sum ./
# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

COPY . .

ARG EFFECTIVE_VERSION
RUN make install EFFECTIVE_VERSION=$EFFECTIVE_VERSION

############# base
FROM gcr.io/distroless/static-debian12:nonroot AS base

############# gardener-extension-shoot-falco
FROM base AS gardener-extension-shoot-falco-service

WORKDIR /
COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-shoot-falco-service /gardener-extension-shoot-falco-service
ENTRYPOINT ["/gardener-extension-shoot-falco-service"]

############# gardener-extension-admission-shoot-falco-service
FROM base AS gardener-extension-admission-shoot-falco-service

WORKDIR /
COPY --from=builder /go/bin/gardener-extension-admission-shoot-falco-service /gardener-extension-admission-shoot-falco-service
ENTRYPOINT ["/gardener-extension-admission-shoot-falco-service"]
