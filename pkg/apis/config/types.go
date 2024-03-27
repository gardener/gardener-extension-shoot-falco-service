// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	healthcheckconfig "github.com/gardener/gardener/extensions/pkg/apis/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Configuration contains information about the falco extension configuration
type Configuration struct {
	metav1.TypeMeta

	// Falco extension configuration
	Falco *Falco

	// HealthCheckConfig is the config for the health check controller.
	HealthCheckConfig *healthcheckconfig.HealthCheckConfig
}

// Falco extension configuration
type Falco struct {
	// PriorityClass to use for Falco shoot deployment
	PriorityClassName *string

	// Lifetime of the CA certificates
	CertificateLifetime *metav1.Duration

	// Renew CA certificates after this duration
	CertificateRenewAfter *metav1.Duration

	// Token lifetime
	TokenLifetime *metav1.Duration

	// Private key for token issuer
	TokenIssuerPrivateKey string

	// Event inggestor URL
	IngestorURL string

	// Falco versions
	FalcoVersions []FalcoVersions

	// Falco images
	FalcoImages []FalcoImages
}

type FalcoImages struct {
	// Falco version
	Version string

	// supported architectures (amd64, arm64)
	Architectures []string

	// Falco image for that version
	FalcoImage string

	// Falcosidekick image for that version
	FalcosidekickImage string
}

type FalcoVersions struct {
	// Falco version
	Version string

	// Classification: [preview|supported|deprecated]
	Classification string

	// date when Falco version is going to expire
	// +optional
	ExpiryDate *metav1.Time
}
