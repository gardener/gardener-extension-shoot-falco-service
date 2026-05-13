// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Configuration contains information about the falco extension configuration
type Configuration struct {
	metav1.TypeMeta

	// Falco extension configuration
	Falco *Falco

	// HealthCheckConfig is the config for the health check controller.
	HealthCheckConfig *healthcheckconfigv1alpha1.HealthCheckConfig
}

// Falco extension configuration
type Falco struct {
	// PriorityClass to use for Falco shoot deployment
	PriorityClassName *string

	// Central storage configuration
	CentralStorage *CentralStorageConfig

	// Lifetime of the CA certificates
	// (Falco - Falcosidekick communication)
	CertificateLifetime *metav1.Duration

	// Renew CA certificates after this duration
	CertificateRenewAfter *metav1.Duration

	// Default event logger
	// possible values are: "none", "central", "logging", "webhook"
	DefaultEventDestination *string

	// Additional resources to deploy on the seed
	Additional *AdditionalConfig
}

// Central storage configuration
type CentralStorageConfig struct {
	// Token lifetime
	TokenLifetime *metav1.Duration

	// Private key for token issuer
	TokenIssuerPrivateKey string

	// Ingestor URL
	URL string

	// Enabled ?
	Enabled bool
}

// AdditionalConfig holds configuration for additional seed-level resources.
type AdditionalConfig struct {
	SeedManagedResources []AdditionalSeedManagedResource
}

// AdditionalSeedManagedResource describes a Helm chart to deploy as a ManagedResource on the seed.
type AdditionalSeedManagedResource struct {
	Name      string
	Namespace string
	Helm      HelmConfig
}

// HelmConfig specifies a Helm chart to pull from an OCI repository and render with values.
type HelmConfig struct {
	OCIRepository gardencorev1.OCIRepository
	Values        map[string]interface{}
}
