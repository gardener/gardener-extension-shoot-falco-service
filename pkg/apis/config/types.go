// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

	// Cluster identity token configuration for global default destinations
	ClusterIdentityToken *ClusterIdentityTokenConfig

	// Lifetime of the CA certificates
	// (Falco - Falcosidekick communication)
	CertificateLifetime *metav1.Duration

	// Renew CA certificates after this duration
	CertificateRenewAfter *metav1.Duration

	// Default event logger
	// possible values are: "none", "central", "logging", "webhook"
	DefaultEventDestination *string

	// Global default destinations applied to all shoots unless opted out
	GlobalDefaultDestinations []GlobalDefaultDestination

	// Additional resources to deploy on the seed
	Additional *AdditionalConfig

	// VPA configuration defaults for Falco DaemonSet
	FalcoVPA *FalcoVPAConfig

	// Default resource requests for Falco pods
	DefaultRequests *FalcoResourceValues

	// Default resource limits for Falco pods (none by default)
	DefaultLimits *FalcoResourceValues
}

// GlobalDefaultDestination defines an operator-provided Falcosidekick output destination
type GlobalDefaultDestination struct {
	// Unique name for this destination
	Name string
	// Falcosidekick output configuration
	FalcosidekickOutput FalcosidekickOutput
}

// FalcosidekickOutput holds the Falcosidekick output key and value configuration
type FalcosidekickOutput struct {
	// Falcosidekick output key (e.g., "splunk", "webhook", "elasticsearch")
	Key string
	// Configuration values for the output (may contain template variables)
	Value *runtime.RawExtension
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
	Name string
	Helm HelmConfig
}

// HelmConfig specifies a Helm chart source and render values.
// Exactly one of OCIRepository or Chart must be set.
type HelmConfig struct {
	OCIRepository *gardencorev1.OCIRepository
	Chart         *string
	Values        *runtime.RawExtension
}

// ClusterIdentityTokenConfig holds configuration for issuing per-shoot JWT tokens
// used as template variable in global default destinations
type ClusterIdentityTokenConfig struct {
	// Private key (PEM-encoded RSA) for signing cluster identity tokens
	TokenIssuerPrivateKey string

	// Lifetime of the issued token
	TokenLifetime *metav1.Duration
}

// FalcoVPAConfig holds VPA defaults for the Falco DaemonSet
type FalcoVPAConfig struct {
	// Minimum resources VPA can recommend (floor)
	MinAllowed FalcoVPAResources

	// Maximum resources VPA can recommend (ceiling)
	MaxAllowed FalcoVPAResources
}

// FalcoVPAResources specifies resource quantities for VPA bounds
type FalcoVPAResources struct {
	Memory string
	Cpu    string
}

// FalcoResourceValues specifies resource quantities for Falco pod requests/limits
type FalcoResourceValues struct {
	Memory string
	Cpu    string
}
