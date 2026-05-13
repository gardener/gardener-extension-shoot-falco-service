// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Configuration contains information about the falco extension configuration
type Configuration struct {
	metav1.TypeMeta `json:",inline"`

	// Falco extension configuration
	Falco *Falco `json:"falco,omitempty"`

	// HealthCheckConfig is the config for the health check controller.
	// +optional
	HealthCheckConfig *healthcheckconfigv1alpha1.HealthCheckConfig `json:"healthCheckConfig,omitempty"`
}

// Falco extension configuration
type Falco struct {
	// PriorityClass to use for Falco shoot deployment
	PriorityClassName *string `json:"priorityClassName,omitempty"`

	// Central storage configuration
	CentralStorage *CentralStorageConfig `json:"centralStorage,omitempty"`

	// Lifetime of the CA certificates
	// +optional
	CertificateLifetime *metav1.Duration `json:"certificateLifetime,omitempty"`

	// Renew CA certificates after this duration
	// +optional
	CertificateRenewAfter *metav1.Duration `json:"certificateRenewAfter,omitempty"`

	// Default event logger
	// possible values are: "none", "central", "cluster", "webhook"
	DefaultEventDestination *string `json:"defaultEventDestination,omitempty"`

	// Global default destinations applied to all shoots unless opted out
	// +optional
	GlobalDefaultDestinations []GlobalDefaultDestination `json:"globalDefaultDestinations,omitempty"`

	// Additional resources to deploy on the seed
	// +optional
	Additional *AdditionalConfig `json:"additional,omitempty"`
}

// GlobalDefaultDestination defines an operator-provided Falcosidekick output destination
type GlobalDefaultDestination struct {
	// Unique name for this destination
	Name string `json:"name"`
	// Falcosidekick output configuration
	FalcosidekickOutput FalcosidekickOutput `json:"falcosidekickOutput"`
}

// FalcosidekickOutput holds the Falcosidekick output key and value configuration
type FalcosidekickOutput struct {
	// Falcosidekick output key (e.g., "splunk", "webhook", "elasticsearch")
	Key string `json:"key"`
	// Configuration values for the output (may contain template variables)
	Value *runtime.RawExtension `json:"value,omitempty"`
}

// Central storage configuration
type CentralStorageConfig struct {
	// Token lifetime
	// +optional
	TokenLifetime *metav1.Duration `json:"tokenLifetime,omitempty"`

	// Private key for token issuer
	// +optional
	TokenIssuerPrivateKey string `json:"tokenIssuerPrivateKey,omitempty"`

	// Ingestor URL
	// +optional
	URL string `json:"url,omitempty"`

	// Central storage configuration enabled
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

// AdditionalConfig holds configuration for additional seed-level resources.
type AdditionalConfig struct {
	// SeedManagedResources is a list of Helm charts to deploy as ManagedResources on the seed.
	// +optional
	SeedManagedResources []AdditionalSeedManagedResource `json:"seedManagedResources,omitempty"`
}

// AdditionalSeedManagedResource describes a Helm chart to deploy as a ManagedResource on the seed.
type AdditionalSeedManagedResource struct {
	// Name is the name of the ManagedResource.
	Name string `json:"name"`

	// Helm specifies the chart to pull and render.
	Helm HelmConfig `json:"helm"`
}

// HelmConfig specifies a Helm chart to pull from an OCI repository and render with values.
type HelmConfig struct {
	// OCIRepository defines where to pull the chart from.
	OCIRepository gardencorev1.OCIRepository `json:"ociRepository"`

	// Values are the Helm values to use when rendering the chart.
	// +optional
	Values *runtime.RawExtension `json:"values,omitempty"`
}
