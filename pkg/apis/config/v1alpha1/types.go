// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// Lifetime of the CA certificates
	// +optional
	CertificateLifetime *metav1.Duration `json:"certificateLifetime,omitempty"`

	// Renew CA certificates after this duration
	// +optional
	CertificateRenewAfter *metav1.Duration `json:"certificateRenewAfter,omitempty"`

	// Token lifetime
	// +optional
	TokenLifetime *metav1.Duration `json:"tokenLifetime,omitempty"`

	// Private key for token issuer
	TokenIssuerPrivateKey string `json:"tokenIssuerPrivateKey,omitempty"`

	// Ingestor URL
	IngestorURL string `json:"ingestorURL,omitempty"`

	// Default event logger
	// possible values are: "none", "central", "cluster", "webhook"
	DefaultEventDestination *string `json:"defaultEventDestination,omitempty"`
}
