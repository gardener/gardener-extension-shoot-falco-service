// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Falco cluster configuration resource
type FalcoServiceConfig struct {
	metav1.TypeMeta `json:",inline"`

	// additional Falco configuration
	// +optional
	FalcoConfig *FalcoConfig `json:"falcoConfig,omitempty"`

	// Falco version to use
	// +optional
	FalcoVersion *string `json:"falcoVersion,omitempty"`

	// Automatically update Falco
	// +optional
	AutoUpdate *bool `json:"autoUpdate,omitempty"`

	// Enable periodic heartbeat events
	// +optional
	HeartbeatEvent *bool `json:"heartbeatEvent,omitempty"`

	// nodeSelector for Falco pods
	// +optional
	NodeSelector *map[string]string `json:"nodeSelector,omitempty"`

	// tolerations for Falco pods
	// +optional
	Tolerations *[]corev1.Toleration `json:"tolerations,omitempty"`

	Rules *Rules `json:"rules,omitempty"`

	Destinations *[]Destination `json:"destinations,omitempty"`
}

type Destination struct {
	Name               string  `json:"name,omitempty"`
	ResourceSecretName *string `json:"resourceSecretName,omitempty"`
}

type Rules struct {
	StandardRules *[]string     `json:"standard,omitempty"`
	CustomRules   *[]CustomRule `json:"custom,omitempty"`
}

type CustomRule struct {
	ResourceName   string `json:"resourceName,omitempty"`
	ShootConfigMap string `json:"shootConfigMap,omitempty"`
}

type FalcoCtl struct {
	Indexes      []FalcoCtlIndex `json:"indexes,omitempty"`
	AllowedTypes []string        `json:"allowedTypes,omitempty"`

	Install *Install `json:"install,omitempty"`
	Follow  *Follow  `json:"follow,omitempty"`
}

type FalcoCtlIndex struct {
	Name *string `json:"name,omitempty"`
	Url  *string `json:"url,omitempty"`
}

type Follow struct {
	Refs  []string `json:"refs,omitempty"`
	Every *string  `json:"every,omitempty"`
}

type Install struct {
	Refs        []string `json:"refs,omitempty"`
	ResolveDeps *bool    `json:"resolveDeps,omitempty"`
}

type Gardener struct {
	// use Falco rules from correspoonging rules release, defaults to true
	// +optional
	UseFalcoRules *bool `json:"useFalcoRules,omitempty"`

	// use Falco incubating rules from correspoonging rules release
	// +optional
	UseFalcoIncubatingRules *bool `json:"useFalcoIncubatingRules,omitempty"`

	// use Falco sandbox rules from corresponding rules release
	// +optional
	UseFalcoSandboxRules *bool `json:"useFalcoSandboxRules,omitempty"`

	// References to custom rules files
	// +optional
	CustomRules []string `json:"customRules,omitempty"`
}

type Webhook struct {
	Enabled       *bool              `json:"enabled,omitempty"`
	Address       *string            `json:"address,omitempty"`
	Method        *string            `json:"method,omitempty"`
	CustomHeaders *map[string]string `json:"customHeaders,omitempty"`
	Checkcerts    *bool              `json:"checkcerts,omitempty"`
	SecretRef     *string            `json:"secretRef,omitempty"`
}

type Output struct {
	LogFalcoEvents *bool    `json:"logFalcoEvents,omitempty"`
	EventCollector *string  `json:"eventCollector,omitempty"`
	CustomWebhook  *Webhook `json:"customWebhook,omitempty"`
}

type FalcoConfig struct {
	// Falco container resource settings
	// +optional
	Resources *FalcoResources `json:"resources,omitempty"`
}

type FalcoResources struct {
	// limits
	Limits *ResourceValues `json:"limits,omitempty"`

	// requests
	Requests *ResourceValues `json:"requests,omitempty"`
}

type ResourceValues struct {
	Cpu    *string `json:"cpu,omitempty"`
	Memory *string `json:"memory,omitempty"`
}
