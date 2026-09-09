// SPDX-FileCopyrightText: Contributors to the Gardener project
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
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	Rules *Rules `json:"rules,omitempty"`

	Destinations []Destination `json:"destinations,omitempty"`
}

type Destination struct {
	Name               string  `json:"name,omitempty"`
	Enabled            *bool   `json:"enabled,omitempty"`
	ResourceSecretName *string `json:"resourceSecretName,omitempty"`
}

type Rules struct {
	StandardRules []string     `json:"standard,omitempty"`
	CustomRules   []CustomRule `json:"custom,omitempty"`
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
	// Resources configures static resource requests/limits for the Falco container.
	// Mutually exclusive with AdaptiveResources. If neither is set, chart defaults apply.
	// +optional
	Resources *FalcoResources `json:"resources,omitempty"`

	// AdaptiveResources enables per-worker-pool dynamic resource sizing.
	// The feature is active when this field is non-nil. Mutually exclusive with Resources.
	// Only available for Gardener-managed shoots with worker pools.
	// +optional
	AdaptiveResources *AdaptiveResources `json:"adaptiveResources,omitempty"`
}

// AdaptiveResources configures per-worker-pool dynamic resource sizing for Falco.
type AdaptiveResources struct {
	// Formulas defines arithmetic expressions for each resource field.
	Formulas ResourceFormulas `json:"formulas"`
}

// ResourceFormulas holds one optional expression per resource field.
// Each expression is evaluated against node capacity variables and must produce a number.
type ResourceFormulas struct {
	// CPURequest expression. Result unit: millicores (500 → "500m").
	// +optional
	CPURequest *string `json:"cpuRequest,omitempty"`

	// CPULimit expression. Result unit: millicores.
	// +optional
	CPULimit *string `json:"cpuLimit,omitempty"`

	// MemoryRequest expression. Result unit: MiB (2048 → "2048Mi").
	// +optional
	MemoryRequest *string `json:"memoryRequest,omitempty"`

	// MemoryLimit expression. Result unit: MiB.
	// +optional
	MemoryLimit *string `json:"memoryLimit,omitempty"`
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
