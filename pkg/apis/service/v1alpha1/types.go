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
	// Resources defines default resource requests/limits applied to all worker
	// pools. Each value field accepts either a plain Kubernetes quantity
	// ("500m", "2Gi") or an arithmetic expression evaluated against node
	// capacity variables:
	//   nodeCPU         – number of CPU cores (float)
	//   nodeMemoryMi    – RAM in MiB (float)
	//   nodeMemoryGi    – RAM in GiB (float)
	//   nodeEphemeralGi – ephemeral storage in GiB (float)
	// CPU expression results are interpreted as millicores; memory as MiB.
	// If nil, system defaults apply.
	// +optional
	Resources *FalcoResources `json:"resources,omitempty"`

	// WorkerPoolResources allows per-worker-pool resource overrides, keyed by
	// pool name. A pool listed here inherits Resources for any field it does
	// not set. Pools not listed use Resources directly. If Resources is also
	// nil, system defaults apply.
	// +optional
	WorkerPoolResources map[string]*FalcoResources `json:"workerPoolResources,omitempty"`
}

// FalcoResources mirrors the existing structure exactly so that existing shoot
// specs require no migration. The Cpu and Memory fields now additionally accept
// arithmetic expressions (see FalcoConfig.Resources for the variable set).
type FalcoResources struct {
	// +optional
	Limits *ResourceValues `json:"limits,omitempty"`

	// +optional
	Requests *ResourceValues `json:"requests,omitempty"`
}

// ResourceValues holds a CPU and memory value, each of which is either a plain
// Kubernetes quantity or an arithmetic expression.
type ResourceValues struct {
	// Kubernetes quantity ("500m", "2") or arithmetic expression.
	// +optional
	Cpu *string `json:"cpu,omitempty"`
	// Kubernetes quantity ("2Gi", "512Mi") or arithmetic expression.
	// +optional
	Memory *string `json:"memory,omitempty"`
}
