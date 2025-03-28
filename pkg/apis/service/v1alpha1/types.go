// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Falco cluster configuration resource
type FalcoServiceConfig struct {
	metav1.TypeMeta `json:",inline"`

	// Falco version to use
	// +optional
	FalcoVersion *string `json:"falcoVersion,omitempty"`

	// Automatically update Falco
	// +optional
	AutoUpdate *bool `json:"autoUpdate,omitempty"`

	// -------------------------------------------------------------------
	// remove by 2025-05-01

	// use "gardener" or "falcoctl", defaults to "gardener"
	// +optional
	Resources *string `json:"resources,omitempty"`

	// Falcoctl configuration
	// +optional
	FalcoCtl *FalcoCtl `json:"falcoCtl,omitempty"`

	// Configuration for Gardener managed Falco
	// +optional
	Gardener *Gardener `json:"gardener,omitempty"`

	// Specify the output configuration. Default to log Falco events
	// in the Gardener monitoring stack.
	Output *Output `json:"output,omitempty"`

	// required for migration
	// Configuration for custom webhook
	// +optional
	CustomWebhook *Webhook `json:"webhook,omitempty"`

	// -------------------------------------------------------------------
	// added due to issue #215

	Rules *Rules `json:"rules,omitempty"`

	Destinations *[]Destination `json:"destinations,omitempty"`
}

type Destination struct {
	Name      string `json:"name,omitempty"`
	SecretRef string `json:"secretRef,omitempty"`
}

type Rules struct {
	StandardRules *[]string     `json:"standard,omitempty"`
	CustomRules   *[]CustomRule `json:"custom,omitempty"`
}

type CustomRule struct {
	ResourceSecretRef string `json:"resourceSecretRef,omitempty"`
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
