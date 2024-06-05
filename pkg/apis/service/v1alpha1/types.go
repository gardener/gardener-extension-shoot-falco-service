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

	// use "gardener" or "falcoctl", defaults to "gardener"
	// +optional
	Resources *string `json:"resources,omitempty"`

	// Falcoctl configuration
	// +optional
	FalcoCtl *FalcoCtl `json:"falcoCtl,omitempty"`

	// Configuration for Gardener managed Falco
	// +optional
	Gardener *Gardener `json:"gardener,omitempty"`

	// Configuration for custom webhook
	// +optional
	CustomWebhook *Webhook `json:"webhook,omitempty"`
}

type FalcoCtl struct {
	// TODO
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
	RuleRefs []Rule `json:"ruleRefs,omitempty"`
}

type Rule struct {
	Ref string `json:"ref,omitempty"`
}

type Webhook struct {
	Enabled       *bool   `json:"enabled,omitempty"`
	Address       *string `json:"address,omitempty"`
	CustomHeaders *string `json:"customHeaders,omitempty"`
	Checkcerts    *bool   `json:"checkcerts,omitempty"`
}
