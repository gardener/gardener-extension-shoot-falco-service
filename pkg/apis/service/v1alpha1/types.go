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
	FalcoVersion *string `json:"falcoVersion,omitempty"`

	// use Falco incubating rules from correspoonging rules release
	UseFalcoIncubatingRules bool `json:"useFalcoIncubatingRules,omitempty"`

	// use Falco sandbox rules from corresponding rules release
	UseFalcoSandboxRules bool `json:"useFalcoSandboxRules,omitempty"`

	// References to custom rules files
	RuleRefs []string `json:"ruleRefs,omitempty"`
}
