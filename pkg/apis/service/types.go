// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Falco cluster configuration resource
type FalcoServiceConfig struct {
	metav1.TypeMeta

	// Falco version to use
	FalcoVersion *string

	// use Falco incubating rules from correspoonging rules release
	UseFalcoIncubatingRules bool

	// use Falco sandbox rules from corresponding rules release
	UseFalcoSandboxRules bool

	// References to custom rules files
	RuleRefs []string
}
