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

	// Automatically update Falco
	// +optional
	AutoUpdate *bool

	// use "gardener" or "falcoctl", defaults to "gardener"
	// +optional
	Resources *string

	// Falcoctl configuration
	// +optional
	FalcoCtl *FalcoCtl

	// Configuration for Gardener managed Falco
	// +optional
	Gardener *Gardener

	// Configuration for custom webhook
	// +optional
	CustomWebhook *Webhook
}

type FalcoCtl struct {

	// TODO
}

type Gardener struct {
	// use Falco rules from correspoonging rules release, defaults to true
	// +optional
	UseFalcoRules *bool

	// use Falco incubating rules from correspoonging rules release
	// +optional
	UseFalcoIncubatingRules *bool

	// use Falco sandbox rules from corresponding rules release
	// +optional
	UseFalcoSandboxRules *bool

	// References to custom rules files
	// +optional
	CustomRules []string
}

type Webhook struct {
	Enabled       *bool
	Address       *string
	CustomHeaders *string
	Checkcerts    *bool
}
