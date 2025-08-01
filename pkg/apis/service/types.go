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

	// Enable periodic heartbeat events
	// +optional
	HeartbeatEvent *bool

	// nodeSelector for Falco pods
	// +optional
	NodeSelector *map[string]string

	Rules *Rules

	Destinations *[]Destination
}

type Destination struct {
	Name               string
	ResourceSecretName *string
}

type Rules struct {
	StandardRules *[]string
	CustomRules   *[]CustomRule
}

type CustomRule struct {
	ResourceName   string
	ShootConfigMap string
}

type FalcoCtl struct {
	Indexes      []FalcoCtlIndex
	AllowedTypes []string

	Install *Install
	Follow  *Follow
}

type FalcoCtlIndex struct {
	Name *string
	Url  *string
}

type Follow struct {
	Refs  []string
	Every *string
}

type Install struct {
	Refs        []string
	ResolveDeps *bool
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
	Method        *string
	CustomHeaders *map[string]string
	Checkcerts    *bool
	SecretRef     *string
}

type Output struct {
	// Log Falco events to the pod log where it can be scraped by the
	// log collector. Defaults to true. Logs are automatically collected
	// in the Gardener context.
	LogFalcoEvents *bool

	// Specify the log collector to use. There are currently three options;
	// one of them requires additional configuration:
	// - "none": do not collect Falco event logs. This is useful if you
	//   scrape and process the event logs yourself.
	// - "cluster": us the gardener logging stack to collect and store
	//   Falco event logs. This is the default.
	// - "central": use the Gardener central Falco event storage
	// - "custom": push Falco events to a custom collector. This option
	//   requires the custom webhook configuration.
	EventCollector *string

	// Configuration for custom webhook. Default is empty
	CustomWebhook *Webhook
}
