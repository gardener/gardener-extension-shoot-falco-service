// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type FalcoProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              Spec `json:"spec"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type FalcoProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []FalcoProfile `json:"items"`
}

type Spec struct {
	Versions Versions `json:"versions"`
	Images   Images   `json:"images"`
}

type Versions struct {
	Falco         []FalcoVersion         `json:"falco"`
	Falcosidekick []FalcosidekickVersion `json:"falcosidekick"`
	Falcoctl      []FalcoctlVersion      `json:"falcoctl"`
}

type Images struct {
	Falco         []ImageSpec `json:"falco"`
	Falcosidekick []ImageSpec `json:"falcosidekick"`
	Falcoctl      []ImageSpec `json:"falcoctl"`
}

type FalcoVersion struct {
	Classification string  `json:"classification"`
	ExpirationDate *string `json:"expirationDate,omitempty"`
	Version        string  `json:"version"`
	RulesVersion   string  `json:"rulesVersion"`
}

type FalcosidekickVersion struct {
	Classification string  `json:"classification"`
	ExpirationDate *string `json:"expirationDate,omitempty"`
	Version        string  `json:"version"`
}

type FalcoctlVersion struct {
	Classification string  `json:"classification"`
	ExpirationDate *string `json:"expirationDate,omitempty"`
	Version        string  `json:"version"`
}

type ImageSpec struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Repository   string `json:"repository"`
	Tag          string `json:"tag"`
}

type Version interface {
	GetClassification() string
	GetExpirationDate() *string
	GetVersion() string
}

func (v FalcoVersion) GetVersion() string {
	return v.Version
}

func (v FalcoVersion) GetClassification() string {
	return v.Classification
}

func (v FalcoVersion) GetExpirationDate() *string {
	return v.ExpirationDate
}

func (v FalcosidekickVersion) GetVersion() string {
	return v.Version
}

func (v FalcosidekickVersion) GetClassification() string {
	return v.Classification
}

func (v FalcosidekickVersion) GetExpirationDate() *string {
	return v.ExpirationDate
}

func (v FalcoctlVersion) GetVersion() string {
	return v.Version
}

func (v FalcoctlVersion) GetClassification() string {
	return v.Classification
}

func (v FalcoctlVersion) GetExpirationDate() *string {
	return v.ExpirationDate
}
