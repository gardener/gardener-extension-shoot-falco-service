// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type FalcoProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              Spec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type FalcoProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []FalcoProfile `json:"items"`
}

type Spec struct {
	Versions Versions `json:"versions"`

	Images Images `json:"images"`
}

type Versions struct {
	Falco []FalcoVersion `json:"falco"`

	Falcosidekick []FalcosidekickVersion `json:"falcosidekick"`
}

type Images struct {
	Falco         []ImageSpec `json:"falco"`
	Falcosidekick []ImageSpec `json:"falcosidekick"`
}

type FalcoVersion struct {
	Classification string `json:"classification"`

	ExpirationDate *string `json:"expirationDate,omitempty"`

	Version string `json:"version"`

	RulesVersion string `json:"rulesVersion"`
}

type FalcosidekickVersion struct {
	Classification string `json:"classification"`

	ExpirationDate *string `json:"expirationDate,omitempty"`

	Version string `json:"version"`
}

type ImageSpec struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Repository   string `json:"repository"`
	Tag          string `json:"tag"`
}
