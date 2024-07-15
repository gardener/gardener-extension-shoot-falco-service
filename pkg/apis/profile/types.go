// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type FalcoProfile struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec Spec
}
type FalcoProfileList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []FalcoProfile `json:"items"`
}
type Spec struct {
	Versions Versions

	Images Images
}

type Versions struct {
	Falco []FalcoVersion

	Falcosidekick []FalcosidekickVersion
}

type Images struct {
	Falco         []ImageSpec
	Falcosidekick []ImageSpec
}

type FalcoVersion struct {
	Classification string

	ExpirationDate *string

	Version string

	RulesVersion string
}

type FalcosidekickVersion struct {
	Classification string

	ExpirationDate *string

	Version string
}

type ImageSpec struct {
	Version      string
	Architecture string
	Repository   string
	Tag          string
}
