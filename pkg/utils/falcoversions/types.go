// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falcoversions

type FalcoVersions struct {
	FalcoVersions []FalcoVersion `json:"falcoVersions"`
}

type FalcoVersion struct {
	Version string `json:"version"`

	Classification string `json:"classification"`

	RulesVersion string `json:"rulesVersion"`
}

type FalcosidekickVersions struct {
	FalcosidekickVersions []FalcosidekickVersion `json:"falcosidekickVersions"`
}

type FalcosidekickVersion struct {
	Version string `json:"version"`

	Classification string `json:"classification"`
}
