// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package falcoversions

type FalcoVersions struct {
	FalcoVersions []FalcoVersion `json:"falcoVersions"`
}

type FalcoVersion struct {
	Version        string `json:"version"`
	Classification string `json:"classification"`
	RulesVersion   string `json:"rulesVersion"`
}

type FalcosidekickVersions struct {
	FalcosidekickVersions []FalcosidekickVersion `json:"falcosidekickVersions"`
}

type FalcosidekickVersion struct {
	Version        string `json:"version"`
	Classification string `json:"classification"`
}

type FalcoctlVersions struct {
	FalcoctlVersions []FalcoctlVersion `json:"falcoctlVersions"`
}

type FalcoctlVersion struct {
	Version        string `json:"version"`
	Classification string `json:"classification"`
}
