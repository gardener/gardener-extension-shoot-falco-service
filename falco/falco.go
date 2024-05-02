// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falco

import (
	"embed"

	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils/falcoversions"
)

type Falco struct {
	Falco                 *falcoversions.FalcoVersions
	FalcoSidekickVersions *falcoversions.FalcosidekickVersions
	Rules                 embed.FS
}

var (
	//go:embed falcoversions.yaml
	falcoVersionsYAML string

	//go:embed falcosidekickversions.yaml
	falcoSidekickVersionsYAML string

	//go:embed rules
	rulesFiles embed.FS

	falcoVersions         *falcoversions.FalcoVersions
	falcoSidekickVersions *falcoversions.FalcosidekickVersions
)

func init() {
	var err error

	falcoVersions, err = falcoversions.ReadFalcoVersions([]byte(falcoVersionsYAML))
	runtime.Must(err)

	falcoSidekickVersions, err = falcoversions.ReadFalcosidekickVersions([]byte(falcoSidekickVersionsYAML))
	runtime.Must(err)

}

// Retrun all the needed Falco configuration
func FalcoVersions() Falco {
	return Falco{
		Falco:                 falcoVersions,
		FalcoSidekickVersions: falcoSidekickVersions,
		Rules:                 rulesFiles,
	}
}

func (f *Falco) GetRulesForVersion(name string, version string) (*string, error) {
	return nil, nil
}
