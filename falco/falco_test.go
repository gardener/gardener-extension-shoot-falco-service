// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falco

import (
	"testing"

	iv "github.com/gardener/gardener/pkg/utils/imagevector"

	"github.com/gardener/gardener-extension-shoot-falco-service/imagevector"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils/falcoversions"
)

var (
	versions Falco
)

func init() {
	versions = FalcoVersions()
}

func Version(version string) iv.FindOptionFunc {
	return func(options *iv.FindOptions) {
		options.RuntimeVersion = &version
	}
}
func TestConfigIntegrity(t *testing.T) {

	images := imagevector.ImageVector()

	for _, fv := range versions.Falco.FalcoVersions {
		img := falcoversions.GetImageForVersion(images, "falco", fv.Version)
		if img == nil {
			t.Errorf("No image for falco version %s", fv.Version)
		}
	}
	for _, fv := range versions.FalcoSidekickVersions.FalcosidekickVersions {
		img := falcoversions.GetImageForVersion(images, "falcosidekick", fv.Version)
		if img == nil {
			t.Errorf("No image for falcosidekick version %s", fv.Version)
		}
	}
}

func TestRulesIntegrity(t *testing.T) {
	rules := versions.Rules
	for _, fv := range versions.Falco.FalcoVersions {
		dir := "rules/" + fv.RulesVersion
		_, err := rules.ReadDir(dir)
		if err != nil {
			t.Fatalf("no tules for Falco version %s", fv.RulesVersion)
		}
		for _, file := range []string{constants.FalcoRules, constants.FalcoIncubatingRules, constants.FalcoSandboxRules} {
			rulesFile := dir + "/" + file
			rf, err := rules.ReadFile(rulesFile)
			if err != nil {
				t.Errorf("missing rules file %s for version %s", rulesFile, fv.RulesVersion)
			}
			if len(rf) == 0 {
				t.Errorf("rules file %s for version %s is empty", rulesFile, fv.RulesVersion)
			}
		}
	}
}
