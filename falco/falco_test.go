// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falco_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/imagevector"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils/falcoversions"
)

var _ = Describe("Falco", func() {
	var versions falco.Falco

	BeforeEach(func() {
		versions = falco.FalcoVersions()
	})

	Describe("ConfigIntegrity", func() {
		It("should have images for all falco versions", func() {
			images := imagevector.ImageVector()
			for _, fv := range versions.Falco.FalcoVersions {
				img := falcoversions.GetImageForVersion(images, "falco", fv.Version)
				Expect(img).NotTo(BeNil(), "No image for falco version %s", fv.Version)
			}
		})

		It("should have images for all falcosidekick versions", func() {
			images := imagevector.ImageVector()
			for _, fv := range versions.FalcoSidekickVersions.FalcosidekickVersions {
				img := falcoversions.GetImageForVersion(images, "falcosidekick", fv.Version)
				Expect(img).NotTo(BeNil(), "No image for falcosidekick version %s", fv.Version)
			}
		})
	})

	Describe("RulesIntegrity", func() {
		It("should have rules files for all falco versions", func() {
			rules := versions.Rules
			for _, fv := range versions.Falco.FalcoVersions {
				dir := "rules/" + fv.RulesVersion
				_, err := rules.ReadDir(dir)
				Expect(err).NotTo(HaveOccurred(), "no rules for Falco version %s", fv.RulesVersion)

				for _, file := range []string{constants.FalcoRules, constants.FalcoIncubatingRules, constants.FalcoSandboxRules} {
					rulesFile := dir + "/" + file
					rf, err := rules.ReadFile(rulesFile)
					Expect(err).NotTo(HaveOccurred(), "missing rules file %s for version %s", rulesFile, fv.RulesVersion)
					Expect(rf).NotTo(BeEmpty(), "rules file %s for version %s is empty", rulesFile, fv.RulesVersion)
				}
			}
		})
	})
})
