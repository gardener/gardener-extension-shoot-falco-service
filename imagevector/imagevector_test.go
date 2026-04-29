// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener/pkg/utils/imagevector"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	. "github.com/gardener/gardener-extension-shoot-falco-service/imagevector"
)

var _ = Describe("Imagevector", func() {
	var (
		versions falco.Falco
		iv       imagevector.ImageVector
	)

	BeforeEach(func() {
		versions = falco.FalcoVersions()
		iv = ImageVector()
	})

	It("should have images for all falco versions", func() {
		for _, fv := range versions.Falco.FalcoVersions {
			found := false
			for _, image := range iv {
				if *image.Version == fv.Version && image.Name == "falco" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "no images found for falco version %s", fv.Version)
		}
	})

	It("should have images for all falcosidekick versions", func() {
		for _, fv := range versions.FalcoSidekickVersions.FalcosidekickVersions {
			found := false
			for _, image := range iv {
				if *image.Version == fv.Version && image.Name == "falcosidekick" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "no images found for falcosidekick version %s", fv.Version)
		}
	})

	It("should have a maintained version for every image", func() {
		for _, image := range iv {
			found := false
			for _, fv := range versions.Falco.FalcoVersions {
				if *image.Version == fv.Version && image.Name == "falco" {
					found = true
					break
				}
			}
			for _, fv := range versions.FalcoSidekickVersions.FalcosidekickVersions {
				if *image.Version == fv.Version && image.Name == "falcosidekick" {
					found = true
					break
				}
			}
			for _, fv := range versions.FalcoCtlVersions.FalcoctlVersions {
				if *image.Version == fv.Version && image.Name == "falcoctl" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "no version maintained for image %s version %s", image.Name, *image.Version)
		}
	})
})
