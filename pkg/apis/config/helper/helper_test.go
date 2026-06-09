// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	. "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config/helper"
)

func TestHelper(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Helper Suite")
}

var _ = Describe("Helper", func() {
	Describe("#FindGlobalDefaultByName", func() {
		var gds []config.GlobalDefaultDestination

		BeforeEach(func() {
			gds = []config.GlobalDefaultDestination{
				{Name: "splunk-central", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
				{Name: "elastic-central", FalcosidekickOutput: config.FalcosidekickOutput{Key: "elasticsearch"}},
			}
		})

		It("should find an existing destination by name", func() {
			found := FindGlobalDefaultByName(gds, "splunk-central")
			Expect(found).NotTo(BeNil())
			Expect(found.Name).To(Equal("splunk-central"))
			Expect(found.FalcosidekickOutput.Key).To(Equal("splunk"))
		})

		It("should return nil for a nonexistent name", func() {
			Expect(FindGlobalDefaultByName(gds, "nonexistent")).To(BeNil())
		})

		It("should return nil for a nil slice", func() {
			Expect(FindGlobalDefaultByName(nil, "splunk-central")).To(BeNil())
		})
	})

	Describe("#GlobalDefaultKeyMap", func() {
		It("should build a map from name to key", func() {
			gds := []config.GlobalDefaultDestination{
				{Name: "splunk-central", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
				{Name: "elastic-central", FalcosidekickOutput: config.FalcosidekickOutput{Key: "elasticsearch"}},
			}
			keys := GlobalDefaultKeyMap(gds)
			Expect(keys).To(HaveLen(2))
			Expect(keys).To(HaveKeyWithValue("splunk-central", "splunk"))
			Expect(keys).To(HaveKeyWithValue("elastic-central", "elasticsearch"))
		})

		It("should return an empty map for nil input", func() {
			Expect(GlobalDefaultKeyMap(nil)).To(BeEmpty())
		})
	})
})
