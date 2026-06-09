// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	. "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config/validation"
)

func TestValidation(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Validation Suite")
}

var _ = Describe("ValidateConfiguration", func() {
	It("should pass for nil Falco config", func() {
		conf := &config.Configuration{}
		Expect(ValidateConfiguration(conf)).To(BeEmpty())
	})

	It("should pass for empty global defaults", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{},
			},
		}
		Expect(ValidateConfiguration(conf)).To(BeEmpty())
	})

	It("should pass for valid global defaults", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "my-splunk", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
					{Name: "my-elastic", FalcosidekickOutput: config.FalcosidekickOutput{Key: "elasticsearch"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(BeEmpty())
	})

	It("should reject a name that conflicts with a standard destination", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "logging", FalcosidekickOutput: config.FalcosidekickOutput{Key: "loki"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(ConsistOf(
			PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("falco.globalDefaultDestinations[0].name"),
			})),
		))
	})

	It("should reject duplicate names", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "my-splunk", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
					{Name: "my-splunk", FalcosidekickOutput: config.FalcosidekickOutput{Key: "webhook"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(ConsistOf(
			PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeDuplicate),
				"Field": Equal("falco.globalDefaultDestinations[1].name"),
			})),
		))
	})

	It("should reject duplicate output keys", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "dest-a", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
					{Name: "dest-b", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(ConsistOf(
			PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("falco.globalDefaultDestinations[1].falcosidekickOutput.key"),
			})),
		))
	})
})
