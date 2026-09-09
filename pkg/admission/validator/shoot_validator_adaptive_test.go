// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"github.com/gardener/gardener/pkg/apis/core"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

var _ = Describe("verifyFalcoConfigAdaptiveResources", func() {
	var (
		shootWithPools *core.Shoot
		shootNoPools   *core.Shoot
	)

	BeforeEach(func() {
		shootWithPools = &core.Shoot{
			Spec: core.ShootSpec{
				Provider: core.Provider{
					Workers: []core.Worker{{Name: "local"}},
				},
			},
		}
		shootNoPools = &core.Shoot{
			Spec: core.ShootSpec{
				Provider: core.Provider{},
			},
		}
	})

	It("returns nil when AdaptiveResources is not set", func() {
		conf := &service.FalcoServiceConfig{}
		Expect(verifyFalcoConfigAdaptiveResources(conf, shootWithPools)).To(Succeed())
	})

	It("returns nil when FalcoConfig is nil", func() {
		Expect(verifyFalcoConfigAdaptiveResources(nil, shootWithPools)).To(Succeed())
	})

	It("rejects AdaptiveResources on a shoot with no worker pools", func() {
		conf := falcoConfWithFormulas(stringValue("NodeCPU * 100.0"), nil, nil, nil)
		err := verifyFalcoConfigAdaptiveResources(conf, shootNoPools)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("worker pool"))
	})

	It("rejects an empty Formulas struct", func() {
		conf := &service.FalcoServiceConfig{
			FalcoConfig: &service.FalcoConfig{
				AdaptiveResources: &service.AdaptiveResources{
					Formulas: service.ResourceFormulas{},
				},
			},
		}
		err := verifyFalcoConfigAdaptiveResources(conf, shootWithPools)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("at least one formula"))
	})

	It("rejects an invalid expression", func() {
		conf := falcoConfWithFormulas(stringValue("not_a_var * 2"), nil, nil, nil)
		err := verifyFalcoConfigAdaptiveResources(conf, shootWithPools)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cpuRequest"))
	})

	It("accepts a valid expression on a shoot with worker pools", func() {
		conf := falcoConfWithFormulas(stringValue("NodeCPU * 100.0"), nil, stringValue("512.0"), nil)
		Expect(verifyFalcoConfigAdaptiveResources(conf, shootWithPools)).To(Succeed())
	})

	It("accepts all four formulas set", func() {
		conf := falcoConfWithFormulas(
			stringValue("NodeCPU * 100.0"),
			stringValue("NodeCPU * 200.0"),
			stringValue("NodeMemoryMi / 8.0"),
			stringValue("NodeMemoryMi / 4.0"),
		)
		Expect(verifyFalcoConfigAdaptiveResources(conf, shootWithPools)).To(Succeed())
	})
})

var _ = Describe("verifyFalcoConfigResources mutual exclusion", func() {
	It("rejects both Resources and AdaptiveResources set", func() {
		conf := &service.FalcoServiceConfig{
			FalcoConfig: &service.FalcoConfig{
				Resources: &service.FalcoResources{},
				AdaptiveResources: &service.AdaptiveResources{
					Formulas: service.ResourceFormulas{CPURequest: stringValue("500.0")},
				},
			},
		}
		err := verifyFalcoConfigResources(conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("mutually exclusive"))
	})

	It("accepts only Resources set", func() {
		conf := &service.FalcoServiceConfig{
			FalcoConfig: &service.FalcoConfig{
				Resources: &service.FalcoResources{},
			},
		}
		Expect(verifyFalcoConfigResources(conf)).To(Succeed())
	})

	It("accepts only AdaptiveResources set", func() {
		conf := &service.FalcoServiceConfig{
			FalcoConfig: &service.FalcoConfig{
				AdaptiveResources: &service.AdaptiveResources{
					Formulas: service.ResourceFormulas{CPURequest: stringValue("500.0")},
				},
			},
		}
		Expect(verifyFalcoConfigResources(conf)).To(Succeed())
	})
})

func falcoConfWithFormulas(cpuReq, cpuLim, memReq, memLim *string) *service.FalcoServiceConfig {
	return &service.FalcoServiceConfig{
		FalcoConfig: &service.FalcoConfig{
			AdaptiveResources: &service.AdaptiveResources{
				Formulas: service.ResourceFormulas{
					CPURequest:    cpuReq,
					CPULimit:      cpuLim,
					MemoryRequest: memReq,
					MemoryLimit:   memLim,
				},
			},
		},
	}
}
