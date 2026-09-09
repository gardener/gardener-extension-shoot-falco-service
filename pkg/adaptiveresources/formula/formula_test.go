// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package formula_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/adaptiveresources/formula"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

func TestFormula(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Formula Suite")
}

func strPtr(s string) *string { return &s }

var _ = Describe("Compile", func() {
	It("accepts a valid expression", func() {
		f := apisservice.ResourceFormulas{CPURequest: strPtr("NodeCPU * 100")}
		c, err := formula.Compile(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())
	})

	It("rejects an invalid expression", func() {
		f := apisservice.ResourceFormulas{CPURequest: strPtr("unknown_var * 2")}
		_, err := formula.Compile(f)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cpuRequest"))
	})

	It("rejects a non-numeric expression", func() {
		// string literals don't satisfy AsFloat64
		f := apisservice.ResourceFormulas{MemoryLimit: strPtr(`"hello"`)}
		_, err := formula.Compile(f)
		Expect(err).To(HaveOccurred())
	})

	It("compiles nil fields without error", func() {
		c, err := formula.Compile(apisservice.ResourceFormulas{})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.CPURequest).To(BeNil())
		Expect(c.CPULimit).To(BeNil())
		Expect(c.MemoryRequest).To(BeNil())
		Expect(c.MemoryLimit).To(BeNil())
	})

	It("produces a stable ConfigHash for equal formulas", func() {
		expr1 := "NodeCPU * 100"
		f1 := apisservice.ResourceFormulas{CPURequest: &expr1}
		expr2 := "NodeCPU * 100"
		f2 := apisservice.ResourceFormulas{CPURequest: &expr2}
		c1, _ := formula.Compile(f1)
		c2, _ := formula.Compile(f2)
		Expect(c1.ConfigHash).To(Equal(c2.ConfigHash))
	})

	It("produces different ConfigHash for different formulas", func() {
		f1 := apisservice.ResourceFormulas{CPURequest: strPtr("NodeCPU * 100")}
		f2 := apisservice.ResourceFormulas{CPURequest: strPtr("NodeCPU * 200")}
		c1, _ := formula.Compile(f1)
		c2, _ := formula.Compile(f2)
		Expect(c1.ConfigHash).NotTo(Equal(c2.ConfigHash))
	})
})

var _ = Describe("Eval", func() {
	DescribeTable("CPU millicores formatting",
		func(expr string, env formula.NodeEnv, expected string) {
			f := apisservice.ResourceFormulas{CPURequest: &expr}
			c, err := formula.Compile(f)
			Expect(err).NotTo(HaveOccurred())
			result, err := c.Eval(env)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.CPURequest).To(Equal(expected))
		},
		Entry("2 CPUs → 400m", "NodeCPU < 4 ? 400.0 : 500.0", formula.NodeEnv{NodeCPU: 2}, "400m"),
		Entry("4 CPUs → 500m", "NodeCPU < 4 ? 400.0 : 500.0", formula.NodeEnv{NodeCPU: 4}, "500m"),
		Entry("floor truncation", "NodeCPU * 133.3", formula.NodeEnv{NodeCPU: 4}, "533m"),
	)

	DescribeTable("Memory MiB formatting",
		func(expr string, env formula.NodeEnv, expected string) {
			f := apisservice.ResourceFormulas{MemoryRequest: &expr}
			c, err := formula.Compile(f)
			Expect(err).NotTo(HaveOccurred())
			result, err := c.Eval(env)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.MemoryRequest).To(Equal(expected))
		},
		Entry("512Mi", "512.0", formula.NodeEnv{}, "512Mi"),
		Entry("uses NodeMemoryMi", "NodeMemoryMi / 8.0", formula.NodeEnv{NodeMemoryMi: 32768}, "4096Mi"),
		Entry("floor truncation", "NodeMemoryMi * 0.1", formula.NodeEnv{NodeMemoryMi: 10000}, "1000Mi"),
	)

	It("evaluates the canonical tiered formula", func() {
		// NodeCPU < 4 ? 400 : (NodeCPU < 8 ? 500 : (NodeCPU <= 100 ? 1024 : 2048))
		exprStr := "NodeCPU < 4 ? 400.0 : (NodeCPU < 8 ? 500.0 : (NodeCPU <= 100 ? 1024.0 : 2048.0))"
		f := apisservice.ResourceFormulas{CPURequest: &exprStr}
		c, err := formula.Compile(f)
		Expect(err).NotTo(HaveOccurred())

		cases := []struct {
			cpu float64
			exp string
		}{
			{2, "400m"},
			{4, "500m"},
			{8, "1024m"},
			{100, "1024m"},
			{101, "2048m"},
		}
		for _, tc := range cases {
			result, err := c.Eval(formula.NodeEnv{NodeCPU: tc.cpu})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.CPURequest).To(Equal(tc.exp), "NodeCPU=%v", tc.cpu)
		}
	})

	It("returns empty strings for nil programs", func() {
		c, err := formula.Compile(apisservice.ResourceFormulas{})
		Expect(err).NotTo(HaveOccurred())
		result, err := c.Eval(formula.NodeEnv{NodeCPU: 8, NodeMemoryMi: 32768})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.CPURequest).To(Equal(""))
		Expect(result.CPULimit).To(Equal(""))
		Expect(result.MemoryRequest).To(Equal(""))
		Expect(result.MemoryLimit).To(Equal(""))
	})

	It("evaluates independent programs for all four fields", func() {
		f := apisservice.ResourceFormulas{
			CPURequest:    strPtr("NodeCPU * 100.0"),
			CPULimit:      strPtr("NodeCPU * 200.0"),
			MemoryRequest: strPtr("NodeMemoryMi / 4.0"),
			MemoryLimit:   strPtr("NodeMemoryMi / 2.0"),
		}
		c, err := formula.Compile(f)
		Expect(err).NotTo(HaveOccurred())
		env := formula.NodeEnv{NodeCPU: 8, NodeMemoryMi: 32768}
		result, err := c.Eval(env)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.CPURequest).To(Equal("800m"))
		Expect(result.CPULimit).To(Equal("1600m"))
		Expect(result.MemoryRequest).To(Equal("8192Mi"))
		Expect(result.MemoryLimit).To(Equal("16384Mi"))
	})

	It("exposes NodeMemoryGi variable", func() {
		f := apisservice.ResourceFormulas{MemoryLimit: strPtr("NodeMemoryGi * 64.0")}
		c, err := formula.Compile(f)
		Expect(err).NotTo(HaveOccurred())
		result, err := c.Eval(formula.NodeEnv{NodeMemoryGi: 32})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.MemoryLimit).To(Equal("2048Mi"))
	})
})
