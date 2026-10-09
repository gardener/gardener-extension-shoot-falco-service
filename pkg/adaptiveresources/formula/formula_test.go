// SPDX-FileCopyrightText: Contributors to the Gardener project
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

func makeResources(cpuReq, cpuLim, memReq, memLim *string) *apisservice.FalcoResources {
	r := &apisservice.FalcoResources{}
	if cpuReq != nil || memReq != nil {
		r.Requests = &apisservice.ResourceValues{Cpu: cpuReq, Memory: memReq}
	}
	if cpuLim != nil || memLim != nil {
		r.Limits = &apisservice.ResourceValues{Cpu: cpuLim, Memory: memLim}
	}
	return r
}

var _ = Describe("Compile", func() {
	It("accepts a valid expression", func() {
		r := makeResources(strPtr("NodeCPU * 100"), nil, nil, nil)
		c, err := formula.Compile(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())
	})

	It("rejects an invalid expression", func() {
		r := makeResources(strPtr("unknown_var * 2"), nil, nil, nil)
		_, err := formula.Compile(r)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("requests.cpu"))
	})

	It("rejects a non-numeric expression", func() {
		// string literals don't satisfy AsFloat64
		r := makeResources(nil, nil, nil, strPtr(`"hello"`))
		_, err := formula.Compile(r)
		Expect(err).To(HaveOccurred())
	})

	It("compiles nil resources without error", func() {
		c, err := formula.Compile(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())
	})

	It("compiles empty FalcoResources without error", func() {
		c, err := formula.Compile(&apisservice.FalcoResources{})
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())
	})

	It("accepts a plain k8s quantity", func() {
		r := makeResources(strPtr("500m"), nil, strPtr("512Mi"), nil)
		c, err := formula.Compile(r)
		Expect(err).NotTo(HaveOccurred())
		result, err := c.Eval(formula.NodeEnv{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.CPURequest).To(Equal("500m"))
		Expect(result.MemoryRequest).To(Equal("512Mi"))
	})

	It("produces a stable ConfigHash for equal resources", func() {
		r1 := makeResources(strPtr("NodeCPU * 100"), nil, nil, nil)
		r2 := makeResources(strPtr("NodeCPU * 100"), nil, nil, nil)
		c1, _ := formula.Compile(r1)
		c2, _ := formula.Compile(r2)
		Expect(c1.ConfigHash).To(Equal(c2.ConfigHash))
	})

	It("produces different ConfigHash for different resources", func() {
		r1 := makeResources(strPtr("NodeCPU * 100"), nil, nil, nil)
		r2 := makeResources(strPtr("NodeCPU * 200"), nil, nil, nil)
		c1, _ := formula.Compile(r1)
		c2, _ := formula.Compile(r2)
		Expect(c1.ConfigHash).NotTo(Equal(c2.ConfigHash))
	})
})

var _ = Describe("Eval", func() {
	DescribeTable("CPU millicores formatting",
		func(cpuExpr string, env formula.NodeEnv, expected string) {
			r := makeResources(strPtr(cpuExpr), nil, nil, nil)
			c, err := formula.Compile(r)
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
		func(memExpr string, env formula.NodeEnv, expected string) {
			r := makeResources(nil, nil, strPtr(memExpr), nil)
			c, err := formula.Compile(r)
			Expect(err).NotTo(HaveOccurred())
			result, err := c.Eval(env)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.MemoryRequest).To(Equal(expected))
		},
		Entry("uses NodeMemoryMi", "NodeMemoryMi / 8.0", formula.NodeEnv{NodeMemoryMi: 32768}, "4096Mi"),
		Entry("floor truncation", "NodeMemoryMi * 0.1", formula.NodeEnv{NodeMemoryMi: 10000}, "1000Mi"),
	)

	It("evaluates the canonical tiered formula", func() {
		exprStr := "NodeCPU < 4 ? 400.0 : (NodeCPU < 8 ? 500.0 : (NodeCPU <= 100 ? 1024.0 : 2048.0))"
		r := makeResources(strPtr(exprStr), nil, nil, nil)
		c, err := formula.Compile(r)
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

	It("returns empty strings when all fields are nil", func() {
		c, err := formula.Compile(&apisservice.FalcoResources{})
		Expect(err).NotTo(HaveOccurred())
		result, err := c.Eval(formula.NodeEnv{NodeCPU: 8, NodeMemoryMi: 32768})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.CPURequest).To(Equal(""))
		Expect(result.CPULimit).To(Equal(""))
		Expect(result.MemoryRequest).To(Equal(""))
		Expect(result.MemoryLimit).To(Equal(""))
	})

	It("evaluates independent programs for all four fields", func() {
		r := &apisservice.FalcoResources{
			Requests: &apisservice.ResourceValues{
				Cpu:    strPtr("NodeCPU * 100.0"),
				Memory: strPtr("NodeMemoryMi / 4.0"),
			},
			Limits: &apisservice.ResourceValues{
				Cpu:    strPtr("NodeCPU * 200.0"),
				Memory: strPtr("NodeMemoryMi / 2.0"),
			},
		}
		c, err := formula.Compile(r)
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
		r := makeResources(nil, nil, nil, strPtr("NodeMemoryGi * 64.0"))
		c, err := formula.Compile(r)
		Expect(err).NotTo(HaveOccurred())
		result, err := c.Eval(formula.NodeEnv{NodeMemoryGi: 32})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.MemoryLimit).To(Equal("2048Mi"))
	})

	It("evaluates the NodeMemoryGi tiered CPU formula (adaptive integration test formula)", func() {
		// Formula used by the integration tests to verify three machine tiers.
		cpuExpr := "NodeMemoryGi < 10 ? 200 : (NodeMemoryGi < 20 ? 400 : 800)"
		memExpr := "NodeMemoryGi * 8"
		r := &apisservice.FalcoResources{
			Requests: &apisservice.ResourceValues{
				Cpu:    strPtr(cpuExpr),
				Memory: strPtr(memExpr),
			},
		}
		c, err := formula.Compile(r)
		Expect(err).NotTo(HaveOccurred())

		cases := []struct {
			nodeMemGi float64
			wantCPU   string
			wantMem   string
		}{
			{8, "200m", "64Mi"},   // small tier  (~8 GiB)
			{16, "400m", "128Mi"}, // medium tier (~16 GiB)
			{32, "800m", "256Mi"}, // large tier  (~32 GiB)
		}
		for _, tc := range cases {
			result, err := c.Eval(formula.NodeEnv{NodeMemoryGi: tc.nodeMemGi})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.CPURequest).To(Equal(tc.wantCPU), "NodeMemoryGi=%.0f cpuRequest", tc.nodeMemGi)
			Expect(result.MemoryRequest).To(Equal(tc.wantMem), "NodeMemoryGi=%.0f memoryRequest", tc.nodeMemGi)
		}
	})

	It("handles mixed literal and expression fields in the same FalcoResources", func() {
		// Global default: literal. Per-pool override: expression for CPU only, memory inherited (nil → no override).
		r := &apisservice.FalcoResources{
			Requests: &apisservice.ResourceValues{
				Cpu:    strPtr("NodeMemoryGi * 25"),
				Memory: strPtr("128Mi"),
			},
		}
		c, err := formula.Compile(r)
		Expect(err).NotTo(HaveOccurred())
		result, err := c.Eval(formula.NodeEnv{NodeMemoryGi: 32})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.CPURequest).To(Equal("800m"))
		Expect(result.MemoryRequest).To(Equal("128Mi"))
	})

	It("returns plain quantity verbatim for literal fields", func() {
		r := &apisservice.FalcoResources{
			Requests: &apisservice.ResourceValues{
				Cpu:    strPtr("250m"),
				Memory: strPtr("1Gi"),
			},
			Limits: &apisservice.ResourceValues{
				Cpu:    strPtr("1"),
				Memory: strPtr("2Gi"),
			},
		}
		c, err := formula.Compile(r)
		Expect(err).NotTo(HaveOccurred())
		result, err := c.Eval(formula.NodeEnv{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.CPURequest).To(Equal("250m"))
		Expect(result.MemoryRequest).To(Equal("1Gi"))
		Expect(result.CPULimit).To(Equal("1"))
		Expect(result.MemoryLimit).To(Equal("2Gi"))
	})
})
