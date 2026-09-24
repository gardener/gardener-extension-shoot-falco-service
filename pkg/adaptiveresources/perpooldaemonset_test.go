// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package adaptiveresources_test

import (
	"fmt"
	"testing"

	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/version"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/adaptiveresources"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

func TestAdaptiveResources(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AdaptiveResources Suite")
}

var testRenderer chartrenderer.Interface

var _ = BeforeSuite(func() {
	testRenderer = chartrenderer.NewWithServerVersion(&version.Info{GitVersion: "v1.29.0"})
})

func strPtr(s string) *string { return &s }

func makeCloudProfile(types ...gardenerv1beta1.MachineType) *gardenerv1beta1.CloudProfile {
	return &gardenerv1beta1.CloudProfile{
		Spec: gardenerv1beta1.CloudProfileSpec{
			MachineTypes: types,
		},
	}
}

func machineType(name string, cpu, memGi int64) gardenerv1beta1.MachineType {
	return gardenerv1beta1.MachineType{
		Name:   name,
		CPU:    resource.MustParse(fmt.Sprintf("%d", cpu)),
		Memory: resource.MustParse(fmt.Sprintf("%dGi", memGi)),
	}
}

// minimalBaseValues mimics what BuildFalcoValues returns (keys that the chart consumes).
func minimalBaseValues() map[string]any {
	return map[string]any{
		"falco": map[string]any{
			"grpc": map[string]any{"enabled": false},
		},
	}
}

var _ = Describe("RenderPerPoolDaemonSets", func() {
	var (
		workers      []gardenerv1beta1.Worker
		cloudProfile *gardenerv1beta1.CloudProfile
		adaptive     *apisservice.AdaptiveResources
	)

	BeforeEach(func() {
		cloudProfile = makeCloudProfile(
			machineType("m5.large", 2, 8),
			machineType("m5.xlarge", 4, 16),
		)
		workers = []gardenerv1beta1.Worker{
			{Name: "pool-a", Machine: gardenerv1beta1.Machine{Type: "m5.large"}},
			{Name: "pool-b", Machine: gardenerv1beta1.Machine{Type: "m5.xlarge"}},
		}
		adaptive = &apisservice.AdaptiveResources{
			Formulas: apisservice.ResourceFormulas{
				CPURequest:    strPtr("NodeCPU < 4 ? 400.0 : 800.0"),
				MemoryRequest: strPtr("NodeMemoryGi * 32.0"),
			},
		}
	})

	It("returns an error when adaptiveResources is nil", func() {
		_, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, nil)
		Expect(err).To(HaveOccurred())
	})

	It("renders a DaemonSet for each worker pool plus a default", func() {
		manifest, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, adaptive)
		Expect(err).NotTo(HaveOccurred())
		manifestStr := string(manifest)
		Expect(manifestStr).To(ContainSubstring("falco-pool-a"))
		Expect(manifestStr).To(ContainSubstring("falco-pool-b"))
		Expect(manifestStr).To(ContainSubstring("falco-default"))
	})

	It("manifest contains expected CPU request values for both pools", func() {
		manifest, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, adaptive)
		Expect(err).NotTo(HaveOccurred())
		manifestStr := string(manifest)
		// pool-a: 2 CPUs → 400m; pool-b: 4 CPUs → 800m
		Expect(manifestStr).To(ContainSubstring("400m"))
		Expect(manifestStr).To(ContainSubstring("800m"))
	})

	It("pool-a nodeSelector targets pool-a", func() {
		manifest, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, adaptive)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(manifest)).To(ContainSubstring("pool-a"))
	})

	It("manifest contains DoesNotExist affinity for the default DaemonSet", func() {
		manifest, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, adaptive)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(manifest)).To(ContainSubstring("DoesNotExist"))
	})

	It("pool with unknown machine type skips resource injection without error", func() {
		workers := []gardenerv1beta1.Worker{
			{Name: "unknown-pool", Machine: gardenerv1beta1.Machine{Type: "unknown-type"}},
		}
		_, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, adaptive)
		Expect(err).NotTo(HaveOccurred())
	})

	It("works with empty worker list (only default DaemonSet)", func() {
		manifest, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), nil, cloudProfile, adaptive)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(manifest)).To(ContainSubstring("falco-default"))
	})
})
