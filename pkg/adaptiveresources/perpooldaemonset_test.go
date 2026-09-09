// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package adaptiveresources_test

import (
	"fmt"
	"strings"
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

// combineManifests joins the shared manifest and all pool manifests into one string
// for substring assertions that don't care about which ManagedResource a resource ends up in.
func combineManifests(shared []byte, pools []adaptiveresources.PoolManifest) string {
	parts := []string{string(shared)}
	for _, p := range pools {
		parts = append(parts, string(p.Manifest))
	}
	return strings.Join(parts, "\n---\n")
}

var _ = Describe("RenderPerPoolDaemonSets", func() {
	var (
		workers      []gardenerv1beta1.Worker
		cloudProfile *gardenerv1beta1.CloudProfile
		falcoConfig  *apisservice.FalcoConfig
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
		falcoConfig = &apisservice.FalcoConfig{
			Resources: &apisservice.FalcoResources{
				Requests: &apisservice.ResourceValues{
					Cpu:    strPtr("NodeCPU < 4 ? 400.0 : 800.0"),
					Memory: strPtr("NodeMemoryGi * 32.0"),
				},
			},
		}
	})

	It("renders a DaemonSet for each worker pool plus a default", func() {
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		all := combineManifests(shared, pools)
		Expect(all).To(ContainSubstring("falco-pool-a"))
		Expect(all).To(ContainSubstring("falco-pool-b"))
		Expect(all).To(ContainSubstring("falco-default"))
	})

	It("returns one PoolManifest per worker pool", func() {
		_, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(pools).To(HaveLen(2))
		Expect(pools[0].PoolName).To(Equal("pool-a"))
		Expect(pools[1].PoolName).To(Equal("pool-b"))
	})

	It("pool manifests contain only DaemonSet and ConfigMap (no falcosidekick)", func() {
		_, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		for _, pm := range pools {
			Expect(string(pm.Manifest)).NotTo(ContainSubstring("falcosidekick"))
		}
	})

	It("shared manifest contains falco-default DaemonSet", func() {
		shared, _, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(shared)).To(ContainSubstring("falco-default"))
	})

	It("manifest contains expected CPU request values for both pools", func() {
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		all := combineManifests(shared, pools)
		// pool-a: 2 CPUs → 400m; pool-b: 4 CPUs → 800m
		Expect(all).To(ContainSubstring("400m"))
		Expect(all).To(ContainSubstring("800m"))
	})

	It("pool-a nodeSelector targets pool-a", func() {
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(combineManifests(shared, pools)).To(ContainSubstring("pool-a"))
	})

	It("manifest contains DoesNotExist affinity for the default DaemonSet", func() {
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(combineManifests(shared, pools)).To(ContainSubstring("DoesNotExist"))
	})

	It("pool with unknown machine type skips resource injection without error", func() {
		workers := []gardenerv1beta1.Worker{
			{Name: "unknown-pool", Machine: gardenerv1beta1.Machine{Type: "unknown-type"}},
		}
		_, _, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
	})

	It("works with empty worker list (only shared/default DaemonSet)", func() {
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), nil, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(shared)).To(ContainSubstring("falco-default"))
		Expect(pools).To(BeEmpty())
	})

	It("works with nil falcoConfig (no resource injection)", func() {
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, nil)
		Expect(err).NotTo(HaveOccurred())
		all := combineManifests(shared, pools)
		Expect(all).To(ContainSubstring("falco-pool-a"))
		Expect(all).To(ContainSubstring("falco-default"))
	})

	It("per-pool override takes precedence over default resources", func() {
		falcoConfigWithOverride := &apisservice.FalcoConfig{
			Resources: &apisservice.FalcoResources{
				Requests: &apisservice.ResourceValues{
					Cpu: strPtr("100m"),
				},
			},
			WorkerPoolResources: map[string]*apisservice.FalcoResources{
				"pool-a": {
					Requests: &apisservice.ResourceValues{
						Cpu: strPtr("999m"),
					},
				},
			},
		}
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfigWithOverride)
		Expect(err).NotTo(HaveOccurred())
		all := combineManifests(shared, pools)
		Expect(all).To(ContainSubstring("999m"))
		// pool-b uses default 100m
		Expect(all).To(ContainSubstring("100m"))
	})

	It("works with plain quantities (no expressions)", func() {
		falcoConfigPlain := &apisservice.FalcoConfig{
			Resources: &apisservice.FalcoResources{
				Requests: &apisservice.ResourceValues{
					Cpu:    strPtr("250m"),
					Memory: strPtr("512Mi"),
				},
				Limits: &apisservice.ResourceValues{
					Cpu:    strPtr("500m"),
					Memory: strPtr("1Gi"),
				},
			},
		}
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, falcoConfigPlain)
		Expect(err).NotTo(HaveOccurred())
		all := combineManifests(shared, pools)
		Expect(all).To(ContainSubstring("250m"))
		Expect(all).To(ContainSubstring("512Mi"))
	})
})
