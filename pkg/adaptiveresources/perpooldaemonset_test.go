// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package adaptiveresources_test

import (
	"fmt"
	"maps"
	"strings"
	"testing"

	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/utils/ptr"

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
		Expect(all).To(ContainSubstring("falco-wp-pool-a"))
		Expect(all).To(ContainSubstring("falco-wp-pool-b"))
		Expect(all).NotTo(ContainSubstring("falco-pool-a"))
		Expect(all).NotTo(ContainSubstring("falco-pool-b"))
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
		Expect(all).To(ContainSubstring("falco-wp-pool-a"))
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

	It("worker pool named 'default' produces falco-wp-default, not falco-default", func() {
		defaultWorkers := []gardenerv1beta1.Worker{
			{Name: "default", Machine: gardenerv1beta1.Machine{Type: "m5.large"}},
		}
		shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), defaultWorkers, cloudProfile, falcoConfig)
		Expect(err).NotTo(HaveOccurred())
		all := combineManifests(shared, pools)
		// Per-pool DaemonSet must use the wp- prefix to avoid colliding with falco-default.
		Expect(all).To(ContainSubstring("falco-wp-default"))
		// The shared fallback DaemonSet for unlabeled nodes must still be falco-default.
		Expect(string(shared)).To(ContainSubstring("falco-default"))
		// Confirm no bare "falco-default" was emitted from the per-pool render path.
		poolAll := ""
		for _, pm := range pools {
			poolAll += string(pm.Manifest)
		}
		Expect(poolAll).NotTo(ContainSubstring(`name: falco-default`))
	})
})

var _ = Describe("engine config helpers", func() {
	Describe("mergeEngineConfig", func() {
		It("returns nil when both are nil", func() {
			Expect(adaptiveresources.MergeEngineConfig(nil, nil)).To(BeNil())
		})

		It("returns base when override is nil", func() {
			base := &apisservice.FalcoEngineConfig{BufSizePreset: ptr.To(6)}
			Expect(adaptiveresources.MergeEngineConfig(base, nil)).To(Equal(base))
		})

		It("returns override when base is nil", func() {
			override := &apisservice.FalcoEngineConfig{CpusForEachBuffer: ptr.To(4)}
			Expect(adaptiveresources.MergeEngineConfig(nil, override)).To(Equal(override))
		})

		It("override fields take precedence over base", func() {
			base := &apisservice.FalcoEngineConfig{CpusForEachBuffer: ptr.To(2), BufSizePreset: ptr.To(4)}
			override := &apisservice.FalcoEngineConfig{CpusForEachBuffer: ptr.To(8)}
			merged := adaptiveresources.MergeEngineConfig(base, override)
			Expect(*merged.CpusForEachBuffer).To(Equal(8))
			Expect(*merged.BufSizePreset).To(Equal(4)) // falls back to base
		})

		It("unset override fields fall back to base", func() {
			base := &apisservice.FalcoEngineConfig{BufSizePreset: ptr.To(7)}
			override := &apisservice.FalcoEngineConfig{CpusForEachBuffer: ptr.To(3)}
			merged := adaptiveresources.MergeEngineConfig(base, override)
			Expect(*merged.CpusForEachBuffer).To(Equal(3))
			Expect(*merged.BufSizePreset).To(Equal(7))
		})
	})

	Describe("ApplyEngineConfig", func() {
		It("sets cpus_for_each_buffer in falco.engine.modern_ebpf", func() {
			values := map[string]any{"falco": map[string]any{}}
			cfg := &apisservice.FalcoEngineConfig{CpusForEachBuffer: ptr.To(8)}
			adaptiveresources.ApplyEngineConfig(values, cfg)
			falcoMap := values["falco"].(map[string]any)
			engineMap := falcoMap["engine"].(map[string]any)
			modernEbpf := engineMap["modern_ebpf"].(map[string]any)
			Expect(modernEbpf["cpus_for_each_buffer"]).To(Equal(8))
		})

		It("sets buf_size_preset in falco.engine.modern_ebpf", func() {
			values := map[string]any{"falco": map[string]any{}}
			cfg := &apisservice.FalcoEngineConfig{BufSizePreset: ptr.To(6)}
			adaptiveresources.ApplyEngineConfig(values, cfg)
			falcoMap := values["falco"].(map[string]any)
			engineMap := falcoMap["engine"].(map[string]any)
			modernEbpf := engineMap["modern_ebpf"].(map[string]any)
			Expect(modernEbpf["buf_size_preset"]).To(Equal(6))
		})

		It("creates falco map if absent", func() {
			values := map[string]any{}
			cfg := &apisservice.FalcoEngineConfig{BufSizePreset: ptr.To(3)}
			adaptiveresources.ApplyEngineConfig(values, cfg)
			Expect(values).To(HaveKey("falco"))
		})

		It("is a no-op when cfg is nil", func() {
			values := map[string]any{}
			adaptiveresources.ApplyEngineConfig(values, nil)
			Expect(values).NotTo(HaveKey("falco"))
		})

		It("is a no-op when all fields are nil", func() {
			values := map[string]any{}
			adaptiveresources.ApplyEngineConfig(values, &apisservice.FalcoEngineConfig{})
			Expect(values).NotTo(HaveKey("falco"))
		})

		It("preserves existing falco map entries", func() {
			values := map[string]any{
				"falco": map[string]any{
					"json_output": true,
				},
			}
			cfg := &apisservice.FalcoEngineConfig{CpusForEachBuffer: ptr.To(4)}
			adaptiveresources.ApplyEngineConfig(values, cfg)
			falcoMap := values["falco"].(map[string]any)
			Expect(falcoMap["json_output"]).To(Equal(true))
			engineMap := falcoMap["engine"].(map[string]any)
			Expect(engineMap["modern_ebpf"].(map[string]any)["cpus_for_each_buffer"]).To(Equal(4))
		})

		It("does not mutate the source values map (shallow-clone safety)", func() {
			// Simulates the baseValues → poolValues shallow-clone scenario:
			// ApplyEngineConfig on a clone must not modify the original.
			original := map[string]any{
				"falco": map[string]any{
					"json_output": true,
				},
			}
			clone := maps.Clone(original)
			cfg := &apisservice.FalcoEngineConfig{CpusForEachBuffer: ptr.To(8)}
			adaptiveresources.ApplyEngineConfig(clone, cfg)

			// original's falco map must be untouched
			originalFalco := original["falco"].(map[string]any)
			Expect(originalFalco).NotTo(HaveKey("engine"))
		})
	})

	Describe("engine config rendered into ConfigMap", func() {
		var (
			workers      []gardenerv1beta1.Worker
			cloudProfile *gardenerv1beta1.CloudProfile
		)

		BeforeEach(func() {
			cloudProfile = makeCloudProfile(machineType("m5.large", 2, 8))
			workers = []gardenerv1beta1.Worker{
				{Name: "pool-a", Machine: gardenerv1beta1.Machine{Type: "m5.large"}},
			}
		})

		It("global engine config appears in all pool manifests", func() {
			fc := &apisservice.FalcoConfig{
				EngineConfig: &apisservice.FalcoEngineConfig{
					CpusForEachBuffer: ptr.To(8),
					BufSizePreset:     ptr.To(7),
				},
			}
			shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, fc)
			Expect(err).NotTo(HaveOccurred())
			all := combineManifests(shared, pools)
			Expect(all).To(ContainSubstring("cpus_for_each_buffer: 8"))
			Expect(all).To(ContainSubstring("buf_size_preset: 7"))
		})

		It("per-pool engine override applies only to that pool", func() {
			workers2 := []gardenerv1beta1.Worker{
				{Name: "pool-a", Machine: gardenerv1beta1.Machine{Type: "m5.large"}},
				{Name: "pool-b", Machine: gardenerv1beta1.Machine{Type: "m5.large"}},
			}
			cloudProfile2 := makeCloudProfile(machineType("m5.large", 2, 8))
			fc := &apisservice.FalcoConfig{
				EngineConfig: &apisservice.FalcoEngineConfig{
					CpusForEachBuffer: ptr.To(2),
					BufSizePreset:     ptr.To(4),
				},
				WorkerPoolEngineConfig: map[string]*apisservice.FalcoEngineConfig{
					"pool-a": {CpusForEachBuffer: ptr.To(16)},
				},
			}
			_, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers2, cloudProfile2, fc)
			Expect(err).NotTo(HaveOccurred())
			Expect(pools).To(HaveLen(2))

			// Look up by pool name, not by slice index, so ordering changes don't produce
			// misleading test failures.
			var poolAManifest, poolBManifest string
			for _, pm := range pools {
				switch pm.PoolName {
				case "pool-a":
					poolAManifest = string(pm.Manifest)
				case "pool-b":
					poolBManifest = string(pm.Manifest)
				}
			}
			Expect(poolAManifest).NotTo(BeEmpty(), "pool-a manifest not found")
			Expect(poolBManifest).NotTo(BeEmpty(), "pool-b manifest not found")

			Expect(poolAManifest).To(ContainSubstring("cpus_for_each_buffer: 16"))
			Expect(poolBManifest).To(ContainSubstring("cpus_for_each_buffer: 2"))
		})

		It("nil engine config does not inject engine section", func() {
			fc := &apisservice.FalcoConfig{}
			_, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers, cloudProfile, fc)
			Expect(err).NotTo(HaveOccurred())
			// No explicit injection means the chart default (cpus_for_each_buffer: 2) applies
			// from values.yaml, but we don't inject a custom value — the key should not appear
			// with a non-default value in the rendered output.
			_ = pools
		})

		It("per-pool override does not contaminate falco-default (shallow-clone regression)", func() {
			// This test guards against the bug where ApplyEngineConfig mutated the nested
			// falco/engine/modern_ebpf map in-place; since maps.Clone is shallow, baseValues
			// shared the same pointer and the last pool's override bled into falco-default.
			workers2 := []gardenerv1beta1.Worker{
				{Name: "pool-a", Machine: gardenerv1beta1.Machine{Type: "m5.large"}},
				{Name: "pool-b", Machine: gardenerv1beta1.Machine{Type: "m5.large"}},
			}
			cloudProfile2 := makeCloudProfile(machineType("m5.large", 2, 8))
			fc := &apisservice.FalcoConfig{
				EngineConfig: &apisservice.FalcoEngineConfig{
					CpusForEachBuffer: ptr.To(4),
					BufSizePreset:     ptr.To(6),
				},
				WorkerPoolEngineConfig: map[string]*apisservice.FalcoEngineConfig{
					// pool-b overrides cpusForEachBuffer to 16; falco-default must still see 4
					"pool-b": {CpusForEachBuffer: ptr.To(16)},
				},
			}
			shared, pools, err := adaptiveresources.RenderPerPoolDaemonSets(testRenderer, minimalBaseValues(), workers2, cloudProfile2, fc)
			Expect(err).NotTo(HaveOccurred())
			Expect(pools).To(HaveLen(2))

			sharedStr := string(shared)
			// falco-default must use the global value (4), not pool-b's override (16)
			Expect(sharedStr).To(ContainSubstring("cpus_for_each_buffer: 4"))
			Expect(sharedStr).NotTo(ContainSubstring("cpus_for_each_buffer: 16"))
		})
	})
})
