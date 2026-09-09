// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package adaptiveresources

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"

	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/gardener-extension-shoot-falco-service/charts"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/adaptiveresources/formula"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

const (
	// workerPoolLabel is the well-known Gardener label that identifies worker pool membership.
	workerPoolLabel = "worker.gardener.cloud/pool"
)

// RenderPerPoolDaemonSets renders one Falco DaemonSet per worker pool plus a fallback DaemonSet for nodes
// without a pool label. The caller provides a base values map (already rendered for the standard single-DaemonSet
// deployment) which is cloned per pool; only the resource/nodeSelector/affinity keys are overridden.
//
// Returns a single combined YAML manifest suitable for embedding in a ManagedResource.
func RenderPerPoolDaemonSets(
	renderer chartrenderer.Interface,
	baseValues map[string]any,
	workers []gardenerv1beta1.Worker,
	cloudProfile *gardenerv1beta1.CloudProfile,
	adaptiveResources *apisservice.AdaptiveResources,
) ([]byte, error) {
	if adaptiveResources == nil {
		return nil, fmt.Errorf("adaptiveResources must not be nil")
	}

	compiled, err := formula.Compile(adaptiveResources.Formulas)
	if err != nil {
		return nil, fmt.Errorf("compiling formulas: %w", err)
	}

	// Build a name→MachineType index from the cloud profile.
	machineTypeIndex := buildMachineTypeIndex(cloudProfile)

	var manifests []string

	// One DaemonSet per worker pool.
	for _, worker := range workers {
		env, err := buildNodeEnv(worker.Machine.Type, machineTypeIndex)
		if err != nil {
			// If the machine type is unknown we skip resource injection and rely on chart defaults.
			env = formula.NodeEnv{}
		}

		resourceResult, err := compiled.Eval(env)
		if err != nil {
			return nil, fmt.Errorf("evaluating formulas for pool %q: %w", worker.Name, err)
		}

		poolValues := cloneValues(baseValues)
		poolValues["fullnameOverride"] = "falco-" + worker.Name
		poolValues["nodeSelector"] = map[string]string{
			workerPoolLabel: worker.Name,
		}
		delete(poolValues, "affinity")
		applyResourceResult(poolValues, resourceResult)

		manifest, err := renderChart(renderer, poolValues)
		if err != nil {
			return nil, fmt.Errorf("rendering chart for pool %q: %w", worker.Name, err)
		}
		manifests = append(manifests, manifest)
	}

	// Fallback DaemonSet for nodes that have no pool label (should not normally exist in Gardener shoots).
	defaultValues := cloneValues(baseValues)
	defaultValues["fullnameOverride"] = "falco-default"
	delete(defaultValues, "nodeSelector")
	defaultValues["affinity"] = buildDoesNotExistAffinity()

	defaultManifest, err := renderChart(renderer, defaultValues)
	if err != nil {
		return nil, fmt.Errorf("rendering default DaemonSet: %w", err)
	}
	manifests = append(manifests, defaultManifest)

	return []byte(strings.Join(manifests, "\n---\n")), nil
}

func renderChart(renderer chartrenderer.Interface, values map[string]any) (string, error) {
	chartPath := filepath.Join(charts.InternalChartsPath, constants.FalcoChartname)
	release, err := renderer.RenderEmbeddedFS(
		charts.InternalChart,
		chartPath,
		constants.FalcoChartname,
		metav1.NamespaceSystem,
		values,
	)
	if err != nil {
		return "", err
	}
	return string(release.Manifest()), nil
}

func buildMachineTypeIndex(cloudProfile *gardenerv1beta1.CloudProfile) map[string]gardenerv1beta1.MachineType {
	index := make(map[string]gardenerv1beta1.MachineType)
	if cloudProfile == nil {
		return index
	}
	for _, mt := range cloudProfile.Spec.MachineTypes {
		index[mt.Name] = mt
	}
	return index
}

func buildNodeEnv(machineTypeName string, index map[string]gardenerv1beta1.MachineType) (formula.NodeEnv, error) {
	mt, ok := index[machineTypeName]
	if !ok {
		return formula.NodeEnv{}, fmt.Errorf("machine type %q not found in cloud profile", machineTypeName)
	}

	cpuMillis := mt.CPU.MilliValue()
	memoryBytes := mt.Memory.Value()

	env := formula.NodeEnv{
		NodeCPU:      float64(cpuMillis) / 1000.0,
		NodeMemoryMi: math.Floor(float64(memoryBytes) / (1024 * 1024)),
		NodeMemoryGi: math.Floor(float64(memoryBytes) / (1024 * 1024 * 1024)),
	}

	if mt.Storage != nil {
		storageBytes := mt.Storage.StorageSize.Value()
		env.NodeEphemeralGi = math.Floor(float64(storageBytes) / (1024 * 1024 * 1024))
	}

	return env, nil
}

func applyResourceResult(values map[string]any, result formula.ResourceResult) {
	limitMap := map[string]string{}
	requestsMap := map[string]string{}

	if result.CPULimit != "" {
		limitMap["cpu"] = result.CPULimit
	}
	if result.MemoryLimit != "" {
		limitMap["memory"] = result.MemoryLimit
	}
	if result.CPURequest != "" {
		requestsMap["cpu"] = result.CPURequest
	}
	if result.MemoryRequest != "" {
		requestsMap["memory"] = result.MemoryRequest
	}

	if len(limitMap) != 0 || len(requestsMap) != 0 {
		resources := map[string]any{}
		if len(limitMap) != 0 {
			resources["limits"] = limitMap
		}
		if len(requestsMap) != 0 {
			resources["requests"] = requestsMap
		}
		values["resources"] = resources
	}
}

// buildDoesNotExistAffinity returns an affinity that selects nodes lacking the workerPoolLabel.
func buildDoesNotExistAffinity() map[string]any {
	return map[string]any{
		"nodeAffinity": map[string]any{
			"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{
				"nodeSelectorTerms": []any{
					map[string]any{
						"matchExpressions": []any{
							map[string]any{
								"key":      workerPoolLabel,
								"operator": "DoesNotExist",
							},
						},
					},
				},
			},
		},
	}
}

// cloneValues performs a shallow clone of the top-level map and deep-clones nested maps one level.
func cloneValues(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
