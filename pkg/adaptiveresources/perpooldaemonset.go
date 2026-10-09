// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package adaptiveresources

import (
	"fmt"
	"math"
	"path/filepath"

	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/chartrenderer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/gardener-extension-shoot-falco-service/charts"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/adaptiveresources/formula"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

// PoolManifest holds the rendered YAML manifest for a single worker pool's
// DaemonSet and falco.yaml ConfigMap.
type PoolManifest struct {
	// PoolName is the worker pool name (matches the worker.Name field).
	PoolName string
	// Manifest is the rendered YAML containing the DaemonSet and ConfigMap.
	Manifest []byte
}

// RenderPerPoolDaemonSets renders the Falco resources for a shoot with per-pool DaemonSets.
//
// It returns:
//   - sharedManifest: the falco-default DaemonSet, its ConfigMap, and all shared resources
//     (falcosidekick, RBAC, certs, rules). Intended for the main ManagedResource.
//   - poolManifests: one entry per worker pool, each containing only the pool-specific
//     DaemonSet and its falco.yaml ConfigMap. Intended for per-pool ManagedResources.
func RenderPerPoolDaemonSets(
	renderer chartrenderer.Interface,
	baseValues map[string]any,
	workers []gardenerv1beta1.Worker,
	cloudProfile *gardenerv1beta1.CloudProfile,
	falcoConfig *apisservice.FalcoConfig,
) (sharedManifest []byte, poolManifests []PoolManifest, err error) {
	// Build a name→MachineType index from the cloud profile.
	machineTypeIndex := buildMachineTypeIndex(cloudProfile)

	// One DaemonSet + ConfigMap per worker pool.
	for _, worker := range workers {
		var poolResources *apisservice.FalcoResources
		if falcoConfig != nil {
			if pr, ok := falcoConfig.WorkerPoolResources[worker.Name]; ok {
				poolResources = pr
			} else {
				poolResources = falcoConfig.Resources
			}
		}

		poolValues := cloneValues(baseValues)
		poolValues["fullnameOverride"] = "falco-" + worker.Name
		poolValues["nodeSelector"] = map[string]string{
			v1beta1constants.LabelWorkerPool: worker.Name,
		}
		// daemonSetOnly=true suppresses all shared resources (falcosidekick, RBAC, certs,
		// rules ConfigMaps) but leaves the DaemonSet and falco.yaml ConfigMap enabled.
		poolValues["daemonSetOnly"] = true
		delete(poolValues, "affinity")

		if poolResources != nil {
			compiled, compileErr := formula.Compile(poolResources)
			if compileErr != nil {
				return nil, nil, fmt.Errorf("compiling resources for pool %q: %w", worker.Name, compileErr)
			}
			env, envErr := buildNodeEnv(worker.Machine.Type, machineTypeIndex)
			if envErr != nil {
				// Unknown machine type: skip resource injection, rely on chart defaults.
				env = formula.NodeEnv{}
			}
			resourceResult, evalErr := compiled.Eval(env)
			if evalErr != nil {
				return nil, nil, fmt.Errorf("evaluating resources for pool %q: %w", worker.Name, evalErr)
			}
			applyResourceResult(poolValues, resourceResult)
		}

		manifest, renderErr := renderChart(renderer, poolValues)
		if renderErr != nil {
			return nil, nil, fmt.Errorf("rendering chart for pool %q: %w", worker.Name, renderErr)
		}
		poolManifests = append(poolManifests, PoolManifest{
			PoolName: worker.Name,
			Manifest: []byte(manifest),
		})
	}

	// Shared render: falco-default DaemonSet + ConfigMap + all shared resources.
	// daemonSetOnly is absent so every template renders.
	defaultValues := cloneValues(baseValues)
	defaultValues["fullnameOverride"] = "falco-default"
	delete(defaultValues, "nodeSelector")
	// Remove any resource values from baseValues — falco-default has no machine type
	// to evaluate against, so it uses chart defaults.
	delete(defaultValues, "resources")
	defaultValues["affinity"] = buildDoesNotExistAffinity()

	defaultManifest, renderErr := renderChart(renderer, defaultValues)
	if renderErr != nil {
		return nil, nil, fmt.Errorf("rendering shared/default DaemonSet: %w", renderErr)
	}
	sharedManifest = []byte(defaultManifest)
	return sharedManifest, poolManifests, nil
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
								"key":      v1beta1constants.LabelWorkerPool,
								"operator": "DoesNotExist",
							},
						},
					},
				},
			},
		},
	}
}

// cloneValues performs a shallow clone of the top-level map.
func cloneValues(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
