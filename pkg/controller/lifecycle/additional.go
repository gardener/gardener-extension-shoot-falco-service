// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gardener/gardener/pkg/chartrenderer"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/oci"
	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
)

// DeployAdditionalSeedResources pulls Helm charts from OCI and deploys them as ManagedResources.
// This runs once at startup after leader election is won. If it fails, the extension exits.
func DeployAdditionalSeedResources(ctx context.Context, log logr.Logger, c client.Client, restConfig *rest.Config, namespace string, additional *config.AdditionalConfig) error {
	if additional == nil || len(additional.SeedManagedResources) == 0 {
		return nil
	}

	helmRegistry := oci.NewHelmRegistry(c)
	renderer, err := chartrenderer.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("could not create chart renderer: %w", err)
	}

	for _, res := range additional.SeedManagedResources {
		log.Info("Deploying additional seed managed resource", "name", res.Name, "namespace", namespace)

		archive, err := helmRegistry.Pull(ctx, &res.Helm.OCIRepository)
		if err != nil {
			return fmt.Errorf("failed to pull chart for %s: %w", res.Name, err)
		}

		var values map[string]interface{}
		if res.Helm.Values != nil && res.Helm.Values.Raw != nil {
			if err := json.Unmarshal(res.Helm.Values.Raw, &values); err != nil {
				return fmt.Errorf("failed to unmarshal helm values for %s: %w", res.Name, err)
			}
		}

		release, err := renderer.RenderArchive(archive, res.Name, namespace, values)
		if err != nil {
			return fmt.Errorf("failed to render chart for %s: %w", res.Name, err)
		}

		data := map[string][]byte{"manifests.yaml": release.Manifest()}
		keepObjects := false
		forceOverwrite := false
		if err := managedresources.Create(ctx, c, namespace, res.Name, nil, false, "seed", data, &keepObjects, nil, &forceOverwrite); err != nil {
			return fmt.Errorf("failed to create managed resource %s/%s: %w", namespace, res.Name, err)
		}

		log.Info("Successfully deployed additional seed managed resource", "name", res.Name, "namespace", namespace)
	}

	return nil
}
