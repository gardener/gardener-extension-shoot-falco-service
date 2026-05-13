// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener/pkg/chartrenderer"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/oci"
)

// DeployAdditionalSeedResources pulls Helm charts from OCI and deploys them as ManagedResources.
// This runs once at startup after leader election is won. If it fails, the extension exits.
func DeployAdditionalSeedResources(ctx context.Context, log logr.Logger, c client.Client, restConfig *rest.Config, additional *config.AdditionalConfig) error {
	if additional == nil || len(additional.SeedManagedResources) == 0 {
		return nil
	}

	helmRegistry := oci.NewHelmRegistry(c)
	renderer, err := chartrenderer.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("could not create chart renderer: %w", err)
	}

	for _, res := range additional.SeedManagedResources {
		log.Info("Deploying additional seed managed resource", "name", res.Name, "namespace", res.Namespace)

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: res.Namespace}}
		if err := c.Create(ctx, ns); err != nil && !apierror.IsAlreadyExists(err) {
			return fmt.Errorf("failed to ensure namespace %s: %w", res.Namespace, err)
		}

		archive, err := helmRegistry.Pull(ctx, &res.Helm.OCIRepository)
		if err != nil {
			return fmt.Errorf("failed to pull chart for %s: %w", res.Name, err)
		}

		release, err := renderer.RenderArchive(archive, res.Name, res.Namespace, res.Helm.Values)
		if err != nil {
			return fmt.Errorf("failed to render chart for %s: %w", res.Name, err)
		}

		data := map[string][]byte{"manifests.yaml": release.Manifest()}
		keepObjects := false
		forceOverwrite := false
		if err := managedresources.Create(ctx, c, res.Namespace, res.Name, nil, false, "seed", data, &keepObjects, nil, &forceOverwrite); err != nil {
			return fmt.Errorf("failed to create managed resource %s/%s: %w", res.Namespace, res.Name, err)
		}

		log.Info("Successfully deployed additional seed managed resource", "name", res.Name, "namespace", res.Namespace)
	}

	return nil
}
