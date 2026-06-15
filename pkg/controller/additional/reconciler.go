// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package additional

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/oci"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

const reconcileInterval = 1 * time.Minute

// Reconciler periodically deploys additional seed ManagedResources from OCI Helm charts
// and cleans up stale ones that are no longer in the config.
type Reconciler struct {
	client     client.Client
	restConfig *rest.Config
	namespace  string
	additional *config.AdditionalConfig
	log        logr.Logger
}

// NewReconciler creates a new Reconciler for additional seed resources.
func NewReconciler(c client.Client, restConfig *rest.Config, namespace string, additional *config.AdditionalConfig, log logr.Logger) *Reconciler {
	return &Reconciler{
		client:     c,
		restConfig: restConfig,
		namespace:  namespace,
		additional: additional,
		log:        log,
	}
}

func (r *Reconciler) Start(ctx context.Context) error {
	r.Reconcile(ctx)

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.Reconcile(ctx)
		}
	}
}

func (r *Reconciler) NeedLeaderElection() bool { return true }

// Reconcile deploys configured resources and cleans up stale ones.
func (r *Reconciler) Reconcile(ctx context.Context) {
	if err := r.Deploy(ctx); err != nil {
		r.log.Error(err, "Failed to deploy additional seed resources")
	}
	if err := r.Cleanup(ctx); err != nil {
		r.log.Error(err, "Failed to clean up stale additional seed resources")
	}
}

// Deploy creates or updates ManagedResources for all configured Helm charts.
func (r *Reconciler) Deploy(ctx context.Context) error {
	if r.additional == nil || len(r.additional.SeedManagedResources) == 0 {
		return nil
	}

	helmRegistry := oci.NewHelmRegistry(r.client)
	renderer, err := chartrenderer.NewForConfig(r.restConfig)
	if err != nil {
		return fmt.Errorf("could not create chart renderer: %w", err)
	}

	labels := map[string]string{constants.AdditionalManagedResourceLabel: "true"}

	for _, res := range r.additional.SeedManagedResources {
		mrName := constants.AdditionalManagedResourcePrefix + res.Name
		r.log.Info("Deploying additional seed managed resource", "name", mrName)

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

		release, err := renderer.RenderArchive(archive, res.Name, r.namespace, values)
		if err != nil {
			return fmt.Errorf("failed to render chart for %s: %w", res.Name, err)
		}

		data := map[string][]byte{"manifests.yaml": release.Manifest()}
		keepObjects := false
		forceOverwrite := false
		if err := managedresources.Create(ctx, r.client, r.namespace, mrName, labels, false, "seed", data, &keepObjects, nil, &forceOverwrite); err != nil {
			return fmt.Errorf("failed to create managed resource %s: %w", mrName, err)
		}
	}

	return nil
}

// Cleanup removes ManagedResources that are labeled as additional but no longer in the config.
func (r *Reconciler) Cleanup(ctx context.Context) error {
	desiredNames := sets.New[string]()
	if r.additional != nil {
		for _, res := range r.additional.SeedManagedResources {
			desiredNames.Insert(constants.AdditionalManagedResourcePrefix + res.Name)
		}
	}

	mrList := &resourcesv1alpha1.ManagedResourceList{}
	if err := r.client.List(ctx, mrList, client.InNamespace(r.namespace), client.MatchingLabels{constants.AdditionalManagedResourceLabel: "true"}); err != nil {
		return fmt.Errorf("failed to list additional managed resources: %w", err)
	}

	for _, mr := range mrList.Items {
		if desiredNames.Has(mr.Name) {
			continue
		}
		r.log.Info("Deleting stale additional seed managed resource", "name", mr.Name)
		if err := managedresources.Delete(ctx, r.client, r.namespace, mr.Name, false); err != nil {
			return fmt.Errorf("failed to delete stale managed resource %s: %w", mr.Name, err)
		}
	}

	return nil
}
