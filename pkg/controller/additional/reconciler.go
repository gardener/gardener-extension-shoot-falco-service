// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package additional

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/oci"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

const reconcileInterval = 1 * time.Minute

// Reconciler periodically deploys additional seed ManagedResources from OCI Helm charts
// and cleans up stale ones that are no longer in the config.
type Reconciler struct {
	client       client.Client
	namespace    string
	additional   *config.AdditionalConfig
	log          logr.Logger
	helmRegistry *oci.HelmRegistry
	renderer     chartrenderer.Interface
}

// NewReconciler creates a new Reconciler for additional seed resources.
func NewReconciler(c client.Client, restConfig *rest.Config, namespace string, additional *config.AdditionalConfig, log logr.Logger) (*Reconciler, error) {
	r := &Reconciler{
		client:     c,
		namespace:  namespace,
		additional: additional,
		log:        log,
	}

	if restConfig != nil {
		renderer, err := chartrenderer.NewForConfig(restConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create chart renderer: %w", err)
		}
		r.helmRegistry = oci.NewHelmRegistry(c)
		r.renderer = renderer
	}

	return r, nil
}

// Reconcile deploys configured resources and cleans up stale ones, then requeues.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	var errs []error

	if err := r.Deploy(ctx); err != nil {
		r.log.Error(err, "Failed to deploy additional seed resources")
		errs = append(errs, err)
	}
	if err := r.Cleanup(ctx); err != nil {
		r.log.Error(err, "Failed to clean up stale additional seed resources")
		errs = append(errs, err)
	}

	return reconcile.Result{RequeueAfter: reconcileInterval}, errors.Join(errs...)
}

// Deploy creates or updates ManagedResources for all configured Helm charts.
func (r *Reconciler) Deploy(ctx context.Context) error {
	if r.additional == nil || len(r.additional.SeedManagedResources) == 0 {
		return nil
	}

	if r.renderer == nil || r.helmRegistry == nil {
		return fmt.Errorf("chart renderer not initialized — restConfig was nil at construction time")
	}

	labels := map[string]string{constants.AdditionalManagedResourceLabel: "true"}
	var errs []error

	for _, res := range r.additional.SeedManagedResources {
		mrName := constants.AdditionalManagedResourcePrefix + res.Name

		if err := r.deployResource(ctx, res, mrName, labels); err != nil {
			r.log.Error(err, "Failed to deploy resource", "name", mrName)
			errs = append(errs, fmt.Errorf("resource %s: %w", res.Name, err))
			continue
		}
	}

	return errors.Join(errs...)
}

func (r *Reconciler) deployResource(ctx context.Context, res config.AdditionalSeedManagedResource, mrName string, labels map[string]string) error {
	archive, err := r.helmRegistry.Pull(ctx, &res.Helm.OCIRepository)
	if err != nil {
		return fmt.Errorf("failed to pull chart: %w", err)
	}

	var values map[string]interface{}
	if res.Helm.Values != nil && res.Helm.Values.Raw != nil {
		if err := json.Unmarshal(res.Helm.Values.Raw, &values); err != nil {
			return fmt.Errorf("failed to unmarshal helm values: %w", err)
		}
	}

	release, err := r.renderer.RenderArchive(archive, res.Name, r.namespace, values)
	if err != nil {
		return fmt.Errorf("failed to render chart: %w", err)
	}

	var (
		isNew          = !r.managedResourceExists(ctx, mrName)
		data           = map[string][]byte{"manifests.yaml": release.Manifest()}
		keepObjects    = false
		forceOverwrite = false
	)

	if err := managedresources.Create(ctx, r.client, r.namespace, mrName, labels, false, "seed", data, &keepObjects, nil, &forceOverwrite); err != nil {
		return fmt.Errorf("failed to create or update managed resource: %w", err)
	}

	if isNew {
		r.log.Info("Created additional seed managed resource", "name", mrName)
	}
	return nil
}

func (r *Reconciler) managedResourceExists(ctx context.Context, mrName string) bool {
	mr := &resourcesv1alpha1.ManagedResource{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: r.namespace, Name: mrName}, mr)
	return err == nil || !apierrors.IsNotFound(err)
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

	var errs []error
	for _, mr := range mrList.Items {
		if desiredNames.Has(mr.Name) {
			continue
		}
		r.log.Info("Deleting stale additional seed managed resource", "name", mr.Name)
		if err := managedresources.Delete(ctx, r.client, r.namespace, mr.Name, false); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete stale managed resource %s: %w", mr.Name, err))
		}
	}

	return errors.Join(errs...)
}
