// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	_ "embed"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/charts"
	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/validation"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/falcovalues"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager, config config.Configuration) (extension.Actuator, error) {
	// tokenIssuer, err := secrets.NewTokenIssuer(config.Falco.TokenIssuerPrivateKey, config.Falco.TokenLifetime)
	tokenIssuer, err := secrets.NewTokenIssuer(config.Falco.TokenIssuerPrivateKey, 2)
	if err != nil {
		return nil, err
	}
	falcoVersions := falco.FalcoVersions()
	configBuilder := falcovalues.NewConfigBuilder(mgr.GetClient(), tokenIssuer, &config, &falcoVersions)
	return &actuator{
		client:        mgr.GetClient(),
		config:        mgr.GetConfig(),
		decoder:       serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		serviceConfig: config,
		configBuilder: configBuilder,
		tokenIssuer:   tokenIssuer,
	}, nil
}

type actuator struct {
	client        client.Client
	config        *rest.Config
	decoder       runtime.Decoder
	serviceConfig config.Configuration
	configBuilder *falcovalues.ConfigBuilder
	tokenIssuer   *secrets.TokenIssuer
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()
	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}
	if !controller.IsHibernated(cluster) {
		falcoServiceConfig, err := a.extractFalcoServiceConfig(ex)
		if err != nil {
			return err
		}
		if err := a.createShootResources(ctx, log, cluster, namespace, falcoServiceConfig); err != nil {
			return err
		}
	}
	return nil
}

func (a *actuator) createShootResources(ctx context.Context, log logr.Logger, cluster *controller.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) error {

	log.Info("Reconciling Falco resources for shoot " + cluster.Shoot.Name)
	renderer, err := util.NewChartRendererForShoot(cluster.Shoot.Spec.Kubernetes.Version)
	if err != nil {
		return fmt.Errorf("could not create chart renderer for rendering manged resource chart for shoot: %w", err)
	}
	values, err := a.configBuilder.BuildFalcoValues(ctx, log, cluster, namespace, falcoServiceConfig)
	if err != nil {
		return fmt.Errorf("could not generate falco configuration: %w", err)
	}
	release, err := renderer.RenderEmbeddedFS(charts.InternalChart, filepath.Join(charts.InternalChartsPath, constants.FalcoChartname), constants.FalcoChartname, metav1.NamespaceSystem, values)
	if err != nil {
		return fmt.Errorf("could not render chart for shoot: %w", err)
	}
	releaseManifest := release.Manifest()

	data := map[string][]byte{"config.yaml": releaseManifest}
	if err := managedresources.CreateForShoot(ctx, a.client, namespace, constants.ManagedResourceNameFalco, constants.ExtensionServiceName, false, data); err != nil {
		return fmt.Errorf("could not create managed resource for shoot falco deployment %w", err)
	}
	return nil
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()
	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return fmt.Errorf("unable to get cluster for Falco excetion delete operation: %w", err)
	}
	log.Info("Deleting falco resources for shoot " + cluster.Shoot.Name)
	err = a.deleteShootResources(ctx, log, namespace)
	if err != nil {
		return fmt.Errorf("unable to delete Falco from shoot %s: %w", cluster.Shoot.Name, err)
	}
	return nil
}

// ForceDelete the Extension resource.
func (a *actuator) ForceDelete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Delete(ctx, log, ex)
}

func (a *actuator) deleteShootResources(ctx context.Context, log logr.Logger, namespace string) error {
	log.Info(fmt.Sprintf("Deleting managed resource %s/%s", namespace, constants.ManagedResourceNameFalco))
	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNameFalco); err != nil {
		return err
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := managedresources.WaitUntilDeleted(timeoutCtx, a.client, namespace, constants.ManagedResourceNameFalco); err != nil {
		return err
	}
	log.Info(fmt.Sprintf("Successfully deleted managed resource  %s/%s", namespace, constants.ManagedResourceNameFalco))
	return nil
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, log, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	// Keep objects for shoot managed resources so that they are not deleted from the shoot during the migration
	if err := managedresources.SetKeepObjects(ctx, a.client, ex.GetNamespace(), constants.ExtensionServiceName, true); err != nil {
		return err
	}
	return a.Delete(ctx, log, ex)
}

func (a *actuator) extractFalcoServiceConfig(ex *extensionsv1alpha1.Extension) (*apisservice.FalcoServiceConfig, error) {
	falcoServiceConfig := &apisservice.FalcoServiceConfig{}
	if ex.Spec.ProviderConfig != nil {
		if _, _, err := a.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, falcoServiceConfig); err != nil {
			return nil, fmt.Errorf("could not decode Falco service config: %w", err)
		}
		if errs := validation.ValidateFalcoServiceConfig(falcoServiceConfig); len(errs) > 0 {
			return nil, errs.ToAggregate()
		}
	}
	return falcoServiceConfig, nil
}
