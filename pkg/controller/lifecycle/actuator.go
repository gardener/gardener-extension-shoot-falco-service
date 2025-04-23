// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/charts"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/migration"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/values"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager, config config.Configuration) (extension.Actuator, error) {
	setConfigDefaults(config)

	var tokenIssuer *secrets.TokenIssuer = nil
	if config.Falco.CentralStorage != nil && config.Falco.CentralStorage.Enabled {
		var err error
		tokenIssuer, err = secrets.NewTokenIssuer(
			config.Falco.CentralStorage.TokenIssuerPrivateKey,
			config.Falco.CentralStorage.TokenLifetime,
		)
		if err != nil {
			return nil, err
		}
	}

	configBuilder := values.NewConfigBuilder(mgr.GetClient(), tokenIssuer, &config, profile.FalcoProfileManagerInstance)

	return &actuator{
		client:             mgr.GetClient(),
		config:             mgr.GetConfig(),
		decoder:            serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		serviceConfig:      config,
		configBuilder:      configBuilder,
		tokenIssuer:        tokenIssuer,
		falcoProfileManger: profile.FalcoProfileManagerInstance,
	}, nil
}

func setConfigDefaults(config config.Configuration) {
	if config.Falco.DefaultEventDestination == nil || *config.Falco.DefaultEventDestination == "" {
		config.Falco.DefaultEventDestination = &constants.DefaultEventDestination
	}

	if config.Falco.CertificateLifetime == nil {
		config.Falco.CertificateLifetime = &metav1.Duration{
			Duration: constants.DefaultCertificateLifetime,
		}
	}

	if config.Falco.CertificateRenewAfter == nil {
		config.Falco.CertificateRenewAfter = &metav1.Duration{
			Duration: constants.DefaultCertificateRenewAfter,
		}
	}

	if config.Falco.CentralStorage != nil {
		if config.Falco.CentralStorage.TokenLifetime == nil {
			config.Falco.CentralStorage.TokenLifetime =
				&metav1.Duration{
					Duration: constants.DefaultTokenLifetime,
				}
		}
	}
}

type actuator struct {
	client             client.Client
	config             *rest.Config
	decoder            runtime.Decoder
	serviceConfig      config.Configuration
	configBuilder      *values.ConfigBuilder
	tokenIssuer        *secrets.TokenIssuer
	falcoProfileManger *profile.FalcoProfileManager
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()
	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}
	if !controller.IsHibernated(cluster) {
		falcoServiceConfig, err := a.extractFalcoServiceConfig(log, ex)
		if err != nil {
			return err
		}
		if err := a.createShootResources(ctx, log, cluster, namespace, falcoServiceConfig); err != nil {
			return err
		}
	}
	if err := a.createSeedResources(ctx, log, namespace); err != nil {
		return err
	}
	return nil
}

func (a *actuator) createShootResources(ctx context.Context, log logr.Logger, cluster *controller.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) error {

	// migrate config to new format (migration)
	migration.MigrateIssue215(log, falcoServiceConfig)
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

func (a *actuator) createSeedResources(ctx context.Context, log logr.Logger, namespace string) error {
	log.Info("Creating Falco seed resources for shoot " + namespace)
	values := map[string]interface{}{}

	renderer, err := chartrenderer.NewForConfig(a.config)
	if err != nil {
		return fmt.Errorf("could not create chart renderer: %w", err)
	}

	log.Info("Component is being applied", "component", "shoot-falco-service", "namespace", namespace)

	return a.createManagedResource(ctx, log, namespace, constants.ManagedResourceNameFalcoSeed, "seed", renderer, constants.ManagedResourceNameFalcoChartSeed, namespace, values, nil)
}

func (a *actuator) createManagedResource(ctx context.Context, log logr.Logger, namespace, name, class string, renderer chartrenderer.Interface, chartName, chartNamespace string, chartValues map[string]interface{}, injectedLabels map[string]string) error {
	chartPath := filepath.Join(charts.InternalChartsPath, chartName)
	log.Info("Rendering chart", "chart", chartName, "chart path", chartPath)
	chart, err := renderer.RenderEmbeddedFS(charts.InternalChart, chartPath, chartName, chartNamespace, chartValues)
	if err != nil {
		return err
	}
	data := map[string][]byte{"config.yaml": chart.Manifest()}
	keepObjects := false
	forceOverwriteAnnotations := false
	return managedresources.Create(ctx, a.client, namespace, name, nil, false, class, data, &keepObjects, injectedLabels, &forceOverwriteAnnotations)
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()
	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return fmt.Errorf("unable to get cluster for Falco exextension delete operation: %w", err)
	}
	log.Info("Deleting falco resources for shoot " + cluster.Shoot.Name)
	err = a.deleteShootResources(ctx, log, namespace)
	if err != nil {
		return fmt.Errorf("error deleting Falco from shoot %s: %w", cluster.Shoot.Name, err)
	}
	err = a.deleteSeedResources(ctx, log, namespace)
	if err != nil {
		return fmt.Errorf("error deleting Falco seed resources for shoot %s: %w", cluster.Shoot.Name, err)
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

func (a *actuator) deleteSeedResources(ctx context.Context, log logr.Logger, namespace string) error {
	certs := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.FalcoCertificatesSecretName,
			Namespace: namespace,
		},
	}
	err1 := a.client.Delete(ctx, certs)

	// Check whether this is an error that we can ignore
	kerr, ok := err1.(*apierror.StatusError)
	if ok {
		if kerr.ErrStatus.Code == 404 {
			log.Info(fmt.Sprintf("Secret %s/%s not found, ignoring", namespace, constants.FalcoCertificatesSecretName))
			err1 = nil
		}
	}
	log.Info(fmt.Sprintf("Deleting managed resource %s/%s", namespace, constants.ManagedResourceNameFalco))

	if err := managedresources.Delete(ctx, a.client, namespace, constants.ManagedResourceNameFalcoSeed, false); err != nil {
		return err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	err2 := managedresources.WaitUntilDeleted(timeoutCtx, a.client, namespace, constants.ManagedResourceNameFalcoSeed)

	return errors.Join(err1, err2)
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

func (a *actuator) extractFalcoServiceConfig(log logr.Logger, ex *extensionsv1alpha1.Extension) (*apisservice.FalcoServiceConfig, error) {
	falcoServiceConfig := &apisservice.FalcoServiceConfig{}
	if ex.Spec.ProviderConfig != nil {
		log.Info("Extracting Falco service config", "providerConfig", string(ex.Spec.ProviderConfig.Raw[:]))
		if _, _, err := a.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, falcoServiceConfig); err != nil {
			return nil, fmt.Errorf("could not decode Falco service config: %w", err)
		}
	}
	return falcoServiceConfig, nil
}
