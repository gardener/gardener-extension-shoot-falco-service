// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/extensions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"github.com/gardener/gardener/extensions/pkg/util"
	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1/helper"

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
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/values"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager, config config.Configuration) (extension.Actuator, error) {
	setConfigDefaults(config)
	var tokenIssuer *secrets.TokenIssuer = nil
	if config.Falco.CentralStorage != nil && config.Falco.CentralStorage.Enabled {
		if config.Falco.CentralStorage.TokenIssuerPrivateKey == "" {
			return nil, fmt.Errorf("token issuer private key is required")
		}

		if config.Falco.CentralStorage.URL == "" {
			return nil, fmt.Errorf("central storage URL is required")
		}

		var err error
		if tokenIssuer, err = secrets.NewTokenIssuer(
			config.Falco.CentralStorage.TokenIssuerPrivateKey,
			config.Falco.CentralStorage.TokenLifetime,
		); err != nil {
			return nil, err
		}
	}
	configBuilder := values.NewConfigBuilder(mgr.GetClient(), tokenIssuer, &config, profile.FalcoProfileManagerInstance)

	gardenRESTConfig, err := kubernetes.RESTConfigFromKubeconfigFile(os.Getenv("GARDEN_KUBECONFIG"), kubernetes.AuthTokenFile)
	if err != nil {
		return nil, err
	}
	dynamicGardenCluster, err := dynamic.NewForConfig(gardenRESTConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating dynamic garden cluster object: %w", err)
	}

	localClusterK8sVersion, err := getLocalClusterK8sVersion(mgr.GetConfig())
	if err != nil {
		return nil, err
	}
	seed, err := getSeed(context.TODO(), dynamicGardenCluster, os.Getenv("SEED_NAME"))
	if err != nil {
		return nil, fmt.Errorf("cannot get seed: %v", err)
	}

	return &actuator{
		client:                 mgr.GetClient(),
		config:                 mgr.GetConfig(),
		decoder:                serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		serviceConfig:          config,
		configBuilder:          configBuilder,
		tokenIssuer:            tokenIssuer,
		falcoProfileManger:     profile.FalcoProfileManagerInstance,
		gardenClient:           dynamicGardenCluster,
		localClusterK8sVersion: localClusterK8sVersion,
		seed:                   seed,
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
	client                 client.Client
	config                 *rest.Config
	decoder                runtime.Decoder
	serviceConfig          config.Configuration
	configBuilder          *values.ConfigBuilder
	tokenIssuer            *secrets.TokenIssuer
	falcoProfileManger     *profile.FalcoProfileManager
	gardenClient           *dynamic.DynamicClient
	localClusterK8sVersion string
	seed                   *gardenerv1beta1.Seed
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {

	var (
		reconcileCtx *utils.ReconcileContext
		err          error
		namespace    = ex.GetNamespace()
	)

	extClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.Class)
	switch extClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		shootCluster, err := controller.GetCluster(ctx, a.client, namespace)
		if err != nil {
			return fmt.Errorf("failed to get cluster config for shoot: %w", err)
		}
		if controller.IsHibernated(shootCluster) {
			return nil
		}
		reconcileCtx = &utils.ReconcileContext{
			TargetClusterK8sVersion: shootCluster.Shoot.Spec.Kubernetes.Version,
			ResourceSection:         a.getClusterResourcesForShoot(shootCluster),
			ClusterIdentity:         shootCluster.Shoot.Status.ClusterIdentity,
			ShootTechnicalId:        shootCluster.Shoot.Status.TechnicalID,
			ClusterName:             shootCluster.Shoot.Name,
		}
		if shootCluster.Seed.Spec.Ingress != nil {
			reconcileCtx.SeedIngressDomain = shootCluster.Seed.Spec.Ingress.Domain
		}
	case extensionsv1alpha1.ExtensionClassSeed:
		// Falco will be deployed on the local cluster, we have the version
		reconcileCtx = &utils.ReconcileContext{
			TargetClusterK8sVersion: a.localClusterK8sVersion,
			ResourceSection:         a.getClusterResourcesForSeed(),
			ClusterIdentity:         a.seed.Status.ClusterIdentity,
			ClusterName:             a.seed.Name,
		}
	case extensionsv1alpha1.ExtensionClassGarden:
		// TODO
		reconcileCtx = &utils.ReconcileContext{
			ClusterName: "garden",
		}
	}
	falcoServiceConfig, err := a.extractFalcoServiceConfig(log, ex)
	if err != nil {
		return err
	}
	reconcileCtx.FalcoServiceConfig = falcoServiceConfig
	reconcileCtx.Namespace = namespace
	reconcileCtx.IsSeedDeployment = isSeedDeployment(ex)
	reconcileCtx.IsShootDeployment = isShootDeployment(ex)
	reconcileCtx.IsGardenDeployment = isGardenDeployment(ex)

	if err := a.createShootResources(ctx, log, reconcileCtx); err != nil {
		return err
	}

	if err := a.createSeedResources(ctx, log, namespace); err != nil {
		return err
	}
	return nil
}

func (a *actuator) createShootResources(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext) error {

	log.Info("Creating Falco shoot resources for shoot " + reconcileCtx.Namespace)
	renderer, err := util.NewChartRendererForShoot(reconcileCtx.TargetClusterK8sVersion)
	if err != nil {
		return fmt.Errorf("could not create chart renderer for rendering manged resource chart for shoot: %w", err)
	}
	values, err := a.configBuilder.BuildFalcoValues(ctx, log, reconcileCtx)
	if err != nil {
		return fmt.Errorf("could not generate falco configuration: %w", err)
	}
	release, err := renderer.RenderEmbeddedFS(charts.InternalChart, filepath.Join(charts.InternalChartsPath, constants.FalcoChartname), constants.FalcoChartname, metav1.NamespaceSystem, values)
	if err != nil {
		return fmt.Errorf("could not render chart for shoot: %w", err)
	}
	releaseManifest := release.Manifest()

	data := map[string][]byte{"config.yaml": releaseManifest}
	if reconcileCtx.IsShootDeployment {
		if err := managedresources.CreateForShoot(ctx, a.client, reconcileCtx.Namespace, constants.ManagedResourceNameFalco, constants.ExtensionServiceName, false, data); err != nil {
			return fmt.Errorf("could not create managed resource for shoot falco deployment %w", err)
		}
	} else if reconcileCtx.IsSeedDeployment {
		// shoot resources must be provisioned in the same cluster (garden, seed)
		if err := managedresources.CreateForSeed(ctx, a.client, reconcileCtx.Namespace, constants.ManagedResourceNameFalco, false, data); err != nil {
			//		if err := managedresources.CreateForShoot(ctx, a.client, reconcileCtx.Namespace, constants.ManagedResourceNameFalco, constants.ExtensionServiceName, false, data); err != nil {
			return fmt.Errorf("could not create managed resource for shoot falco deployment %w", err)
		}
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
	var (
		cluster *controller.Cluster
		err     error
	)

	if isShootDeployment(ex) {
		cluster, err = controller.GetCluster(ctx, a.client, namespace)
		if err != nil {
			return fmt.Errorf("failed to get cluster config for shoot for Falco exension delete operation: %w", err)
		}
		if controller.IsHibernated(cluster) {
			return nil
		}
		log.Info("Deleting falco resources for shoot " + cluster.Shoot.Name)
	}
	err = a.deleteShootResources(ctx, log, namespace, ex)
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

func (a *actuator) deleteShootResources(ctx context.Context, log logr.Logger, namespace string, ex *extensionsv1alpha1.Extension) error {
	log.Info(fmt.Sprintf("Deleting managed resource %s/%s", namespace, constants.ManagedResourceNameFalco))
	if isShootDeployment(ex) {
		if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNameFalco); err != nil {
			return err
		}
	} else if isSeedDeployment(ex) {
		if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNameFalco); err != nil {
			return err
		}
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

func isShootDeployment(ex *extensionsv1alpha1.Extension) bool {
	return extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.Class) == extensionsv1alpha1.ExtensionClassShoot
}

func isSeedDeployment(ex *extensionsv1alpha1.Extension) bool {
	return extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.Class) == extensionsv1alpha1.ExtensionClassSeed
}

func isGardenDeployment(ex *extensionsv1alpha1.Extension) bool {
	return extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.Class) == extensionsv1alpha1.ExtensionClassGarden
}

func getLocalClusterK8sVersion(cfg *rest.Config) (string, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return "", fmt.Errorf("cannot get discovery client for local cluster %v", err)
	}
	v, err := discoveryClient.ServerVersion()
	if err != nil {
		return "", fmt.Errorf("cannot get kubernertes version of local cluster %v", err)
	}
	return v.Major + "." + v.Minor, nil
}

// []gardenerv1beta1.NamedResourceReference

func getSecret(ctx context.Context, c client.Client, namespace string, name string) (*corev1.Secret, error) {

	secret := corev1.Secret{}
	err := c.Get(ctx,
		client.ObjectKey{
			Namespace: namespace,
			Name:      name,
		},
		&secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secretRef %s: %v", name, err)
	}
	return &secret, err
}

func (a *actuator) getClusterResourcesForShoot(cluster *extensions.Cluster) []gardenerv1beta1.NamedResourceReference {
	return cluster.Shoot.Spec.Resources
}

func (a *actuator) getClusterResourcesForSeed() []gardenerv1beta1.NamedResourceReference {
	return a.seed.Spec.Resources
}

/*
	func (a *actuator) getClusterResourcesForSeed(ctx context.Context, seedName string) ([]gardenerv1beta1.NamedResourceReference, error) {
		seed := &gardenerv1beta1.Seed{}
		err := a.gardenClient.Get(ctx,
			client.ObjectKey{
				Name: seedName},
			seed)

		return seed.Spec.Resources, err
	}
*/
func getSeed(ctx context.Context, client *dynamic.DynamicClient, seedName string) (*gardenerv1beta1.Seed, error) {
	seedResource, err := client.Resource(gardenerv1beta1.SchemeGroupVersion.WithResource("seeds")).Get(ctx, seedName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var seed gardenerv1beta1.Seed
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(seedResource.Object, &seed)
	if err != nil {
		return nil, err
	}
	return &seed, nil
}

func (a *actuator) getClusterResourcesForGarden() {
	// TODO
}
