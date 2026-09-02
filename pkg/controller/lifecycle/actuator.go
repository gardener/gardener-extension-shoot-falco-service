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

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/api/extensions/v1alpha1/helper"
	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/extensions"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/charts"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/validator"
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

	var clusterIdentityTokenIssuer *secrets.TokenIssuer
	if config.Falco.ClusterIdentityToken != nil && config.Falco.ClusterIdentityToken.TokenIssuerPrivateKey != "" {
		var err error
		if clusterIdentityTokenIssuer, err = secrets.NewTokenIssuer(
			config.Falco.ClusterIdentityToken.TokenIssuerPrivateKey,
			config.Falco.ClusterIdentityToken.TokenLifetime,
		); err != nil {
			return nil, fmt.Errorf("failed to create cluster identity token issuer: %w", err)
		}
	}

	configBuilder := values.NewConfigBuilder(mgr.GetClient(), tokenIssuer, clusterIdentityTokenIssuer, &config, profile.FalcoProfileManagerInstance)

	gardenRESTConfig, err := kubernetes.RESTConfigFromKubeconfigFile(os.Getenv("GARDEN_KUBECONFIG"), kubernetes.AuthTokenFile)
	if err != nil {
		return nil, err
	}
	dynamicGardenCluster, err := dynamic.NewForConfig(gardenRESTConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating dynamic garden cluster object: %w", err)
	}

	dynamicRuntimeCluster, err := dynamic.NewForConfig(mgr.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("failed creating dynamic runtime cluster object: %w", err)
	}

	localClusterK8sVersion, err := getLocalClusterK8sVersion(mgr.GetConfig())
	if err != nil {
		return nil, err
	}

	// SEED_NAME is set for seed-class deployments only; garden-class deployments have no seed name.
	var seed *gardenerv1beta1.Seed
	if seedName := os.Getenv("SEED_NAME"); seedName != "" {
		seed, err = getSeed(context.TODO(), dynamicGardenCluster, seedName)
		if err != nil {
			return nil, fmt.Errorf("cannot get seed: %v", err)
		}
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
		runtimeClient:          dynamicRuntimeCluster,
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

	if config.Falco.ClusterIdentityToken != nil {
		if config.Falco.ClusterIdentityToken.TokenLifetime == nil {
			config.Falco.ClusterIdentityToken.TokenLifetime =
				&metav1.Duration{
					Duration: constants.DefaultClusterIdentityTokenLifetime,
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
	runtimeClient          *dynamic.DynamicClient
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
	var currentSeed *gardenerv1beta1.Seed
	var currentGarden *operatorv1alpha1.Garden
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
			Shoot:                   shootCluster.Shoot,
			Seed:                    shootCluster.Seed,
		}
		if shootCluster.Seed.Spec.Ingress != nil {
			reconcileCtx.SeedIngressDomain = shootCluster.Seed.Spec.Ingress.Domain
		}
	case extensionsv1alpha1.ExtensionClassSeed:
		// Re-fetch the seed on every reconcile so spec.resources changes are picked up without restart.
		var seedErr error
		currentSeed, seedErr = getSeed(ctx, a.gardenClient, a.seed.Name)
		if seedErr != nil {
			return fmt.Errorf("failed to re-fetch seed: %w", seedErr)
		}
		reconcileCtx = &utils.ReconcileContext{
			TargetClusterK8sVersion: a.localClusterK8sVersion,
			ResourceSection:         currentSeed.Spec.Resources,
			ClusterIdentity:         currentSeed.Status.ClusterIdentity,
			ClusterName:             currentSeed.Name,
		}
	case extensionsv1alpha1.ExtensionClassGarden:
		// Re-fetch the Garden object on every reconcile so spec changes are picked up without restart.
		var gardenErr error
		currentGarden, gardenErr = utils.GetGarden(ctx, a.runtimeClient)
		if gardenErr != nil {
			return fmt.Errorf("failed to fetch garden object: %w", gardenErr)
		}
		clusterIdentity := currentGarden.Spec.VirtualCluster.Gardener.ClusterIdentity
		reconcileCtx = &utils.ReconcileContext{
			TargetClusterK8sVersion: a.localClusterK8sVersion,
			ResourceSection:         currentGarden.Spec.Resources,
			ClusterIdentity:         &clusterIdentity,
			ClusterName:             currentGarden.Name,
		}
		// Gardener does not project ref- secrets for Garden resources; do it ourselves.
		if err := reconcileGardenRefSecrets(ctx, a.client, namespace, currentGarden.Spec.Resources); err != nil {
			return fmt.Errorf("failed to reconcile garden ref secrets: %w", err)
		}
	}
	falcoServiceConfig, err := a.extractFalcoServiceConfig(ex)
	if err != nil {
		return err
	}

	// Validate the FalcoServiceConfig — no admission webhook runs for seed/garden-class extensions.
	switch extClass {
	case extensionsv1alpha1.ExtensionClassGarden:
		if err := validator.ValidateForGarden(ctx, falcoServiceConfig, currentGarden, a.serviceConfig.Falco.GlobalDefaultDestinations); err != nil {
			return fmt.Errorf("invalid FalcoServiceConfig for garden: %w", err)
		}
	case extensionsv1alpha1.ExtensionClassSeed:
		if err := validator.ValidateForSeed(ctx, falcoServiceConfig, currentSeed, a.serviceConfig.Falco.GlobalDefaultDestinations); err != nil {
			return fmt.Errorf("invalid FalcoServiceConfig for seed: %w", err)
		}
	}

	reconcileCtx.FalcoServiceConfig = falcoServiceConfig
	reconcileCtx.Namespace = namespace
	reconcileCtx.IsSeedDeployment = isSeedDeployment(ex)
	reconcileCtx.IsShootDeployment = isShootDeployment(ex)
	reconcileCtx.IsGardenDeployment = isGardenDeployment(ex)
	if reconcileCtx.IsShootDeployment {
		reconcileCtx.FalcoNamespace = metav1.NamespaceSystem
	} else {
		reconcileCtx.FalcoNamespace = constants.NamespaceFalco
	}

	if err := a.createFalcoResources(ctx, log, reconcileCtx); err != nil {
		return err
	}

	if err := a.createControlPlaneResources(ctx, log, reconcileCtx); err != nil {
		return err
	}
	return nil
}

func (a *actuator) createFalcoResources(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext) error {

	log.Info("creating Falco resources for " + reconcileCtx.Namespace)
	renderer, err := util.NewChartRendererForShoot(reconcileCtx.TargetClusterK8sVersion)
	if err != nil {
		return fmt.Errorf("could not create chart renderer for rendering manged resource chart for shoot: %w", err)
	}
	values, err := a.configBuilder.BuildFalcoValues(ctx, log, reconcileCtx)
	if err != nil {
		return fmt.Errorf("could not generate falco configuration: %w", err)
	}

	// Falco runs in kube-system on shoot clusters; on seed/garden it runs in the falco namespace.
	release, err := renderer.RenderEmbeddedFS(charts.InternalChart, filepath.Join(charts.InternalChartsPath, constants.FalcoChartname), constants.FalcoChartname, reconcileCtx.FalcoNamespace, values)
	if err != nil {
		return fmt.Errorf("could not render Falco chart: %w", err)
	}
	releaseManifest := release.Manifest()

	data := map[string][]byte{"config.yaml": releaseManifest}
	switch {
	case reconcileCtx.IsShootDeployment:
		if err := managedresources.CreateForShoot(ctx, a.client, reconcileCtx.Namespace, constants.ManagedResourceNameFalco, constants.ExtensionServiceName, false, data); err != nil {
			return fmt.Errorf("could not create managed resource for Falco shoot deployment: %w", err)
		}
	case reconcileCtx.IsSeedDeployment:
		if err := managedresources.CreateForSeed(ctx, a.client, reconcileCtx.Namespace, constants.ManagedResourceNameFalco, false, data); err != nil {
			return fmt.Errorf("could not create managed resource for Falco seed deployment: %w", err)
		}
	case reconcileCtx.IsGardenDeployment:
		// No CreateForGarden exists; CreateForSeed is correct here — both seed and garden extensions
		// run on the runtime cluster and the resource manager applies manifests locally.
		if err := managedresources.CreateForSeed(ctx, a.client, reconcileCtx.Namespace, constants.ManagedResourceNameFalco, false, data); err != nil {
			return fmt.Errorf("could not create managed resource for Falco garden deployment: %w", err)
		}
	}
	return nil
}

func (a *actuator) createControlPlaneResources(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext) error {
	// TODO: seed and garden deployments will need their own control-plane resources (e.g. monitoring);
	// for now only the shoot-specific chart (token-requestor, ScrapeConfig) is deployed.
	if !reconcileCtx.IsShootDeployment {
		return nil
	}
	log.Info("Creating Falco control plane resources for " + reconcileCtx.Namespace)
	values := map[string]interface{}{}

	renderer, err := chartrenderer.NewForConfig(a.config)
	if err != nil {
		return fmt.Errorf("could not create chart renderer: %w", err)
	}

	log.Info("Component is being applied", "component", "shoot-falco-service", "namespace", reconcileCtx.Namespace)

	return a.createManagedResource(ctx, log, reconcileCtx.Namespace, constants.ManagedResourceNameFalcoSeed, "seed", renderer, constants.ManagedResourceNameFalcoChartSeed, reconcileCtx.Namespace, values, nil)
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
		log.Info("Deleting falco resources for shoot " + cluster.Shoot.Name)
	}
	err = a.deleteFalcoResources(ctx, log, namespace, ex)
	if err != nil {
		return fmt.Errorf("error deleting Falco resources for %s: %w", namespace, err)
	}
	err = a.deleteControlPlaneResources(ctx, log, namespace)
	if err != nil {
		return fmt.Errorf("error deleting Falco control plane resources for %s: %w", namespace, err)
	}
	return nil
}

// ForceDelete the Extension resource.
func (a *actuator) ForceDelete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Delete(ctx, log, ex)
}

func (a *actuator) deleteFalcoResources(ctx context.Context, log logr.Logger, namespace string, ex *extensionsv1alpha1.Extension) error {
	log.Info(fmt.Sprintf("Deleting managed resource %s/%s", namespace, constants.ManagedResourceNameFalco))
	switch {
	case isShootDeployment(ex):
		if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNameFalco); err != nil {
			return err
		}
	case isSeedDeployment(ex):
		if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNameFalco); err != nil {
			return err
		}
	case isGardenDeployment(ex):
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

	// For seed and garden deployments Falco runs in the "falco" namespace, which Gardener's
	// resource manager creates implicitly but never removes. Delete it explicitly now that all
	// workloads are gone.
	if isSeedDeployment(ex) || isGardenDeployment(ex) {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: constants.NamespaceFalco}}
		if err := client.IgnoreNotFound(a.client.Delete(ctx, ns)); err != nil {
			return fmt.Errorf("failed to delete falco namespace: %w", err)
		}
		log.Info("Deleted falco namespace", "namespace", constants.NamespaceFalco)
	}
	return nil
}

func (a *actuator) deleteControlPlaneResources(ctx context.Context, log logr.Logger, namespace string) error {
	certs := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.FalcoCertificatesSecretName,
			Namespace: namespace,
		},
	}
	err1 := client.IgnoreNotFound(a.client.Delete(ctx, certs))
	if err1 != nil {
		log.Error(err1, fmt.Sprintf("Failed to delete secret %s/%s", namespace, constants.FalcoCertificatesSecretName))
	}

	log.Info(fmt.Sprintf("Deleting managed resource %s/%s", namespace, constants.ManagedResourceNameFalcoSeed))

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
	if err := managedresources.SetKeepObjects(ctx, a.client, ex.GetNamespace(), constants.ManagedResourceNameFalco, true); err != nil {
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

func (a *actuator) getClusterResourcesForShoot(cluster *extensions.Cluster) []gardenerv1beta1.NamedResourceReference {
	return cluster.Shoot.Spec.Resources
}

func getSeed(ctx context.Context, client *dynamic.DynamicClient, seedName string) (*gardenerv1beta1.Seed, error) {
	return utils.GetSeed(ctx, client, seedName)
}

// reconcileGardenRefSecrets copies secrets/configmaps from Garden spec.resources into namespace
// as ref-<name>, mirroring what gardenlet does for Seed resources.
func reconcileGardenRefSecrets(ctx context.Context, c client.Client, namespace string, resources []gardenerv1beta1.NamedResourceReference) error {
	for _, ref := range resources {
		if ref.ResourceRef.APIVersion != "v1" {
			continue
		}
		switch ref.ResourceRef.Kind {
		case "Secret":
			src := &corev1.Secret{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.ResourceRef.Name}, src); err != nil {
				return fmt.Errorf("failed to read referenced secret %s: %w", ref.ResourceRef.Name, err)
			}
			dst := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      "ref-" + ref.ResourceRef.Name,
				},
				Data: src.Data,
			}
			if err := client.IgnoreAlreadyExists(c.Create(ctx, dst)); err != nil {
				existing := &corev1.Secret{}
				if getErr := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: dst.Name}, existing); getErr != nil {
					return fmt.Errorf("failed to get existing ref secret %s: %w", dst.Name, getErr)
				}
				existing.Data = src.Data
				if err := c.Update(ctx, existing); err != nil {
					return fmt.Errorf("failed to update ref secret %s: %w", dst.Name, err)
				}
			}
		case "ConfigMap":
			src := &corev1.ConfigMap{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.ResourceRef.Name}, src); err != nil {
				return fmt.Errorf("failed to read referenced configmap %s: %w", ref.ResourceRef.Name, err)
			}
			dst := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      "ref-" + ref.ResourceRef.Name,
				},
				Data:       src.Data,
				BinaryData: src.BinaryData,
			}
			if err := client.IgnoreAlreadyExists(c.Create(ctx, dst)); err != nil {
				existing := &corev1.ConfigMap{}
				if getErr := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: dst.Name}, existing); getErr != nil {
					return fmt.Errorf("failed to get existing ref configmap %s: %w", dst.Name, getErr)
				}
				existing.Data = src.Data
				existing.BinaryData = src.BinaryData
				if err := c.Update(ctx, existing); err != nil {
					return fmt.Errorf("failed to update ref configmap %s: %w", dst.Name, err)
				}
			}
		}
	}
	return nil
}
