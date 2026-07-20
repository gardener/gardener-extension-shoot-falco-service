// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"os"

	"github.com/gardener/gardener/extensions/pkg/controller"
	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	"github.com/gardener/gardener/extensions/pkg/controller/heartbeat"
	heartbeatcmd "github.com/gardener/gardener/extensions/pkg/controller/heartbeat/cmd"
	"github.com/gardener/gardener/extensions/pkg/util"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	componentbaseconfig "k8s.io/component-base/config/v1alpha1"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	serviceinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/install"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/cmd"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/additional"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/healthcheck"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/lifecycle"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils"
)

const Name = "gardener-extension-shoot-falco-service"

// NewControllerManagerCommand creates a new command for running the Falco extension service controller
func NewControllerManagerCommand(ctx context.Context) *cobra.Command {
	var (
		restOpts = &controllercmd.RESTOptions{}
		mgrOpts  = &controllercmd.ManagerOptions{
			LeaderElection:          true,
			LeaderElectionID:        controllercmd.LeaderElectionNameID(constants.GardenerExtensionServiceName),
			LeaderElectionNamespace: os.Getenv("LEADER_ELECTION_NAMESPACE"),
		}
		// Falco options
		falcoCtrlOpts = &cmd.FalcoOptions{}

		reconcileOpts = &controllercmd.ReconcilerOptions{
			IgnoreOperationAnnotation: true,
		}

		heartbeatCtrlOpts = &heartbeatcmd.Options{
			ExtensionName:        constants.GardenerExtensionServiceName,
			RenewIntervalSeconds: 30,
			Namespace:            os.Getenv("LEADER_ELECTION_NAMESPACE"),
		}

		aggOption = controllercmd.NewOptionAggregator(
			restOpts,
			mgrOpts,
			falcoCtrlOpts,
			controllercmd.PrefixOption("heartbeat-", heartbeatCtrlOpts),
			reconcileOpts,
		)
	)

	cmd := &cobra.Command{
		Use: constants.GardenerExtensionServiceName,
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()
			if err := aggOption.Complete(); err != nil {
				return fmt.Errorf("error completing options: %w", err)
			}

			if err := heartbeatCtrlOpts.Validate(); err != nil {
				return err
			}

			log, err := logger.NewZapLogger(logger.InfoLevel, logger.FormatJSON)
			if err != nil {
				return fmt.Errorf("error instantiating zap logger: %w", err)
			}
			logf.SetLogger(log)

			log.Info("Starting "+Name, "version", version.Get())

			util.ApplyClientConnectionConfigurationToRESTConfig(&componentbaseconfig.ClientConnectionConfiguration{
				QPS:   100.0,
				Burst: 130,
			}, restOpts.Completed().Config)

			completedMgrOpts := mgrOpts.Completed().Options()
			completedMgrOpts.Client = client.Options{
				Cache: &client.CacheOptions{
					DisableFor: []client.Object{
						&corev1.Secret{},    // applied for ManagedResources
						&corev1.ConfigMap{}, // applied for monitoring config
					},
				},
			}

			mgr, err := manager.New(restOpts.Completed().Config, completedMgrOpts)
			if err != nil {
				return fmt.Errorf("could not instantiate manager: %w", err)
			}
			log.Info("getting rest config for garden")
			gardenRESTConfig, err := kubernetes.RESTConfigFromKubeconfigFile(os.Getenv("GARDEN_KUBECONFIG"), kubernetes.AuthTokenFile)
			if err != nil {
				return err
			}
			log.Info("setting up cluster object for garden")
			gardenCluster, err := cluster.New(gardenRESTConfig, func(opts *cluster.Options) {
				opts.Scheme = kubernetes.GardenScheme
				opts.Logger = log
			})
			if err != nil {
				return fmt.Errorf("failed creating garden cluster object: %w", err)
			}
			dynamicGardenCluster, err := dynamic.NewForConfig(gardenRESTConfig)
			if err != nil {
				return fmt.Errorf("failed creating dynamic garden cluster object: %w", err)
			}

			log.Info("adding garden cluster to manager")
			if err := mgr.Add(gardenCluster); err != nil {
				return fmt.Errorf("failed adding garden cluster to manager: %w", err)
			}
			if err := controller.AddToScheme(mgr.GetScheme()); err != nil {
				return fmt.Errorf("could not update manager scheme: %w", err)
			}

			if err := serviceinstall.AddToScheme(mgr.GetScheme()); err != nil {
				return fmt.Errorf("could not update manager scheme: %w", err)
			}
			if err := falcoCtrlOpts.Complete(); err != nil {
				return err
			}
			falcoConfig := falcoCtrlOpts.Completed()
			falcoConfig.Apply(&lifecycle.DefaultAddOptions.ServiceConfig)

			profile.NewFalcoProfileManager(dynamicGardenCluster)

			if err := lifecycle.AddToManager(ctx, mgr); err != nil {
				return fmt.Errorf("could not add falco extension controller to manager: %w", err)
			}

			var additionalConfig *config.AdditionalConfig
			if lifecycle.DefaultAddOptions.ServiceConfig.Falco != nil {
				additionalConfig = lifecycle.DefaultAddOptions.ServiceConfig.Falco.Additional
			}

			var seedIngressDomain string
			seed, err := utils.GetSeed(context.TODO(), dynamicGardenCluster, os.Getenv("SEED_NAME"))
			if err != nil {
				return fmt.Errorf("could not get seed for additional resources controller: %w", err)
			}
			if seed.Spec.Ingress != nil {
				seedIngressDomain = seed.Spec.Ingress.Domain
			}

			ingressWildcardCertName, err := getIngressWildcardCertificateName(ctx, mgr.GetClient(), log)
			if err != nil {
				return fmt.Errorf("could not get ingress wildcard certificate name: %w", err)
			}

			if err := additional.AddToManager(mgr, log, restOpts.Completed().Config, completedMgrOpts.LeaderElectionNamespace, additionalConfig, seedIngressDomain, ingressWildcardCertName); err != nil {
				return fmt.Errorf("could not add additional seed resources controller: %w", err)
			}

			if err := healthcheck.AddToManager(ctx, mgr); err != nil {
				return fmt.Errorf("could not add health check controller to manager: %w", err)
			}

			heartbeatCtrlOpts.Completed().Apply(&heartbeat.DefaultAddOptions)
			if err := heartbeat.AddToManager(ctx, mgr); err != nil {
				return fmt.Errorf("could not add healtbeat controller to manager: %w", err)
			}

			if err := mgr.Start(ctx); err != nil {
				return fmt.Errorf("error running manager: %w", err)
			}
			return nil
		},
	}

	aggOption.AddFlags(cmd.Flags())

	return cmd
}

func getIngressWildcardCertificateName(ctx context.Context, c client.Client, log logr.Logger) (string, error) {
	secretList := &corev1.SecretList{}
	if err := c.List(ctx, secretList,
		client.InNamespace(v1beta1constants.GardenNamespace),
		client.MatchingLabels{v1beta1constants.GardenRole: v1beta1constants.GardenRoleControlPlaneWildcardCert},
	); err != nil {
		return "", fmt.Errorf("failed to list controlplane-cert secrets: %w", err)
	}
	if len(secretList.Items) == 0 {
		log.Info("no controlplane-cert secret found in garden namespace")
		return "", nil
	}
	if len(secretList.Items) > 1 {
		log.Info("multiple controlplane-cert secrets found, using the first one")
	}
	return secretList.Items[0].Name, nil
}
