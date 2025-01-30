// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"os"
	"strconv"

	controllercmd "github.com/gardener/gardener/extensions/pkg/controller/cmd"
	"github.com/gardener/gardener/extensions/pkg/util"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	"github.com/gardener/gardener/pkg/apis/core/install"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	componentbaseconfig "k8s.io/component-base/config/v1alpha1"
	"k8s.io/component-base/version/verflag"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	runtimelog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	admissioncmd "github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/cmd"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/validator"
	profileiinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/profile/install"
	serviceinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/install"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/maintenance"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

// AdmissionName is the name of the admission component.
const AdmissionName = "admission-shoot-falco-service"

var log = runtimelog.Log.WithName("gardener-extension-admission-shoot-falco-service")

// NewAdmissionCommand creates a new command for running an admission webhook.
func NewAdmissionCommand(ctx context.Context) *cobra.Command {
	var (
		restOpts = &controllercmd.RESTOptions{}
		mgrOpts  = &controllercmd.ManagerOptions{
			LeaderElection:          true,
			LeaderElectionID:        controllercmd.LeaderElectionNameID(AdmissionName),
			LeaderElectionNamespace: os.Getenv("LEADER_ELECTION_NAMESPACE"),
			WebhookServerPort:       443,
			HealthBindAddress:       ":8081",
			WebhookCertDir:          "/tmp/admission-shoot-falco-service-cert",
		}
		// options for the webhook server
		webhookServerOptions = &webhookcmd.ServerOptions{
			Namespace: os.Getenv("WEBHOOK_CONFIG_NAMESPACE"),
		}
		webhookSwitches = admissioncmd.GardenWebhookSwitchOptions()
		webhookOptions  = webhookcmd.NewAddToManagerOptions(
			AdmissionName,
			"",
			nil,
			webhookServerOptions,
			webhookSwitches,
		)
		falcoOptions = &validator.FalcoWebhookOptions{}
		aggOption    = controllercmd.NewOptionAggregator(
			restOpts,
			mgrOpts,
			webhookOptions,
			falcoOptions,
		)
	)

	cmd := &cobra.Command{
		Use: "admission webhooks of shoot-falco-service",
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			if err := aggOption.Complete(); err != nil {
				runtimelog.Log.Error(err, "Error completing options")
				os.Exit(1)
			}

			util.ApplyClientConnectionConfigurationToRESTConfig(&componentbaseconfig.ClientConnectionConfiguration{
				QPS:   100.0,
				Burst: 130,
			}, restOpts.Completed().Config)

			managerOptions := mgrOpts.Completed().Options()

			// Operators can enable the source cluster option via SOURCE_CLUSTER environment variable.
			// In-cluster config will be used if no SOURCE_KUBECONFIG is specified.
			//
			// The source cluster is for instance used by Gardener's certificate controller, to maintain certificate
			// secrets in a different cluster ('runtime-garden') than the cluster where the webhook configurations
			// are maintained ('virtual-garden').
			var sourceClusterConfig *rest.Config
			if sourceClusterEnabled := os.Getenv("SOURCE_CLUSTER"); sourceClusterEnabled != "" {
				log.Info("Configuring source cluster option")
				var err error
				sourceClusterConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("SOURCE_KUBECONFIG"))
				if err != nil {
					return err
				}
				managerOptions.LeaderElectionConfig = sourceClusterConfig
			} else {
				// Restrict the cache for secrets to the configured namespace to avoid the need for cluster-wide list/watch permissions.
				managerOptions.Cache = cache.Options{
					ByObject: map[client.Object]cache.ByObject{
						&corev1.Secret{}: {Namespaces: map[string]cache.Config{webhookOptions.Server.Completed().Namespace: {}}},
					},
				}
			}

			falcoOptions.Completed().Apply(&validator.DefautltFalcoWebhookOptions)
			mgr, err := manager.New(restOpts.Completed().Config, managerOptions)
			if err != nil {
				runtimelog.Log.Error(err, "Could not instantiate manager")
				os.Exit(1)
			}

			install.Install(mgr.GetScheme())

			if err := serviceinstall.AddToScheme(mgr.GetScheme()); err != nil {
				runtimelog.Log.Error(err, "Could not update manager scheme")
				os.Exit(1)
			}

			if err := profileiinstall.AddToScheme(mgr.GetScheme()); err != nil {
				runtimelog.Log.Error(err, "could not update manager scheme")
				os.Exit(1)
			}

			var sourceCluster cluster.Cluster
			if sourceClusterConfig != nil {
				sourceCluster, err = cluster.New(sourceClusterConfig, func(opts *cluster.Options) {
					opts.Logger = log
					opts.Cache.DefaultNamespaces = map[string]cache.Config{v1beta1constants.GardenNamespace: {}}
				})
				if err != nil {
					return err
				}

				if err := mgr.AddReadyzCheck("source-informer-sync", gardenerhealthz.NewCacheSyncHealthz(sourceCluster.GetCache())); err != nil {
					return err
				}
				if err = mgr.Add(sourceCluster); err != nil {
					return err
				}
			}

			dynamicClientProjects, err := dynamic.NewForConfig(mgr.GetConfig())
			if err != nil {
				return err
			}

			validator.NewProjects(dynamicClientProjects)
			go validator.ProjectsInstance.StartProjectWatch()

			dynamicClient, err := dynamic.NewForConfig(mgr.GetConfig())
			if err != nil {
				return err
			}

			fpm := profile.NewFalcoProfileManager(dynamicClient)
			go fpm.StartWatch()

			log.Info("Setting up webhook server")
			if _, err := webhookOptions.Completed().AddToManager(ctx, mgr, sourceCluster); err != nil {
				return err
			}

			if err := mgr.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
				return fmt.Errorf("could not add readycheck for informers: %w", err)
			}

			if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
				return fmt.Errorf("could not add healthcheck: %w", err)
			}

			if err := mgr.AddReadyzCheck("webhook-server", mgr.GetWebhookServer().StartedChecker()); err != nil {
				return fmt.Errorf("could not add readycheck of webhook to manager: %w", err)
			}

			if err := maintenance.AddToManager(ctx, mgr); err != nil {
				return err
			}

			alphaUsage, _ := strconv.ParseBool(os.Getenv("RESTRICTED_USAGE"))
			if alphaUsage {
				log.Info("Alpha usage restriction is enabled")
			}

			return mgr.Start(ctx)
		},
	}

	aggOption.AddFlags(cmd.Flags())

	return cmd
}
