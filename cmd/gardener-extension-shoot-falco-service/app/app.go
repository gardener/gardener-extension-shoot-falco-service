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
	"github.com/gardener/gardener/pkg/logger"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/component-base/version"
	"k8s.io/component-base/version/verflag"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	serviceinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/install"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/cmd"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/lifecycle"
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
			if err := lifecycle.AddToManager(ctx, mgr); err != nil {
				return fmt.Errorf("could not add falco extension controller to manager: %w", err)
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
