// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package additional

import (
	"fmt"

	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
)

const ControllerName = "additional-seed-resources"

// AddToManager registers the additional seed resources reconciler with the manager.
func AddToManager(mgr manager.Manager, log logr.Logger, restConfig *rest.Config, namespace string, additional *config.AdditionalConfig, seedIngressDomain string, ingressWildcardCertificateName string) error {
	r, err := NewReconciler(mgr.GetClient(), restConfig, namespace, additional, seedIngressDomain, ingressWildcardCertificateName, log.WithName(ControllerName))
	if err != nil {
		return fmt.Errorf("could not create additional seed resources reconciler: %w", err)
	}

	return builder.
		ControllerManagedBy(mgr).
		Named(ControllerName).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			ReconciliationTimeout:   controllerutils.DefaultReconciliationTimeout,
		}).
		WatchesRawSource(controllerutils.EnqueueOnce).
		Complete(r)
}
