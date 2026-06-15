// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package additional

import (
	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
)

// AddToManager registers the additional seed resources reconciler with the manager.
// The controller always runs so it can clean up stale resources even when the config is empty.
func AddToManager(mgr manager.Manager, log logr.Logger, restConfig *rest.Config, namespace string, additional *config.AdditionalConfig) error {
	r := NewReconciler(mgr.GetClient(), restConfig, namespace, additional, log.WithName("additional-seed-resources"))
	return mgr.Add(r)
}
