// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	controllerconfig "github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/config"
)

const (
	// Type is the type of Extension resource.
	Type = constants.ExtensionType
	// Name is the name of the lifecycle controller.
	Name = "falco_lifecycle_controller"
	// FinalizerSuffix is the finalizer suffix for the Falco extension.
	FinalizerSuffix = constants.ExtensionType
)

// DefaultAddOptions contains configuration for the Falco extension
var DefaultAddOptions = AddOptions{}

// AddOptions are options to apply when adding the policy filter controller to the manager.
type AddOptions struct {
	// ControllerOptions contains options for the controller.
	ControllerOptions controller.Options
	// ServiceConfig contains configuration for the Falco runtime
	ServiceConfig controllerconfig.Config
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
}

// AddToManager adds a Falco extension lifecycle controller to the given controller manager.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	act, err := NewActuator(mgr, DefaultAddOptions.ServiceConfig.Configuration)
	if err != nil {
		return err
	}
	return extension.Add(mgr, extension.AddArgs{
		Actuator:          act,
		ControllerOptions: DefaultAddOptions.ControllerOptions,
		Name:              Name,
		FinalizerSuffix:   FinalizerSuffix,
		Resync:            60 * time.Minute,
		Predicates:        extension.DefaultPredicates(ctx, mgr, DefaultAddOptions.IgnoreOperationAnnotation),
		Type:              constants.ExtensionType,
	})
}
