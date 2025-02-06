// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"context"
	"fmt"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/mutator"
)

// ControllerName is the name of this controller.
const CONTROLLERNAME = "shoot-maintenance-falco"

var logger = log.Log.WithName(CONTROLLERNAME)

func AddToManager(ctx context.Context, mgr manager.Manager) error { // , cfg config.ControllerManagerConfiguration) error {
	// if err := (&maintenance.Reconciler{Config: cfg.Controllers.ShootMaintenance,}).AddToManager(mgr); err != nil {

	r := &Reconciler{mutator: mutator.NewShoot(mgr)}
	if err := r.AddToManager(mgr); err != nil {
		return fmt.Errorf("failed adding maintenance reconciler: %w", err)
	}
	return nil
}

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager) error {
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor(CONTROLLERNAME + "-controller")
	}

	return builder.
		ControllerManagedBy(mgr).
		Named(CONTROLLERNAME).
		For(&gardencorev1beta1.Shoot{}, builder.WithPredicates(r.ShootPredicate())).
		Complete(r)
}

// ShootPredicate returns the predicates for the core.gardener.cloud/v1beta1.Shoot watch.
func (r *Reconciler) ShootPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			shoot, ok := e.ObjectNew.(*gardencorev1beta1.Shoot)
			if !ok {
				return ok
			}

			oldShoot, ok := e.ObjectOld.(*gardencorev1beta1.Shoot)
			if !ok {
				return ok
			}
			maintain := (hasMaintainNowAnnotation(shoot) && !hasMaintainNowAnnotation(oldShoot)) ||
				!apiequality.Semantic.DeepEqual(oldShoot.Spec.Maintenance.TimeWindow, shoot.Spec.Maintenance.TimeWindow)

			key := "extensions.extensions.gardener.cloud/shoot-falco-service"
			val, ok := shoot.ObjectMeta.Labels[key]

			return maintain && ok && val == "true"
		},
	}
}
