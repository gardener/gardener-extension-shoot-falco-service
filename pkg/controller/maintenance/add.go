// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"context"
	"fmt"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
)

// ControllerName is the name of this controller.
const CONTROLLERNAME = "shoot-maintenance-falco"

func AddToManager(ctx context.Context, mgr manager.Manager) error { // , cfg config.ControllerManagerConfiguration) error {
	// if err := (&maintenance.Reconciler{Config: cfg.Controllers.ShootMaintenance,}).AddToManager(mgr); err != nil {
	r := &Reconciler{}
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
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 0, //ptr.Deref(r.Config.ConcurrentSyncs, 0), TODO sensible default??
		}).
		Complete(r)
}

// ShootPredicate returns the predicates for the core.gardener.cloud/v1beta1.Shoot watch.
func (r *Reconciler) ShootPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			shoot, ok := e.ObjectNew.(*gardencorev1beta1.Shoot)
			if !ok {
				return false
			}

			oldShoot, ok := e.ObjectOld.(*gardencorev1beta1.Shoot)
			if !ok {
				return false
			}

			return (hasMaintainNowAnnotation(shoot) && !hasMaintainNowAnnotation(oldShoot)) ||
				!apiequality.Semantic.DeepEqual(oldShoot.Spec.Maintenance.TimeWindow, shoot.Spec.Maintenance.TimeWindow)
		},
	}
}
