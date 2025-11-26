// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"context"
	"fmt"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/mutator"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

// Reconciler reconciles Shoots and maintains them by updating versions or triggering operations.
type Reconciler struct {
	Client   client.Client
	Clock    clock.Clock
	Recorder record.EventRecorder
	mutator  *mutator.Shoot
}

// Reconcile reconciles Shoots and maintains them by updating versions or triggering operations.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {

	shoot := &gardencorev1beta1.Shoot{}
	if err := r.Client.Get(ctx, request.NamespacedName, shoot); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if shoot.DeletionTimestamp != nil {
		logger.Info("Skipping Shoot because it is marked for deletion")
		return reconcile.Result{}, nil
	}

	requeueAfter, nextMaintenance := requeueAfterDuration(shoot)
	if !mustMaintainNow(shoot, r.Clock) {
		logger.Info("Skipping Shoot because it doesn't need to be maintained now")
		logger.Info("Scheduled next maintenance for Shoot", "duration", requeueAfter.Round(time.Minute), "nextMaintenance", nextMaintenance.Round(time.Minute))
		return reconcile.Result{RequeueAfter: requeueAfter}, nil
	}

	logger.Info(fmt.Sprintf("Maintaining Shoot %s:%s", shoot.Namespace, shoot.Name))
	if err := r.reconcile(ctx, shoot); err != nil {
		logger.Error(err, fmt.Sprintf("Failed to maintain Shoot %s:%s", shoot.Namespace, shoot.Name))
		return reconcile.Result{RequeueAfter: time.Second * 10}, err
	}

	logger.Info(fmt.Sprintf("Scheduled next maintenance for Shoot: %v", nextMaintenance.Round(time.Minute)))
	return reconcile.Result{RequeueAfter: requeueAfter}, nil
}

func isVersionExpired(version string, versions map[string]profile.FalcoVersion) bool {
	existingVersion, ok := versions[version]
	if !ok {
		return true
	}

	expired := existingVersion.Classification == "deprecated" &&
		existingVersion.ExpirationDate != nil &&
		time.Now().After(*existingVersion.ExpirationDate)
	return expired
}

func requeueAfterDuration(shoot *gardencorev1beta1.Shoot) (time.Duration, time.Time) {
	var (
		now             = time.Now()
		window          = gardenerutils.EffectiveShootMaintenanceTimeWindow(shoot)
		duration        = window.RandomDurationUntilNext(now, false)
		nextMaintenance = time.Now().UTC().Add(duration)
	)

	return duration, nextMaintenance
}

func (r *Reconciler) reconcile(ctx context.Context, shoot *gardencorev1beta1.Shoot) error {
	falcoConf, err := r.mutator.ExtractFalcoConfig(shoot)
	if err != nil {
		return err
	}
	if falcoConf == nil {
		return fmt.Errorf("the Falco config is empty")
	}

	currentVersion := falcoConf.FalcoVersion
	availableVersions := profile.FalcoProfileManagerInstance.GetFalcoVersions()

	forceUpdate := isVersionExpired(*currentVersion, *availableVersions)
	autoUpdate := falcoConf.AutoUpdate != nil && *falcoConf.AutoUpdate

	var versionToSet *string
	if forceUpdate {
		logger.Info("Falco version expired, needs upgrade")
		versionToSet, err = mutator.GetForceUpdateVersion(*currentVersion, *availableVersions)
	} else if autoUpdate {
		logger.Info("Falco AutoUpdate enabled")
		versionToSet, err = mutator.GetAutoUpdateVersion(*availableVersions)
	}
	if err != nil {
		return err
	}

	needToUpdate := versionToSet != nil && *versionToSet != *currentVersion

	if !needToUpdate {
		logger.Info("Do not need to update Falco version")
		return nil
	}

	falcoConf.FalcoVersion = versionToSet
	if err := r.mutator.UpdateFalcoConfigShoot(shoot, falcoConf); err != nil {
		return fmt.Errorf("could not update Falco config: %s", err.Error())
	}

	// We want to keep the annotations as they are; the general maintenance controller will remove them
	// _ = maintainOperation(shoot)

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Client.Update(ctx, shoot); err != nil {
			r.Recorder.Event(shoot, corev1.EventTypeWarning, gardencorev1beta1.ShootMaintenanceFailed, err.Error())
			return err
		}
		return nil
	})
	if retryErr != nil {
		return fmt.Errorf("falco maintenance update failed: %v", retryErr)
	}

	logger.Info(fmt.Sprintf("Falco shoot maintenance completed; updated from version %s to %s", *currentVersion, *versionToSet))
	return nil
}

func mustMaintainNow(shoot *gardencorev1beta1.Shoot, clock clock.Clock) bool {
	return hasMaintainNowAnnotation(shoot) || gardenerutils.IsNowInEffectiveShootMaintenanceTimeWindow(shoot, clock)
}

func hasMaintainNowAnnotation(shoot *gardencorev1beta1.Shoot) bool {
	operation, ok := shoot.Annotations[v1beta1constants.GardenerOperation]
	return ok && operation == v1beta1constants.ShootOperationMaintain
}

// ExpirationDateExpired returns if now is equal or after the given expirationDate
func ExpirationDateExpired(timestamp *metav1.Time) bool {
	if timestamp == nil {
		return false
	}
	return time.Now().UTC().After(timestamp.Time) || time.Now().UTC().Equal(timestamp.Time)
}
