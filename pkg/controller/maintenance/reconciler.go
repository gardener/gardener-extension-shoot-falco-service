// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"context"
	"fmt"
	"strconv"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/controllerutils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	log "github.com/sirupsen/logrus"
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
	ctx, cancel := controllerutils.GetMainReconciliationContext(ctx, controllerutils.DefaultReconciliationTimeout)
	defer cancel()

	shoot := &gardencorev1beta1.Shoot{}
	if err := r.Client.Get(ctx, request.NamespacedName, shoot); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if shoot.DeletionTimestamp != nil {
		log.Info("Skipping Shoot because it is marked for deletion")
		return reconcile.Result{}, nil
	}

	// Disbale for testing
	requeueAfter, nextMaintenance := requeueAfterDuration(shoot)
	if !mustMaintainNow(shoot, r.Clock) {
		log.Info("Skipping Shoot because it doesn't need to be maintained now")
		log.Info("Scheduled next maintenance for Shoot", "duration", requeueAfter.Round(time.Minute), "nextMaintenance", nextMaintenance.Round(time.Minute))
		return reconcile.Result{RequeueAfter: requeueAfter}, nil
	}

	log.Infof("Maintaining Shoot %s:%s", shoot.Namespace, shoot.Name)
	if err := r.reconcile(ctx, shoot); err != nil {
		log.Errorf("Failed to maintain Shoot %s:%s: %v", shoot.Namespace, shoot.Name, err)
		return reconcile.Result{RequeueAfter: time.Second * 10}, err
	}

	log.Info("Scheduled next maintenance for Shoot: ", nextMaintenance.Round(time.Minute))
	return reconcile.Result{RequeueAfter: requeueAfter}, nil
}

func isVersionExpired(version string, versions map[string]profile.Version) bool {
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
		log.Info("Falco AutoUpdate disabled but needs forced upgrade")
		versionToSet, err = mutator.GetForceUpdateVersion(*currentVersion, *availableVersions)
	} else if autoUpdate {
		log.Info("Falco AutoUpdate enabled")
		versionToSet, err = mutator.GetAutoUpdateVersion(*availableVersions)
	}
	if err != nil {
		return err
	}

	needToUpdate := versionToSet != nil && *versionToSet != *currentVersion

	if !needToUpdate {
		log.Info("Do not need to update Falco version")
		return nil
	}

	falcoConf.FalcoVersion = versionToSet
	if err := r.mutator.UpdateFalcoConfig(shoot, falcoConf); err != nil {
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

	log.Info("Falco shoot maintenance completed")
	return nil
}

func mustMaintainNow(shoot *gardencorev1beta1.Shoot, clock clock.Clock) bool {
	return hasMaintainNowAnnotation(shoot) || gardenerutils.IsNowInEffectiveShootMaintenanceTimeWindow(shoot, clock)
}

func hasMaintainNowAnnotation(shoot *gardencorev1beta1.Shoot) bool {
	operation, ok := shoot.Annotations[v1beta1constants.GardenerOperation]
	return ok && operation == v1beta1constants.ShootOperationMaintain
}

func hasMaintainFalcoAnnotation(shoot *gardencorev1beta1.Shoot) bool {
	operation, ok := shoot.Annotations[v1beta1constants.GardenerOperation]
	return ok && operation == v1beta1constants.ShootOperationMaintain
}

func needsRetry(shoot *gardencorev1beta1.Shoot) bool {
	needsRetryOperation := false

	if val, ok := shoot.Annotations[v1beta1constants.FailedShootNeedsRetryOperation]; ok {
		needsRetryOperation, _ = strconv.ParseBool(val)
	}

	return needsRetryOperation
}

func getOperation(shoot *gardencorev1beta1.Shoot) string {
	var (
		operation            = v1beta1constants.GardenerOperationReconcile
		maintenanceOperation = shoot.Annotations[v1beta1constants.GardenerMaintenanceOperation]
	)

	if maintenanceOperation != "" {
		operation = maintenanceOperation
	}

	return operation
}

// ExpirationDateExpired returns if now is equal or after the given expirationDate
func ExpirationDateExpired(timestamp *metav1.Time) bool {
	if timestamp == nil {
		return false
	}
	return time.Now().UTC().After(timestamp.Time) || time.Now().UTC().Equal(timestamp.Time)
}
