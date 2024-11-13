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
		return reconcile.Result{}, err
	}

	// Disable for testing
	log.Info("Scheduled next maintenance for Shoot", "duration", requeueAfter.Round(time.Minute), "nextMaintenance", nextMaintenance.Round(time.Minute))
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

	// TODO do we need to dopy here or not?
	maintainedShoot := shoot.DeepCopy()

	falcoConf, err := r.mutator.ExtractFalcoConfig(maintainedShoot)
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

	// TODO do the update and remove the labels. set success or not
	falcoConf.FalcoVersion = versionToSet
	if err := r.mutator.UpdateFalcoConfig(maintainedShoot, falcoConf); err != nil {
		return fmt.Errorf("could not update Falco config: %s", err.Error())
	}

	// TODO can be used for debugging to see number of changes to shoot spec
	// var m = make(map[string]string)
	// m["myAnnotation"] = fmt.Sprintf("helloWorls %d", i)
	// i++
	// maintainedShoot.Annotations = m

	// patch := client.MergeFrom(shoot.DeepCopy())

	// TODO think about how to mark Falco maintenance progress
	// shoot.Status.LastMaintenance = &gardencorev1beta1.LastMaintenance{
	// 	Description:   fmt.Sprintf("Updating Falco version from %s to %s", *currentVersion, *versionToSet),
	// 	TriggeredTime: metav1.Time{Time: r.Clock.Now()},
	// 	State:         gardencorev1beta1.LastOperationStateProcessing,
	// }

	// if err := r.Client.Status().Patch(ctx, shoot, patch); err != nil {
	// 	return err
	// }

	// First dry run the update call to check if it can be executed successfully (maintenance might yield a Shoot configuration that is rejected by the ApiServer).
	// If the dry run fails, the shoot maintenance is marked as failed and is retried only in
	// next maintenance window.
	if err := r.Client.Update(ctx, maintainedShoot.DeepCopy(), &client.UpdateOptions{
		DryRun: []string{metav1.DryRunAll},
	}); err != nil {
		// If shoot maintenance is triggered by `gardener.cloud/operation=maintain` annotation and if it fails in dry run,
		// `maintain` operation annotation needs to be removed so that if reason for failure is fixed and maintenance is triggered
		// again via `maintain` operation annotation then it should not fail with the reason that annotation is already present.
		// Removal of annotation during shoot status patch is possible cause only spec is kept in original form during status update
		// https://github.com/gardener/gardener/blob/a2f7de0badaae6170d7b9b84c163b8cab43a84d2/pkg/apiserver/registry/core/shoot/strategy.go#L258-L267

		// TODO again we will need a mechanism to signal maintenance similiar to this one
		// if hasMaintainNowAnnotation(shoot) {
		// 	delete(shoot.Annotations, v1beta1constants.GardenerOperation)
		// }
		// shoot.Status.LastMaintenance.Description = "Falco maintenance failed"
		// shoot.Status.LastMaintenance.State = gardencorev1beta1.LastOperationStateFailed
		// shoot.Status.LastMaintenance.FailureReason = ptr.To(fmt.Sprintf("Updates to the Shoot failed to be applied: %s", err.Error()))
		// if err := r.Client.Status().Patch(ctx, shoot, patch); err != nil {
		// 	return err
		// }

		log.Info("Shoot maintenance failed", "reason", err)
		return nil
	}

	shoot.Spec = *maintainedShoot.Spec.DeepCopy()
	// shoot.Annotations = maintainedShoot.Annotations

	// TODO this is required for the annotations??
	// update shoot spec changes in maintenance call
	_ = maintainOperation(shoot)

	// try to maintain shoot, but don't retry on conflict, because a conflict means that we potentially operated on stale
	// data (e.g. when calculating the updated k8s version), so rather return error and backoff
	if err := r.Client.Update(ctx, shoot); err != nil {
		r.Recorder.Event(shoot, corev1.EventTypeWarning, gardencorev1beta1.ShootMaintenanceFailed, err.Error())
		return err
	}

	// if shoot.Status.LastMaintenance != nil && shoot.Status.LastMaintenance.State == gardencorev1beta1.LastOperationStateProcessing {
	// 	patch := client.MergeFrom(shoot.DeepCopy())
	// 	shoot.Status.LastMaintenance.Description = fmt.Sprintf("Succesfully updated Falco version from %s to %s", *currentVersion, *versionToSet)
	// 	shoot.Status.LastMaintenance.State = gardencorev1beta1.LastOperationStateSucceeded

	// 	if err := r.Client.Status().Patch(ctx, shoot, patch); err != nil {
	// 		return err
	// 	}
	// }

	// TODO need to add reports for Falco??
	// make sure to report (partial) maintenance failures
	// if kubernetesControlPlaneUpdate != nil {
	// 	if kubernetesControlPlaneUpdate.isSuccessful {
	// 		r.Recorder.Eventf(shoot, corev1.EventTypeNormal, gardencorev1beta1.ShootEventK8sVersionMaintenance, "%s", fmt.Sprintf("Control Plane: %s. Reason: %s.", kubernetesControlPlaneUpdate.description, kubernetesControlPlaneUpdate.reason))
	// 	} else {
	// 		r.Recorder.Eventf(shoot, corev1.EventTypeWarning, gardencorev1beta1.ShootEventK8sVersionMaintenance, "%s", fmt.Sprintf("Control Plane: Kubernetes version maintenance failed. Reason for update: %s. Error: %v", kubernetesControlPlaneUpdate.reason, kubernetesControlPlaneUpdate.description))
	// 	}
	// }

	// TODO Do we need an event here to record a maintenance event?
	// r.recordMaintenanceEventsForPool(workerToKubernetesUpdate, shoot, gardencorev1beta1.ShootEventK8sVersionMaintenance, "Kubernetes")
	// r.recordMaintenanceEventsForPool(workerToMachineImageUpdate, shoot, gardencorev1beta1.ShootEventImageVersionMaintenance, "Machine image")

	log.Info("Shoot maintenance completed")
	return nil
}

func maintainOperation(shoot *gardencorev1beta1.Shoot) string {
	var operation string
	if hasMaintainNowAnnotation(shoot) {
		delete(shoot.Annotations, v1beta1constants.GardenerOperation)
	}

	if shoot.Status.LastOperation == nil {
		return ""
	}

	switch {
	case shoot.Status.LastOperation.State == gardencorev1beta1.LastOperationStateFailed:
		if needsRetry(shoot) {
			metav1.SetMetaDataAnnotation(&shoot.ObjectMeta, v1beta1constants.GardenerOperation, v1beta1constants.ShootOperationRetry)
			delete(shoot.Annotations, v1beta1constants.FailedShootNeedsRetryOperation)
		}
	default:
		operation = getOperation(shoot)
		metav1.SetMetaDataAnnotation(&shoot.ObjectMeta, v1beta1constants.GardenerOperation, operation)
		delete(shoot.Annotations, v1beta1constants.GardenerMaintenanceOperation)
	}

	if operation == v1beta1constants.GardenerOperationReconcile {
		return ""
	}

	return operation
}

func mustMaintainNow(shoot *gardencorev1beta1.Shoot, clock clock.Clock) bool {
	return hasMaintainNowAnnotation(shoot) || gardenerutils.IsNowInEffectiveShootMaintenanceTimeWindow(shoot, clock)
}

func hasMaintainNowAnnotation(shoot *gardencorev1beta1.Shoot) bool {
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
