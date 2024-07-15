// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/controllerutils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/mutator"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

// TODO used for internal debugging when setting annotation
// var i int = 0

// Reconciler reconciles Shoots and maintains them by updating versions or triggering operations.
type Reconciler struct {
	Client   client.Client
	Clock    clock.Clock
	Recorder record.EventRecorder
	mutator  *mutator.Shoot
}

// Reconcile reconciles Shoots and maintains them by updating versions or triggering operations.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx)

	ctx, cancel := controllerutils.GetMainReconciliationContext(ctx, controllerutils.DefaultReconciliationTimeout)
	defer cancel()

	shoot := &gardencorev1beta1.Shoot{}
	if err := r.Client.Get(ctx, request.NamespacedName, shoot); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if shoot.DeletionTimestamp != nil {
		log.V(1).Info("Skipping Shoot because it is marked for deletion")
		return reconcile.Result{}, nil
	}

	// TODO skipped for testing
	// requeueAfter, nextMaintenance := requeueAfterDuration(shoot)

	// if !mustMaintainNow(shoot, r.Clock) {
	// 	log.V(1).Info("Skipping Shoot because it doesn't need to be maintained now")
	// 	log.V(1).Info("Scheduled next maintenance for Shoot", "duration", requeueAfter.Round(time.Minute), "nextMaintenance", nextMaintenance.Round(time.Minute))
	// 	return reconcile.Result{RequeueAfter: requeueAfter}, nil
	// }

	if err := r.reconcile(ctx, log, shoot); err != nil {
		return reconcile.Result{}, err
	}

	// TODO skipped for testing
	// log.V(1).Info("Scheduled next maintenance for Shoot", "duration", requeueAfter.Round(time.Minute), "nextMaintenance", nextMaintenance.Round(time.Minute))
	// return reconcile.Result{RequeueAfter: requeueAfter}, nil
	return reconcile.Result{}, nil
}

// upgrades to highest supported Falco version
func isVersionDeprecated(version *string) (bool, error) {
	for _, availableVersion := range falco.FalcoVersions().Falco.FalcoVersions {
		if availableVersion.Version == *version {
			return availableVersion.Classification == "deprecated", nil
		}
	}
	return false, fmt.Errorf("the Falco version %s was not found among possible versions", *version)
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

// TODO this can probably be removed
// updateResult represents the result of a Kubernetes or Machine image maintenance operation
// Such maintenance operations can fail if a version must be updated, but the GCM cannot find a suitable version to update to.
// Note: the updates might still be rejected by APIServer validation.
type updateResult struct {
	description  string
	reason       string
	isSuccessful bool
}

func (r *Reconciler) reconcile(ctx context.Context, log logr.Logger, shoot *gardencorev1beta1.Shoot) error {

	// TODO do we need to dopy here or not?
	maintainedShoot := shoot.DeepCopy()

	// TODO check if we have to do anything
	falcoConf, err := r.mutator.ExtractFalcoConfig(maintainedShoot)
	if err != nil {
		return err
	}
	if falcoConf == nil {
		return fmt.Errorf("the Falco config is empty")
	}

	currentVersion := falcoConf.FalcoVersion
	availableVersions := profile.FalcoProfileManagerInstance.GetFalcoVersions()

	deprecated, err := isVersionDeprecated(currentVersion)
	if err != nil {
		return err
	}

	autoUpdate := falcoConf.AutoUpdate != nil && *falcoConf.AutoUpdate
	forceUpdate := !autoUpdate && deprecated

	var versionToSet *string

	if autoUpdate {
		log.Info("Falco AutoUpdate enabled")
		versionToSet, err = mutator.ChooseHighestVersion(availableVersions, "supported")
	} else if forceUpdate {
		log.Info("Falco AutoUpdate disabled but needs forced upgrade")
		versionToSet, err = mutator.ChooseLowestVersionHigherThanCurrent(currentVersion, availableVersions, "supported")
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

	patch := client.MergeFrom(shoot.DeepCopy())

	shoot.Status.LastMaintenance = &gardencorev1beta1.LastMaintenance{
		Description:   fmt.Sprintf("Updating Falco version from %s to %s", *currentVersion, *versionToSet),
		TriggeredTime: metav1.Time{Time: r.Clock.Now()},
		State:         gardencorev1beta1.LastOperationStateProcessing,
	}

	if err := r.Client.Status().Patch(ctx, shoot, patch); err != nil {
		return err
	}

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
		if hasMaintainNowAnnotation(shoot) {
			delete(shoot.Annotations, v1beta1constants.GardenerOperation)
		}
		shoot.Status.LastMaintenance.Description = "Falco maintenance failed"
		shoot.Status.LastMaintenance.State = gardencorev1beta1.LastOperationStateFailed
		shoot.Status.LastMaintenance.FailureReason = ptr.To(fmt.Sprintf("Updates to the Shoot failed to be applied: %s", err.Error()))
		if err := r.Client.Status().Patch(ctx, shoot, patch); err != nil {
			return err
		}

		log.Info("Shoot maintenance failed", "reason", err)
		return nil
	}

	shoot.Spec = *maintainedShoot.Spec.DeepCopy()
	shoot.Annotations = maintainedShoot.Annotations

	// TODO this is required for the annotations??
	// update shoot spec changes in maintenance call
	_ = maintainOperation(shoot)

	// try to maintain shoot, but don't retry on conflict, because a conflict means that we potentially operated on stale
	// data (e.g. when calculating the updated k8s version), so rather return error and backoff
	if err := r.Client.Update(ctx, shoot); err != nil {
		r.Recorder.Event(shoot, corev1.EventTypeWarning, gardencorev1beta1.ShootMaintenanceFailed, err.Error())
		return err
	}

	if shoot.Status.LastMaintenance != nil && shoot.Status.LastMaintenance.State == gardencorev1beta1.LastOperationStateProcessing {
		patch := client.MergeFrom(shoot.DeepCopy())
		shoot.Status.LastMaintenance.Description = fmt.Sprintf("Succesfully updated Falco version from %s to %s", *currentVersion, *versionToSet)
		shoot.Status.LastMaintenance.State = gardencorev1beta1.LastOperationStateSucceeded

		if err := r.Client.Status().Patch(ctx, shoot, patch); err != nil {
			return err
		}
	}

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

// buildMaintenanceMessages builds a combined message containing the performed maintenance operations over all worker pools. If the maintenance operation failed, the description
// contains an indication for the failure and the reason the update was triggered. Details for failed maintenance operations are returned in the second return string.
func buildMaintenanceMessages(kubernetesControlPlaneUpdate *updateResult, workerToKubernetesUpdate map[string]updateResult, workerToMachineImageUpdate map[string]updateResult) (string, string) {
	countSuccessfulOperations := 0
	countFailedOperations := 0
	description := ""
	failureReason := ""

	if kubernetesControlPlaneUpdate != nil {
		if kubernetesControlPlaneUpdate.isSuccessful {
			countSuccessfulOperations++
			description = fmt.Sprintf("%s, %s", description, fmt.Sprintf("Control Plane: %s. Reason: %s", kubernetesControlPlaneUpdate.description, kubernetesControlPlaneUpdate.reason))
		} else {
			countFailedOperations++
			description = fmt.Sprintf("%s, %s", description, fmt.Sprintf("Control Plane: Kubernetes version update failed. Reason for update: %s", kubernetesControlPlaneUpdate.reason))
			failureReason = fmt.Sprintf("%s, Control Plane: Kubernetes maintenance failure due to: %s", failureReason, kubernetesControlPlaneUpdate.description)
		}
	}

	for worker, result := range workerToKubernetesUpdate {
		if result.isSuccessful {
			countSuccessfulOperations++
			description = fmt.Sprintf("%s, %s", description, fmt.Sprintf("Worker pool %q: %s. Reason: %s", worker, result.description, result.reason))
			continue
		}

		countFailedOperations++
		description = fmt.Sprintf("%s, %s", description, fmt.Sprintf("Worker pool %q: Kubernetes version maintenance failed. Reason for update: %s", worker, result.reason))
		failureReason = fmt.Sprintf("%s, Worker pool %q: Kubernetes maintenance failure due to: %s", failureReason, worker, result.description)
	}

	for worker, result := range workerToMachineImageUpdate {
		if result.isSuccessful {
			countSuccessfulOperations++
			description = fmt.Sprintf("%s, %s", description, fmt.Sprintf("Worker pool %q: %s. Reason: %s", worker, result.description, result.reason))
			continue
		}

		countFailedOperations++
		description = fmt.Sprintf("%s, %s", description, fmt.Sprintf("Worker pool %q: machine image version maintenance failed. Reason for update: %s", worker, result.reason))
		failureReason = fmt.Sprintf("%s, Worker pool %q: %s", failureReason, worker, result.description)
	}

	description = strings.TrimPrefix(description, ", ")
	failureReason = strings.TrimPrefix(failureReason, ", ")

	if countFailedOperations == 0 {
		return fmt.Sprintf("All maintenance operations successful. %s", description), failureReason
	}

	return fmt.Sprintf("(%d/%d) maintenance operations successful. %s", countSuccessfulOperations, countSuccessfulOperations+countFailedOperations, description), failureReason
}

// recordMaintenanceEventsForPool records dedicated events for each failed/succeeded maintenance operation per pool
func (r *Reconciler) recordMaintenanceEventsForPool(workerToUpdateResult map[string]updateResult, shoot *gardencorev1beta1.Shoot, eventType string, maintenanceType string) {
	for worker, reason := range workerToUpdateResult {
		if reason.isSuccessful {
			r.Recorder.Eventf(shoot, corev1.EventTypeNormal, eventType, "%s", fmt.Sprintf("Worker pool %q: %v. Reason: %s.",
				worker, reason.description, reason.reason))
			continue
		}

		r.Recorder.Eventf(shoot, corev1.EventTypeWarning, eventType, "%s", fmt.Sprintf("Worker pool %q: %s version maintenance failed. Reason for update: %s. Error: %v",
			worker, maintenanceType, reason.reason, reason.description))
	}
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
