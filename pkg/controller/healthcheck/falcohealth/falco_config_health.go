// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falcohealth

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

type customFalcoHealthCheck struct {
	shootClient    client.Client
	logger         logr.Logger
	deploymentCheck healthcheck.HealthCheck
}

func NewCustomFalcoHealthCheck(deploymentCheck healthcheck.HealthCheck) *customFalcoHealthCheck {
	return &customFalcoHealthCheck{deploymentCheck: deploymentCheck}
}

func (hc *customFalcoHealthCheck) SetLoggerSuffix(provider, extension string) {
	hc.logger = log.Log.WithName(fmt.Sprintf("%s-healthcheck-custom-falco", provider))
	hc.deploymentCheck.SetLoggerSuffix(provider, extension)
}

func (hc *customFalcoHealthCheck) Check(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	// result, err := hc.daemonSetCheck.Check(ctx, request)
	// if err != nil || result.Status != gardencorev1beta1.ConditionTrue {
	// 	return result, err
	// }
	hc.logger.Info(";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;The request object", "request", request, "namespace", request.Namespace, "name", request.Name)
	return hc.checkFalco(ctx, request)
}

// DeepCopy clones the healthCheck
func (hc *customFalcoHealthCheck) DeepCopy() healthcheck.HealthCheck {
	return &customFalcoHealthCheck{
		deploymentCheck: hc.deploymentCheck.DeepCopy(),
		shootClient:    hc.shootClient,
	}
}

// InjectSeedClient injects the seed client
func (hc *customFalcoHealthCheck) InjectSeedClient(seedClient client.Client) {
	if itf, ok := hc.deploymentCheck.(healthcheck.SeedClient); ok {
		itf.InjectSeedClient(seedClient)
	}
}

// InjectShootClient injects the shoot client
func (hc *customFalcoHealthCheck) InjectShootClient(shootClient client.Client) {
	if itf, ok := hc.deploymentCheck.(healthcheck.ShootClient); ok {
		itf.InjectShootClient(shootClient)
		hc.logger.Info("______________________________________________________ client injected into custom Falco health check", shootClient)
	} else {
		hc.logger.Info("______________________________________________________ Shoot client is already set, skipping injection")
	}
	hc.shootClient = shootClient
}

// Check implements the HealthCheck interface
func (hc *customFalcoHealthCheck) checkFalco(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	hc.logger.Info("Checking Falco configuration health", "extension", request)

	// Check if shoot client is available
	if hc.shootClient == nil {
		hc.logger.Info("BBBBBBBBBBB Shoot client is not set, skipping health check for local development")
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionTrue,
			Detail: "Skipping health check - shoot client not available (likely local development)",
		}, nil
	}


	hc.logger.Info("_________________________ We have a shoot client and we will di something")

    namespaces := &corev1.NamespaceList{}
    err := hc.shootClient.List(ctx, namespaces, &client.ListOptions{Limit: 1})
	if err != nil {
		hc.logger.Error(err, "Failed to list namespaces")
		return nil, nil
	}

	// Get Falco DaemonSet from shoot cluster
	daemonSet := &appsv1.DaemonSet{}
	daemonSetKey := types.NamespacedName{
		Name:      "falco",
		Namespace: metav1.NamespaceSystem,
	}

	hc.shootClient.Status()

	if err := hc.shootClient.Get(ctx, daemonSetKey, daemonSet); err != nil {
		hc.logger.Error(err, "Failed to get Falco DaemonSet")
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: fmt.Sprintf("Failed to retrieve Falco DaemonSet: %v", err),
			Codes:  []gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem},
		}, nil
	}

	// Check if DaemonSet is available
	if daemonSet.Status.NumberAvailable == 0 {
		hc.logger.Info("Falco DaemonSet has no available pods")
		return hc.checkPodLogs(ctx)
	}

	// Check if desired number equals ready number
	if daemonSet.Status.DesiredNumberScheduled != daemonSet.Status.NumberReady {
		hc.logger.Info("Falco DaemonSet not fully ready",
			"desired", daemonSet.Status.DesiredNumberScheduled,
			"ready", daemonSet.Status.NumberReady)
		return hc.checkPodLogs(ctx)
	}

	// All pods are ready, extension is healthy
	return &healthcheck.SingleCheckResult{
		Status: gardencorev1beta1.ConditionTrue,
		Detail: "Falco pods are ready and healthy",
	}, nil
}

// checkPodLogs retrieves and analyzes Falco pod logs for configuration errors
func (hc *customFalcoHealthCheck) checkPodLogs(ctx context.Context) (*healthcheck.SingleCheckResult, error) {
	hc.logger.Info("Checking Falco pod logs for configuration errors")

	// List Falco pods
	podList := &corev1.PodList{}
	labelSelector := client.MatchingLabels{
		"app.kubernetes.io/name": "falco",
	}

	if err := hc.shootClient.List(ctx, podList, client.InNamespace(constants.NamespaceKubeSystem), labelSelector); err != nil {
		hc.logger.Error(err, "Failed to list Falco pods")
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: fmt.Sprintf("Failed to list Falco pods: %v", err),
			Codes:  []gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem},
		}, nil
	}

	if len(podList.Items) == 0 {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: "No Falco pods found",
			Codes:  []gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem},
		}, nil
	}

	// Check for any non-ready pods and analyze their status
	var configErrors []string
	var podErrors []string

	for _, pod := range podList.Items {
		if isPodReady(&pod) {
			continue // Skip ready pods
		}

		hc.logger.Info("Checking non-ready Falco pod", "pod", pod.Name, "phase", pod.Status.Phase)

		// Check pod conditions for configuration issues
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionFalse {
				if isConfigurationError(condition.Message) {
					configErrors = append(configErrors, fmt.Sprintf("Pod %s: %s", pod.Name, condition.Message))
				}
			}
		}

		// Check container statuses for configuration errors
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.Name == "falco" && !containerStatus.Ready {
				if containerStatus.State.Waiting != nil && isConfigurationError(containerStatus.State.Waiting.Message) {
					configErrors = append(configErrors, fmt.Sprintf("Pod %s container %s: %s", pod.Name, containerStatus.Name, containerStatus.State.Waiting.Message))
				}
				if containerStatus.State.Terminated != nil && isConfigurationError(containerStatus.State.Terminated.Message) {
					configErrors = append(configErrors, fmt.Sprintf("Pod %s container %s terminated: %s", pod.Name, containerStatus.Name, containerStatus.State.Terminated.Message))
				}
			}
		}

		if len(configErrors) == 0 {
			podErrors = append(podErrors, fmt.Sprintf("Pod %s not ready (phase: %s)", pod.Name, pod.Status.Phase))
		}
	}

	// Report configuration errors if found
	if len(configErrors) > 0 {
		detail := fmt.Sprintf("Falco configuration errors detected: %s", strings.Join(configErrors, "; "))
		hc.logger.Error(nil, "Configuration errors found in Falco", "errors", configErrors)

		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: detail,
			Codes:  []gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem},
		}, nil
	}

	// Report general pod errors if no config errors but pods aren't ready
	if len(podErrors) > 0 {
		detail := fmt.Sprintf("Falco pods not ready: %s", strings.Join(podErrors, "; "))
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: detail,
		}, nil
	}

	// No specific errors found, but pods still not ready
	return &healthcheck.SingleCheckResult{
		Status: gardencorev1beta1.ConditionFalse,
		Detail: "Falco pods are not ready, but no specific configuration errors detected",
	}, nil
}

// isPodReady checks if a pod is ready
func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// isConfigurationError checks if an error message indicates a configuration problem
func isConfigurationError(message string) bool {
	if message == "" {
		return false
	}

	// Enhanced configuration error patterns based on your specific requirements
	configErrorPatterns := []*regexp.Regexp{
		// Engine version mismatches - specific to your error case
		regexp.MustCompile(`(?i)LOAD_ERR_VALIDATE.*Rules require engine version.*but engine version is`),
		regexp.MustCompile(`(?i)required_engine_version.*Rules require engine version.*but engine version is`),
		regexp.MustCompile(`(?i)Falco internal: hot restart failure.*required_engine_version`),

		// Invalid rules files - specific to your error case
		regexp.MustCompile(`(?i)Error:.*\.yaml: Invalid`),
		regexp.MustCompile(`(?i)Invalid.*Errors.*In rules content`),
		regexp.MustCompile(`(?i)shoot-custom-rules.*\.yaml.*Invalid`),

		// Schema validation failures
		regexp.MustCompile(`(?i)schema validation: (failed|error)`),

		// Rules file loading errors
		regexp.MustCompile(`(?i)unable to load rules|error loading rules|rules file.*not found`),
		regexp.MustCompile(`(?i)yaml.*parsing.*error|yaml.*syntax.*error`),
		regexp.MustCompile(`(?i)rule.*compilation.*error|rule.*parsing.*error`),
		regexp.MustCompile(`(?i)failed.*to.*read.*rules|cannot.*open.*rules`),
		regexp.MustCompile(`(?i)rules.*directory.*not.*found|rules.*path.*error`),

		// Configuration file errors
		regexp.MustCompile(`(?i)config.*file.*not.*found|config.*parsing.*error|invalid.*configuration`),
		regexp.MustCompile(`(?i)falco\.yaml.*error|configuration.*invalid`),

		// Custom rules errors - enhanced for shoot ConfigMap rules
		regexp.MustCompile(`(?i)custom.*rules.*error|user.*rules.*invalid`),
		regexp.MustCompile(`(?i)shoot-custom-rules.*error`),

		// Fatal configuration errors
		regexp.MustCompile(`(?i)fatal.*configuration|critical.*config.*error`),
		regexp.MustCompile(`(?i)startup.*failed|initialization.*error`),

		// Rules that can't be loaded/opened (your specific requirement)
		regexp.MustCompile(`(?i)cannot.*read.*rules|unable.*to.*access.*rules`),
		regexp.MustCompile(`(?i)closing inspectors.*Error:`),
	}

	for _, pattern := range configErrorPatterns {
		if pattern.MatchString(message) {
			return true
		}
	}

	return false
}
