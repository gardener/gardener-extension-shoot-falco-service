//  SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
//  SPDX-License-Identifier: Apache-2.0

package falcohealth

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller/healthcheck"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

type customFalcoHealthCheck struct {
	shootClient    client.Client
	logger         logr.Logger
	daemonSetCheck healthcheck.HealthCheck
	restConfig     *rest.Config
	clientset      kubernetes.Interface
}

func NewCustomFalcoHealthCheck(daemonSetCheck healthcheck.HealthCheck) *customFalcoHealthCheck {
	return &customFalcoHealthCheck{daemonSetCheck: daemonSetCheck}
}

func (hc *customFalcoHealthCheck) SetLoggerSuffix(provider, extension string) {
	hc.logger = log.Log.WithName(fmt.Sprintf("%s-healthcheck-custom-falco", provider))
	hc.daemonSetCheck.SetLoggerSuffix(provider, extension)
}

func (hc *customFalcoHealthCheck) Check(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	result, err := hc.checkFalco(ctx, request)

	if err == nil && result != nil && result.Status == gardencorev1beta1.ConditionFalse && len(result.Codes) > 0 {
		hc.logger.Info("Custom health check found configuration errors, returning with error codes", "codes", result.Codes)
		return result, err
	}

	if hc.daemonSetCheck != nil {
		hc.logger.V(1).Info("No configuration errors found, falling back to DaemonSet health check")
		nameName := types.NamespacedName{
			Name:      "falco",
			Namespace: metav1.NamespaceSystem,
		}
		return hc.daemonSetCheck.Check(ctx, nameName)
	}

	return result, err
}

func (hc *customFalcoHealthCheck) InjectSourceClient(sourceClient client.Client) {
	if itf, ok := hc.daemonSetCheck.(healthcheck.SourceClient); ok {
		itf.InjectSourceClient(sourceClient)
	}
}

func (hc *customFalcoHealthCheck) InjectTargetClient(targetClient client.Client) {
	hc.shootClient = targetClient
	hc.logger.V(2).Info("Target client injected into custom Falco health check")

	if config, err := rest.InClusterConfig(); err == nil {
		if clientset, err := kubernetes.NewForConfig(config); err == nil {
			hc.restConfig = config
			hc.clientset = clientset
			hc.logger.V(2).Info("Kubernetes clientset created for log reading")
		} else {
			hc.logger.V(1).Info("Failed to create Kubernetes clientset", "error", err)
		}
	} else {
		hc.logger.V(1).Info("Failed to get in-cluster config", "error", err)
	}

	if itf, ok := hc.daemonSetCheck.(healthcheck.TargetClient); ok {
		itf.InjectTargetClient(targetClient)
		hc.logger.V(2).Info("Target client also injected into underlying health check")
	}
}

func (hc *customFalcoHealthCheck) checkFalco(ctx context.Context, request types.NamespacedName) (*healthcheck.SingleCheckResult, error) {
	if hc.shootClient == nil {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionTrue,
			Detail: "Skipping health check - shoot client not available",
		}, nil
	}

	// Check if Falco pods are ready
	podList := &corev1.PodList{}
	labelSelector := client.MatchingLabels{"app.kubernetes.io/name": "falco"}

	if err := hc.shootClient.List(ctx, podList, client.InNamespace(constants.NamespaceKubeSystem), labelSelector); err != nil {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: fmt.Sprintf("Failed to list Falco pods: %v", err),
		}, nil
	}

	if len(podList.Items) == 0 {
		return &healthcheck.SingleCheckResult{
			Status: gardencorev1beta1.ConditionFalse,
			Detail: "No Falco pods found",
		}, nil
	}

	for _, pod := range podList.Items {
		if !isPodReady(&pod) {
			if configError := hc.checkPodConfigError(ctx, &pod); configError != "" {
				return &healthcheck.SingleCheckResult{
					Status: gardencorev1beta1.ConditionFalse,
					Detail: configError,
					Codes:  []gardencorev1beta1.ErrorCode{gardencorev1beta1.ErrorConfigurationProblem},
				}, nil
			}
		}
	}

	return &healthcheck.SingleCheckResult{
		Status: gardencorev1beta1.ConditionTrue,
	}, nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (hc *customFalcoHealthCheck) checkPodConfigError(ctx context.Context, pod *corev1.Pod) string {
	// 1. Check for ConfigMap mount errors in pod events
	events := &corev1.EventList{}
	fieldSelector := client.MatchingFields{
		"involvedObject.name":      pod.Name,
		"involvedObject.namespace": pod.Namespace,
		"involvedObject.kind":      "Pod",
	}

	if err := hc.shootClient.List(ctx, events, client.InNamespace(pod.Namespace), fieldSelector); err == nil {
		for _, event := range events.Items {
			if event.Type == "Warning" {
				msg := strings.ToLower(event.Message)
				if strings.Contains(msg, "configmap") && (strings.Contains(msg, "not found") || strings.Contains(msg, "mount")) {
					return fmt.Sprintf("Falco ConfigMap mount error: %s", event.Message)
				}
			}
		}
	}

	// 2. Check for rule misconfiguration in container logs (if clientset available)
	if hc.clientset != nil {
		for _, container := range pod.Spec.Containers {
			if container.Name == "falco" {
				if ruleError := hc.checkContainerLogsForRuleErrors(ctx, pod, container.Name); ruleError != "" {
					return ruleError
				}
			}
		}
	}

	return ""
}

func (hc *customFalcoHealthCheck) checkContainerLogsForRuleErrors(ctx context.Context, pod *corev1.Pod, containerName string) string {
	podLogOpts := &corev1.PodLogOptions{
		Container: containerName,
		TailLines: func(i int64) *int64 { return &i }(50),
		Previous:  true, // Get logs from crashed container
	}

	req := hc.clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, podLogOpts)
	logs, err := req.Stream(ctx)
	if err != nil {
		podLogOpts.Previous = false
		req = hc.clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, podLogOpts)
		logs, err = req.Stream(ctx)
		if err != nil {
			return ""
		}
	}
	defer logs.Close()

	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Error:") && strings.Contains(line, ".yaml") && strings.Contains(line, "Invalid") {
			return fmt.Sprintf("Falco rules misconfigured: %s", line)
		}
		if strings.Contains(line, "LOAD_ERR_YAML_PARSE") {
			return fmt.Sprintf("Falco YAML syntax error: %s", line)
		}
		if strings.Contains(line, "LOAD_ERR_VALIDATE") {
			return fmt.Sprintf("Falco rule validation error: %s", line)
		}
	}

	return ""
}
