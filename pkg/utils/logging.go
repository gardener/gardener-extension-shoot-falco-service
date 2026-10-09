// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	"context"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// LoggingBackend describes which logging backends are active in the control-plane namespace.
type LoggingBackend struct {
	ValiEnabled          bool
	OtelCollectorEnabled bool
}

// DetectLoggingBackend probes the control-plane namespace for Gardener-managed logging services
// and returns which backends are currently deployed.
// TODO: remove this detection entirely once OTLP is the sole logging backend and can always be assumed present.
func DetectLoggingBackend(ctx context.Context, c client.Client, namespace string) (LoggingBackend, error) {
	valiList := &corev1.ServiceList{}
	if err := c.List(ctx, valiList,
		client.InNamespace(namespace),
		client.MatchingLabels{
			v1beta1constants.LabelApp:   "vali",
			resourcesv1alpha1.ManagedBy: resourcesv1alpha1.GardenerManager,
		},
	); err != nil {
		return LoggingBackend{}, err
	}

	otelList := &corev1.ServiceList{}
	if err := c.List(ctx, otelList,
		client.InNamespace(namespace),
		client.MatchingLabels{
			v1beta1constants.LabelObservabilityApplication: "opentelemetry-collector",
			resourcesv1alpha1.ManagedBy:                    resourcesv1alpha1.GardenerManager,
		},
	); err != nil {
		return LoggingBackend{}, err
	}

	return LoggingBackend{
		ValiEnabled:          len(valiList.Items) > 0,
		OtelCollectorEnabled: len(otelList.Items) > 0,
	}, nil
}
