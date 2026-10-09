// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"context"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils"
)

var _ = Describe("DetectLoggingBackend", func() {
	const namespace = "shoot--test--foo"

	valiService := func() *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "logging",
				Namespace: namespace,
				Labels: map[string]string{
					v1beta1constants.LabelApp:   "vali",
					resourcesv1alpha1.ManagedBy: resourcesv1alpha1.GardenerManager,
				},
			},
		}
	}

	otelService := func() *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "opentelemetry-collector-collector",
				Namespace: namespace,
				Labels: map[string]string{
					v1beta1constants.LabelObservabilityApplication: "opentelemetry-collector",
					resourcesv1alpha1.ManagedBy:                    resourcesv1alpha1.GardenerManager,
				},
			},
		}
	}

	It("should return both disabled when namespace is empty", func() {
		c := crfake.NewFakeClient()
		backend, err := utils.DetectLoggingBackend(context.TODO(), c, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.ValiEnabled).To(BeFalse())
		Expect(backend.OtelCollectorEnabled).To(BeFalse())
	})

	It("should detect vali when its service is present", func() {
		c := crfake.NewFakeClient(valiService())
		backend, err := utils.DetectLoggingBackend(context.TODO(), c, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.ValiEnabled).To(BeTrue())
		Expect(backend.OtelCollectorEnabled).To(BeFalse())
	})

	It("should detect otel when its service is present", func() {
		c := crfake.NewFakeClient(otelService())
		backend, err := utils.DetectLoggingBackend(context.TODO(), c, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.ValiEnabled).To(BeFalse())
		Expect(backend.OtelCollectorEnabled).To(BeTrue())
	})

	It("should detect both when both services are present", func() {
		c := crfake.NewFakeClient(valiService(), otelService())
		backend, err := utils.DetectLoggingBackend(context.TODO(), c, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.ValiEnabled).To(BeTrue())
		Expect(backend.OtelCollectorEnabled).To(BeTrue())
	})

	It("should not detect vali when its service lacks the managed-by label", func() {
		svc := valiService()
		delete(svc.Labels, resourcesv1alpha1.ManagedBy)
		c := crfake.NewFakeClient(svc)
		backend, err := utils.DetectLoggingBackend(context.TODO(), c, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.ValiEnabled).To(BeFalse())
	})

	It("should not detect otel when its service lacks the managed-by label", func() {
		svc := otelService()
		delete(svc.Labels, resourcesv1alpha1.ManagedBy)
		c := crfake.NewFakeClient(svc)
		backend, err := utils.DetectLoggingBackend(context.TODO(), c, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.OtelCollectorEnabled).To(BeFalse())
	})

	It("should not detect services from a different namespace", func() {
		vali := valiService()
		vali.Namespace = "other-namespace"
		otel := otelService()
		otel.Namespace = "other-namespace"
		c := crfake.NewFakeClient(vali, otel)
		backend, err := utils.DetectLoggingBackend(context.TODO(), c, namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(backend.ValiEnabled).To(BeFalse())
		Expect(backend.OtelCollectorEnabled).To(BeFalse())
	})
})
