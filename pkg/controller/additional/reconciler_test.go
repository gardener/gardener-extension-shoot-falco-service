// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package additional_test

import (
	"context"
	"time"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/additional"
)

var _ = Describe("Reconciler", func() {
	var (
		ctx       context.Context
		scheme    *runtime.Scheme
		namespace string
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespace = "garden"
		scheme = runtime.NewScheme()
		Expect(resourcesv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
	})

	Describe("Reconcile", func() {
		It("should requeue after the reconcile interval on success", func() {
			fakeClient := crfake.NewClientBuilder().WithScheme(scheme).Build()
			r, err := additional.NewReconciler(fakeClient, nil, namespace, nil, zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())

			result, reconcileErr := r.Reconcile(ctx, reconcile.Request{})
			Expect(reconcileErr).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(1 * time.Minute))
		})
	})

	Describe("Cleanup", func() {
		var (
			fakeClient client.Client
			r          *additional.Reconciler
		)

		staleMR := func(name string) *resourcesv1alpha1.ManagedResource {
			return &resourcesv1alpha1.ManagedResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
					Labels:    map[string]string{constants.AdditionalManagedResourceLabel: "true"},
				},
			}
		}

		BeforeEach(func() {
			fakeClient = crfake.NewClientBuilder().WithScheme(scheme).Build()
			var err error
			r, err = additional.NewReconciler(fakeClient, nil, namespace, nil, zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should delete stale resources not in config", func() {
			Expect(fakeClient.Create(ctx, staleMR(constants.AdditionalManagedResourcePrefix+"old-nginx"))).To(Succeed())
			Expect(fakeClient.Create(ctx, staleMR(constants.AdditionalManagedResourcePrefix+"old-redis"))).To(Succeed())

			var err error
			r, err = additional.NewReconciler(fakeClient, nil, namespace, &config.AdditionalConfig{
				SeedManagedResources: []config.AdditionalSeedManagedResource{
					{Name: "old-nginx"},
				},
			}, zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())

			Expect(r.Cleanup(ctx)).To(Succeed())

			mrList := &resourcesv1alpha1.ManagedResourceList{}
			Expect(fakeClient.List(ctx, mrList, client.InNamespace(namespace))).To(Succeed())
			Expect(mrList.Items).To(HaveLen(1))
			Expect(mrList.Items[0].Name).To(Equal(constants.AdditionalManagedResourcePrefix + "old-nginx"))
		})

		It("should delete all labeled resources when config is nil", func() {
			Expect(fakeClient.Create(ctx, staleMR(constants.AdditionalManagedResourcePrefix+"orphan"))).To(Succeed())

			Expect(r.Cleanup(ctx)).To(Succeed())

			mrList := &resourcesv1alpha1.ManagedResourceList{}
			Expect(fakeClient.List(ctx, mrList, client.InNamespace(namespace))).To(Succeed())
			Expect(mrList.Items).To(BeEmpty())
		})

		It("should not delete resources without the label", func() {
			unlabeled := &resourcesv1alpha1.ManagedResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-other-mr",
					Namespace: namespace,
				},
			}
			Expect(fakeClient.Create(ctx, unlabeled)).To(Succeed())

			Expect(r.Cleanup(ctx)).To(Succeed())

			mrList := &resourcesv1alpha1.ManagedResourceList{}
			Expect(fakeClient.List(ctx, mrList, client.InNamespace(namespace))).To(Succeed())
			Expect(mrList.Items).To(HaveLen(1))
		})
	})

	Describe("Deploy", func() {
		It("should return nil when additional config is nil", func() {
			r, err := additional.NewReconciler(nil, nil, namespace, nil, zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Deploy(ctx)).To(Succeed())
		})

		It("should return nil when seed managed resources list is empty", func() {
			r, err := additional.NewReconciler(nil, nil, namespace, &config.AdditionalConfig{}, zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Deploy(ctx)).To(Succeed())
		})
	})
})
