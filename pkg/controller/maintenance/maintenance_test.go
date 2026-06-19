// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance_test

import (
	"context"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/event"
	sigsmanager "sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/gardener/pkg/apis/core/install"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/mutator"
	serviceinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/install"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/maintenance"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

func shootWithFalco(name, namespace string) *gardencorev1beta1.Shoot {
	return &gardencorev1beta1.Shoot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"extensions.extensions.gardener.cloud/shoot-falco-service": "true",
			},
		},
		Spec: gardencorev1beta1.ShootSpec{
			Maintenance: &gardencorev1beta1.Maintenance{
				TimeWindow: &gardencorev1beta1.MaintenanceTimeWindow{
					Begin: "000000+0000",
					End:   "010000+0000",
				},
			},
			Extensions: []gardencorev1beta1.Extension{
				{
					Type: "shoot-falco-service",
					ProviderConfig: &runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"falco.extensions.gardener.cloud/v1alpha1","kind":"FalcoServiceConfig","falcoVersion":"0.99.0","autoUpdate":true}`),
					},
				},
			},
		},
	}
}

func shootWithoutFalco(name, namespace string) *gardencorev1beta1.Shoot {
	return &gardencorev1beta1.Shoot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: gardencorev1beta1.ShootSpec{
			Maintenance: &gardencorev1beta1.Maintenance{
				TimeWindow: &gardencorev1beta1.MaintenanceTimeWindow{
					Begin: "000000+0000",
					End:   "010000+0000",
				},
			},
		},
	}
}

var _ = Describe("ShootPredicate", func() {
	var (
		reconciler *maintenance.Reconciler
		pred       interface {
			Create(event.CreateEvent) bool
			Update(event.UpdateEvent) bool
			Delete(event.DeleteEvent) bool
			Generic(event.GenericEvent) bool
		}
	)

	BeforeEach(func() {
		reconciler = &maintenance.Reconciler{}
		pred = reconciler.ShootPredicate()
	})

	Describe("CreateFunc", func() {
		It("should accept shoots with the Falco label", func() {
			shoot := shootWithFalco("test", "garden-dev")
			e := event.CreateEvent{Object: shoot}
			Expect(pred.Create(e)).To(BeTrue())
		})

		It("should reject shoots without the Falco label", func() {
			shoot := shootWithoutFalco("test", "garden-dev")
			e := event.CreateEvent{Object: shoot}
			Expect(pred.Create(e)).To(BeFalse())
		})

		It("should reject shoots with Falco label set to false", func() {
			shoot := shootWithoutFalco("test", "garden-dev")
			shoot.Labels = map[string]string{
				"extensions.extensions.gardener.cloud/shoot-falco-service": "false",
			}
			e := event.CreateEvent{Object: shoot}
			Expect(pred.Create(e)).To(BeFalse())
		})
	})

	Describe("UpdateFunc", func() {
		It("should accept when Falco shoot gets maintain annotation", func() {
			oldShoot := shootWithFalco("test", "garden-dev")
			newShoot := oldShoot.DeepCopy()
			newShoot.Annotations = map[string]string{
				v1beta1constants.GardenerOperation: v1beta1constants.ShootOperationMaintain,
			}

			e := event.UpdateEvent{ObjectOld: oldShoot, ObjectNew: newShoot}
			Expect(pred.Update(e)).To(BeTrue())
		})

		It("should reject when non-Falco shoot gets maintain annotation", func() {
			oldShoot := shootWithoutFalco("test", "garden-dev")
			newShoot := oldShoot.DeepCopy()
			newShoot.Annotations = map[string]string{
				v1beta1constants.GardenerOperation: v1beta1constants.ShootOperationMaintain,
			}

			e := event.UpdateEvent{ObjectOld: oldShoot, ObjectNew: newShoot}
			Expect(pred.Update(e)).To(BeFalse())
		})

		It("should accept when maintenance window changes on Falco shoot", func() {
			oldShoot := shootWithFalco("test", "garden-dev")
			newShoot := oldShoot.DeepCopy()
			newShoot.Spec.Maintenance.TimeWindow.Begin = "060000+0000"

			e := event.UpdateEvent{ObjectOld: oldShoot, ObjectNew: newShoot}
			Expect(pred.Update(e)).To(BeTrue())
		})

		It("should reject when nothing maintenance-relevant changed", func() {
			oldShoot := shootWithFalco("test", "garden-dev")
			newShoot := oldShoot.DeepCopy()

			e := event.UpdateEvent{ObjectOld: oldShoot, ObjectNew: newShoot}
			Expect(pred.Update(e)).To(BeFalse())
		})

		It("should reject when maintain annotation was already present", func() {
			oldShoot := shootWithFalco("test", "garden-dev")
			oldShoot.Annotations = map[string]string{
				v1beta1constants.GardenerOperation: v1beta1constants.ShootOperationMaintain,
			}
			newShoot := oldShoot.DeepCopy()

			e := event.UpdateEvent{ObjectOld: oldShoot, ObjectNew: newShoot}
			Expect(pred.Update(e)).To(BeFalse())
		})
	})

	Describe("DeleteFunc", func() {
		It("should always reject", func() {
			shoot := shootWithFalco("test", "garden-dev")
			e := event.DeleteEvent{Object: shoot}
			Expect(pred.Delete(e)).To(BeFalse())
		})
	})

	Describe("GenericFunc", func() {
		It("should always reject", func() {
			shoot := shootWithFalco("test", "garden-dev")
			e := event.GenericEvent{Object: shoot}
			Expect(pred.Generic(e)).To(BeFalse())
		})
	})
})

var _ = Describe("Reconciler", func() {
	var (
		ctx context.Context
		mgr sigsmanager.Manager
	)

	BeforeEach(func() {
		ctx = context.Background()

		var err error
		mgr, err = sigsmanager.New(&rest.Config{}, sigsmanager.Options{})
		Expect(err).NotTo(HaveOccurred())
		install.Install(mgr.GetScheme())
		Expect(serviceinstall.AddToScheme(mgr.GetScheme())).To(Succeed())

		profile.GetDummyFalcoProfileManager(
			&map[string]profile.FalcoVersion{
				"0.99.0": {
					Version:        "0.99.0",
					Classification: "supported",
				},
				"0.100.0": {
					Version:        "0.100.0",
					Classification: "supported",
				},
			},
			&map[string]profile.Image{},
			&map[string]profile.Version{},
			&map[string]profile.Image{},
			&map[string]profile.Version{},
			&map[string]profile.Image{},
		)
	})

	Describe("Reconcile skips shoots without Falco", func() {
		It("should not return an error for a shoot without Falco config", func() {
			shoot := shootWithoutFalco("no-falco", "garden-dev")
			// Set maintain annotation so that mustMaintainNow returns true
			shoot.Annotations = map[string]string{
				v1beta1constants.GardenerOperation: v1beta1constants.ShootOperationMaintain,
			}

			scheme := mgr.GetScheme()
			fakeClient := newFakeClientWithShoot(scheme, shoot)
			m := mutator.NewShoot(mgr, nil)

			rec := &maintenance.Reconciler{
				Client:   fakeClient,
				Clock:    clocktesting.NewFakeClock(time.Now()),
				Recorder: &fakeRecorder{},
			}
			setMutator(rec, m)

			result, err := rec.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "no-falco", Namespace: "garden-dev"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		})
	})

	Describe("Reconcile handles deleted shoots", func() {
		It("should return without error for a missing shoot", func() {
			scheme := mgr.GetScheme()
			fakeClient := newFakeClientWithShoot(scheme, nil)
			m := mutator.NewShoot(mgr, nil)

			rec := &maintenance.Reconciler{
				Client:   fakeClient,
				Clock:    clocktesting.NewFakeClock(time.Now()),
				Recorder: &fakeRecorder{},
			}
			setMutator(rec, m)

			result, err := rec.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "gone", Namespace: "garden-dev"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Duration(0)))
		})
	})

	Describe("Reconcile skips shoots not in maintenance window", func() {
		It("should requeue without calling reconcile when outside maintenance window and no annotation", func() {
			shoot := shootWithFalco("not-now", "garden-dev")
			// No maintain annotation, and window is 00:00-01:00 UTC — unlikely to match now

			scheme := mgr.GetScheme()
			fakeClient := newFakeClientWithShoot(scheme, shoot)
			m := mutator.NewShoot(mgr, nil)

			// Use a clock time well outside the maintenance window
			rec := &maintenance.Reconciler{
				Client:   fakeClient,
				Clock:    clocktesting.NewFakeClock(time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)),
				Recorder: &fakeRecorder{},
			}
			setMutator(rec, m)

			result, err := rec.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "not-now", Namespace: "garden-dev"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		})
	})

	Describe("Reconcile with autoUpdate", func() {
		It("should update the Falco version when autoUpdate is enabled and newer version is available", func() {
			shoot := shootWithFalco("auto-update", "garden-dev")
			shoot.Annotations = map[string]string{
				v1beta1constants.GardenerOperation: v1beta1constants.ShootOperationMaintain,
			}

			scheme := mgr.GetScheme()
			fakeClient := newFakeClientWithShoot(scheme, shoot)
			m := mutator.NewShoot(mgr, nil)

			rec := &maintenance.Reconciler{
				Client:   fakeClient,
				Clock:    clocktesting.NewFakeClock(time.Now()),
				Recorder: &fakeRecorder{},
			}
			setMutator(rec, m)

			_, err := rec.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "auto-update", Namespace: "garden-dev"},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &gardencorev1beta1.Shoot{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: "auto-update", Namespace: "garden-dev"}, updated)).To(Succeed())

			ext := findFalcoExtension(updated)
			Expect(ext).NotTo(BeNil())
			Expect(string(ext.ProviderConfig.Raw)).To(ContainSubstring("0.100.0"))
		})
	})

	Describe("Reconcile with expired version", func() {
		It("should force-update an expired Falco version", func() {
			expiredTime := time.Now().Add(-24 * time.Hour)
			profile.GetDummyFalcoProfileManager(
				&map[string]profile.FalcoVersion{
					"0.98.0": {
						Version:        "0.98.0",
						Classification: "deprecated",
						ExpirationDate: ptr.To(expiredTime),
					},
					"0.99.0": {
						Version:        "0.99.0",
						Classification: "supported",
					},
				},
				&map[string]profile.Image{},
				&map[string]profile.Version{},
				&map[string]profile.Image{},
				&map[string]profile.Version{},
				&map[string]profile.Image{},
			)

			shoot := shootWithFalco("force-update", "garden-dev")
			shoot.Spec.Extensions[0].ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"falco.extensions.gardener.cloud/v1alpha1","kind":"FalcoServiceConfig","falcoVersion":"0.98.0","autoUpdate":false}`),
			}
			shoot.Annotations = map[string]string{
				v1beta1constants.GardenerOperation: v1beta1constants.ShootOperationMaintain,
			}

			scheme := mgr.GetScheme()
			fakeClient := newFakeClientWithShoot(scheme, shoot)
			m := mutator.NewShoot(mgr, nil)

			rec := &maintenance.Reconciler{
				Client:   fakeClient,
				Clock:    clocktesting.NewFakeClock(time.Now()),
				Recorder: &fakeRecorder{},
			}
			setMutator(rec, m)

			_, err := rec.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "force-update", Namespace: "garden-dev"},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &gardencorev1beta1.Shoot{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: "force-update", Namespace: "garden-dev"}, updated)).To(Succeed())

			ext := findFalcoExtension(updated)
			Expect(ext).NotTo(BeNil())
			Expect(string(ext.ProviderConfig.Raw)).To(ContainSubstring("0.99.0"))
		})
	})

	Describe("Reconcile with no update needed", func() {
		It("should not modify shoot when version is already the highest supported", func() {
			shoot := shootWithFalco("up-to-date", "garden-dev")
			shoot.Spec.Extensions[0].ProviderConfig = &runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"falco.extensions.gardener.cloud/v1alpha1","kind":"FalcoServiceConfig","falcoVersion":"0.100.0","autoUpdate":true}`),
			}
			shoot.Annotations = map[string]string{
				v1beta1constants.GardenerOperation: v1beta1constants.ShootOperationMaintain,
			}

			scheme := mgr.GetScheme()
			fakeClient := newFakeClientWithShoot(scheme, shoot)
			m := mutator.NewShoot(mgr, nil)

			rec := &maintenance.Reconciler{
				Client:   fakeClient,
				Clock:    clocktesting.NewFakeClock(time.Now()),
				Recorder: &fakeRecorder{},
			}
			setMutator(rec, m)

			_, err := rec.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "up-to-date", Namespace: "garden-dev"},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &gardencorev1beta1.Shoot{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: "up-to-date", Namespace: "garden-dev"}, updated)).To(Succeed())

			ext := findFalcoExtension(updated)
			Expect(ext).NotTo(BeNil())
			Expect(string(ext.ProviderConfig.Raw)).To(ContainSubstring("0.100.0"))
			Expect(string(ext.ProviderConfig.Raw)).NotTo(ContainSubstring("0.99.0"))
		})
	})
})

func findFalcoExtension(shoot *gardencorev1beta1.Shoot) *gardencorev1beta1.Extension {
	for i := range shoot.Spec.Extensions {
		if shoot.Spec.Extensions[i].Type == "shoot-falco-service" {
			return &shoot.Spec.Extensions[i]
		}
	}
	return nil
}
