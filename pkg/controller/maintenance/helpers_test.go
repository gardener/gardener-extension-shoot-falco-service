// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance_test

import (
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/mutator"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/maintenance"
)

func setMutator(r *maintenance.Reconciler, m *mutator.Shoot) {
	r.SetMutator(m)
}

func newFakeClientWithShoot(scheme *runtime.Scheme, shoot *gardencorev1beta1.Shoot) client.Client {
	b := crfake.NewClientBuilder().WithScheme(scheme)
	if shoot != nil {
		b = b.WithObjects(shoot)
	}
	return b.Build()
}

type fakeRecorder struct{}

func (r *fakeRecorder) Eventf(_ runtime.Object, _ runtime.Object, _, _, _, _ string, _ ...interface{}) {
}
