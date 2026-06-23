// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package maintenance

import "github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/mutator"

// SetMutator sets the mutator on the reconciler (test-only export).
func (r *Reconciler) SetMutator(m *mutator.Shoot) {
	r.mutator = m
}
