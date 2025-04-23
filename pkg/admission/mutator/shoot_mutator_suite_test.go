// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

func TestFalcoExtensionMutator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Falco mutating admission test suite")
}

func setProfileManager(profileManager *profile.FalcoProfileManager) {
	profile.FalcoProfileManagerInstance = profileManager
}

func boolValue(value bool) *bool {
	return &value
}
