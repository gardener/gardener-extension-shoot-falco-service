// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestFalcoExtensionValidator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Falco validating admission test suite")
}

func stringValue(value string) *string {
	return &value
}

func boolValue(value bool) *bool {
	return &value
}
