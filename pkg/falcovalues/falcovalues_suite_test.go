// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falcovalues

import (
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
)

var tokenIssuerPrivateKey string
var configBuilder *ConfigBuilder
var logger logr.Logger
var falcoVersions = falco.FalcoVersions()

func TestFalcoValues(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Fakcovalues chart generation test suite")
}

var _ = BeforeSuite(func() {
	key, err := secrets.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())
	tokenIssuerPrivateKey = string(secrets.EncodePrivateKey(key))

})

func stringValue(value string) *string {
	return &value
}

func boolValue(value bool) *bool {
	return &value
}
