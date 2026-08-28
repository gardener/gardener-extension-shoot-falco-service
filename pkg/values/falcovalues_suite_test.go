// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package values

import (
	"testing"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils"
)

var tokenIssuerPrivateKey string
var configBuilder *ConfigBuilder
var logger logr.Logger

func TestFalcoValues(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Falcovalues chart generation test suite")
}

var _ = BeforeSuite(func() {
	key, err := secrets.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())
	tokenIssuerPrivateKey = string(secrets.EncodePrivateKey(key))

})

func stringValue(value string) *string {
	return &value
}

func purposeValue(p gardencorev1beta1.ShootPurpose) *gardencorev1beta1.ShootPurpose {
	return &p
}

func baseReconcileCtx(falcoConf *service.FalcoServiceConfig) *utils.ReconcileContext {
	return &utils.ReconcileContext{
		FalcoServiceConfig: falcoConf,
		Namespace:          "shoot--test--foo",
		IsShootDeployment:  true,
		ShootTechnicalId:   shootSpec.Shoot.Status.TechnicalID,
		SeedIngressDomain:  shootSpec.Seed.Spec.Ingress.Domain,
		ClusterIdentity:    shootSpec.Shoot.Status.ClusterIdentity,
	}
}

// func boolValue(value bool) *bool {
// 	return &value
// }
