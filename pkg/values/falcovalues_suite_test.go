// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package values

import (
	"testing"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	falcopkg "github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils"
)

var tokenIssuerPrivateKey string
var configBuilder *ConfigBuilder
var logger logr.Logger

// testFalcoVersion and testFalcoImage are derived at runtime from the real
// falco-profile.yaml so tests never hardcode a specific version.
var testFalcoVersion string
var testFalcoImage string

func TestFalcoValues(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Falcovalues chart generation test suite")
}

var _ = BeforeSuite(func() {
	key, err := secrets.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())
	tokenIssuerPrivateKey = string(secrets.EncodePrivateKey(key))

	pm, err := profile.NewFalcoProfileManagerFromFalcoProfile(falcopkg.FalcoProfileYAML)
	Expect(err).ToNot(HaveOccurred())
	falcoProfileManager = pm

	// Pick the latest supported falco version from the real profile.
	versions := pm.GetFalcoVersions()
	for _, v := range *versions {
		if v.Classification == "supported" {
			if testFalcoVersion == "" || v.Version > testFalcoVersion {
				testFalcoVersion = v.Version
			}
		}
	}
	Expect(testFalcoVersion).NotTo(BeEmpty(), "no supported falco version found in falco-profile.yaml")

	img := pm.GetFalcoImage(testFalcoVersion)
	Expect(img).NotTo(BeNil())
	testFalcoImage = img.Repository + ":" + img.Tag

	// Re-initialize all package-level configs that depend on testFalcoVersion.
	initVersionedConfigs()
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
