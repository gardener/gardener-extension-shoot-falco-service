// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	providerConfig string = `
			{
				"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
				"autoUpdate": false,
				"falcoVersion": "0.38.1",
				"falcoCtl": {
					"indexes": [
						{
							"name": "default",
							"url": "https://example.com"
						}
					],
					"allowedTypes": [
						"plugins",
						"rules"
					],
					"install": {
						"refs": [
								"a",
								"b"
							],
						"resolveDeps": true
					},
					"follow": {
						"refs": [
							"c"
						],
						"every": "1h"
					}
				},
				"kind": "FalcoServiceConfig",
				"resources": "falcoctl"
			}
`
	providerConfigFalcoctl *extensionsv1alpha1.Extension = &extensionsv1alpha1.Extension{
		Spec: extensionsv1alpha1.ExtensionSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				ProviderConfig: &runtime.RawExtension{
					Raw: []byte(providerConfig),
				},
			},
		},
	}
)

var _ = Describe("FalcoCtlConfig", Label("utils"), func() {
	It("should extract FalcoServiceConfig", func() {
		_, err := ExtractFalcoServiceConfig(providerConfigFalcoctl)
		Expect(err).ToNot(HaveOccurred())
	})
})

var _ = Describe("utils", Label("utils"), func() {
	DescribeTable(
		"#ComputeValiHost",
		func(shootName, projectName, storedTechnicalID, domain string, matcher gomegatypes.GomegaMatcher) {
			var (
				seed = gardencorev1beta1.Seed{
					Spec: gardencorev1beta1.SeedSpec{
						Ingress: &gardencorev1beta1.Ingress{
							Domain: domain,
						},
					},
				}
				shoot = gardencorev1beta1.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Name: shootName,
					},
				}
			)
			shoot.Status = gardencorev1beta1.ShootStatus{
				TechnicalID: storedTechnicalID,
			}
			shoot.Status.TechnicalID = gardenerutils.ComputeTechnicalID(projectName, &shoot)
			Expect(ComputeValiHost(shoot, seed)).To(matcher)
		},
		Entry("ingress calculation (no stored technical ID)",
			"fooShoot",
			"barProject",
			"",
			"ingress.seed.example.com",
			Equal("v-barProject--fooShoot.ingress.seed.example.com"),
		),
		Entry("ingress calculation (historic stored technical ID with a single dash)",
			"fooShoot",
			"barProject",
			"shoot-barProject--fooShoot",
			"ingress.seed.example.com",
			Equal("v-barProject--fooShoot.ingress.seed.example.com")),
		Entry("ingress calculation (current stored technical ID with two dashes)",
			"fooShoot",
			"barProject",
			"shoot--barProject--fooShoot",
			"ingress.seed.example.com",
			Equal("v-barProject--fooShoot.ingress.seed.example.com")),
	)
})
