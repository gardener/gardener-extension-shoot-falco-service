// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	sigsmanager "sigs.k8s.io/controller-runtime/pkg/manager"

	service "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	serviceinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/install"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

var (
	exampleShoot = &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{},
		},
	}

	exampleShootValidation = &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{
				{Type: "shoot-falco-service", Disabled: boolValue(true)},
			},
		},
	}

	exampleShootValidation2 = &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{
				{Type: "shoot-falco-service"},
			},
		},
	}

	genericShoot = &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{
				{
					Type:           "shoot-falco-service",
					Disabled:       boolValue(false),
					ProviderConfig: &runtime.RawExtension{},
				},
			},
			Resources: []core.NamedResourceReference{
				{
					Name: "dummy-custom-rules-ref",
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: "v1",
						Kind:       "ConfigMap",
					},
				},
			},
		},
	}

	genericShootWithSecret = &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{
				{
					Type:           "shoot-falco-service",
					Disabled:       boolValue(false),
					ProviderConfig: &runtime.RawExtension{},
				},
			},
			Resources: []core.NamedResourceReference{
				{
					Name: "dummy-custom-rules-ref",
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: "v1",
						Kind:       "ConfigMap",
					},
				},
				{
					Name: "my-custom-webhook-ref",
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: "v1",
						Kind:       "Secret",
					},
				},
			},
		},
	}

	genericSeed = &core.Seed{
		Spec: core.SeedSpec{
			Extensions: []core.Extension{
				{
					Type:           "shoot-falco-service",
					Disabled:       boolValue(false),
					ProviderConfig: &runtime.RawExtension{},
				},
			},
			Resources: []core.NamedResourceReference{
				{
					Name: "dummy-custom-rules-ref",
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: "v1",
						Kind:       "ConfigMap",
					},
				},
				{
					Name: "my-custom-webhook-ref",
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: "v1",
						Kind:       "Secret",
					},
				},
			},
		},
	}

	genericGarden = &operatorv1alpha1.Garden{
		Spec: operatorv1alpha1.GardenSpec{
			Extensions: []operatorv1alpha1.GardenExtension{
				{
					Type:           "shoot-falco-service",
					ProviderConfig: &runtime.RawExtension{},
				},
			},
			Resources: []gardencorev1beta1.NamedResourceReference{
				{
					Name: "dummy-custom-rules-ref",
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: "v1",
						Kind:       "ConfigMap",
					},
				},
				{
					Name: "my-custom-webhook-ref",
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						APIVersion: "v1",
						Kind:       "Secret",
					},
				},
			},
		},
	}

	falcoExtension1 = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-sandbox-rules",
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "logging"
		 }
		]
	}`

	falcoExtension2 = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "central"
		 }
		]
	}`

	falcoExtension3 = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "stdout"
		 },
		 {
		 	"name": "logging"
		 }
		]
	}`

	falcoExtensionCustomWebhook = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "stdout"
		 },
		 {
		 	"name": "custom",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	falcoExtensionCustomWebookCustomRules = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"custom": [
			 {
				"resourceName": "dummy-custom-rules-ref"
			 }
			]
		},
		"destinations": [
		 {
			"name": "stdout"
		 },
		 {
		 	"name": "custom",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	falcoExtensionwithShootRules1 = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"custom": [
			 {
				"resourceName": "dummy-custom-rules-ref"
			 }, {
				"shootConfigMap": "my-shoot-rules"
			}
			]
		},
		"destinations": [
		 {
			"name": "stdout"
		 },
		 {
		 	"name": "custom",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	// legal
	falcoExtensionwithShootRules2 = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"custom": [
			 {
				"resourceName": "dummy-custom-rules-ref",
				"shootConfigMap": ""
			 }, {
				"shootConfigMap": "my-shoot-rules"
			}
			]
		},
		"destinations": [
		 {
			"name": "stdout"
		 },
		 {
		 	"name": "custom",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	falcoExtensionIllegalNoDestination = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": []
	}`

	falcoExtensionIllegalDoubleDestination = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "logging"
		 },
		 {
		 	"name": "custom",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	falcoExtensionIllegalNoRules = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": []
		},
		"destinations": [
		 {
			"name": "central"
		 }
		]
	}`

	falcoExtensionIllegalAdditionalUnknownField = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"nonsense" : "nonsense",
		"destinations": [
		 {
			"name": "central"
		 },
		 {
		 	"name": "custom",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	falcoExtensionIllegalVersion = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"autoUpdate":true,
		"falcoVersion":"7.8.9",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "central"
		 },
		 {
		 	"name": "custom",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	falcoExtensionIllegalCustomDestWithoutRef = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
		 	"name": "custom"
		 }
		]
	}`

	falcoExtensionIllegalCustomRuleWithoutRef = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			],
			"custom": [
			{
				"resourceName": ""
			}
			]
		},
		"destinations": [
		 {
		 	"name": "stdout"
		 }
		]
	}`

	// wrong object type
	falcoExtensionIllegal7 = `
	{
		"apiVersion":"nonsense.extensions.gardener.cloud/v1alpha1",
		"kind":"dFalcoServiceConfig",
		"autoUpdate":true
	}`

	falcoExtensionIllegalWrongCustomRule1 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			],
			"custom": [
			{
				"shootConfigMap": ""
			}
			]
		},
		"destinations": [
		 {
		 	"name": "stdout"
		 }
		]
	}`

	falcoExtensionIllegalWrongCustomRule2 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			],
			"custom": [
			{
				"resourceName": "dummy-custom-rules-ref",
				"shootConfigMap": "dummy-config-map"
			}
			]
		},
		"destinations": [
		 {
		 	"name": "stdout"
		 }
		]
	}`

	// "logging" destination is not allowed for seed
	falcoExtensionForSeedIllegal = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			],
			"custom": [
			{
				"resourceName": "dummy-custom-rules-ref",
				"shootConfigMap": "dummy-config-map"
			}
			]
		},
		"destinations": [
		 {
		 	"name": "logging"
		 }
		]
	}`

	falcoExtensionSplunk = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "splunk",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	falcoExtensionSplunkNoSecret = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "splunk"
		 }
		]
	}`

	// "logging" destination is not allowed for garden
	falcoExtensionForGardenIllegalLogging = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "logging"
		 }
		]
	}`

	// "otlp" destination is not allowed for garden
	falcoExtensionForGardenIllegalOTLP = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "otlp"
		 }
		]
	}`

	// opensearch with a resourceSecretName pointing to a Secret resource ref
	falcoExtensionOpenSearch = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "opensearch",
			"resourceSecretName": "my-custom-webhook-ref"
		 }
		]
	}`

	// opensearch without resourceSecretName — valid at admission time (secret is only needed at reconcile time)
	falcoExtensionOpenSearchNoSecret = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"rules": {
			"standard": [
				"falco-rules"
			]
		},
		"destinations": [
		 {
			"name": "opensearch"
		 }
		]
	}`
)

func init() {
	supportedVersion := "1.2.3"
	depreatedVersion := "3.2.1"
	expiredVersion := "9.9.9"
	supportedV := profile.FalcoVersion{Version: supportedVersion, Classification: "supported"}
	depreatedV := profile.FalcoVersion{Version: depreatedVersion, Classification: "deprecated"}
	expiredV := profile.FalcoVersion{Version: expiredVersion, Classification: "deprecated", ExpirationDate: &time.Time{}}
	falcoVersions := map[string]profile.FalcoVersion{supportedVersion: supportedV, depreatedVersion: depreatedV, expiredVersion: expiredV}

	profile.GetDummyFalcoProfileManager(
		&falcoVersions,
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
	)
}

var _ = Describe("Test validator", Label("falcovalues"), func() {

	// BeforeEach(func() {
	// 	fakeclient := crfake.NewFakeClient(rulesConfigMap)
	// 	tokenIssuer, err := secrets.NewTokenIssuer(tokenIssuerPrivateKey, 2)
	// 	Expect(err).To(BeNil())
	// 	configBuilder = NewConfigBuilder(fakeclient, tokenIssuer, extensionConfiguration, falcoProfileManager)
	// 	logger, _ = glogger.NewZapLogger(glogger.InfoLevel, glogger.FormatJSON)
	// })

	It("extract falco config", func(ctx SpecContext) {
		s := &shoot{}
		conf, err := s.extractFalcoConfig(exampleShoot)
		Expect(err != nil && conf != nil).To(BeFalse(), "FalcoConf not present but extracted")
	})

	It("validate shoot", func(ctx SpecContext) {
		s := &shoot{}
		err := s.validateShoot(context.Background(), exampleShootValidation, nil)
		Expect(err).To(BeNil(), "FalcoConf not present but extracted")
	})

	It("extension is disabled", func(ctx SpecContext) {
		s := &shoot{}
		exampleShootValidation2.Spec.Extensions[0].Disabled = boolValue(false)
		disabled := s.isDisabled(exampleShootValidation2)
		Expect(disabled).To(BeFalse(), "Extension is disabled but not found")

		exampleShootValidation2.Spec.Extensions[0].Disabled = boolValue(true)
		disabled = s.isDisabled(exampleShootValidation2)
		Expect(disabled).To(BeTrue(), "Extension is disabled but found")

		exampleShootValidation2.Spec.Extensions[0].Disabled = nil
		disabled = s.isDisabled(exampleShootValidation2)
		Expect(disabled).To(BeFalse(), "Extension is present and not explicitly disabled but not found")

		exampleShootValidation2.Spec.Extensions = []core.Extension{}
		disabled = s.isDisabled(exampleShootValidation2)
		Expect(disabled).To(BeTrue(), "No extension is present but reported found")
	})

	// It("verfiy resources", func(ctx SpecContext) {
	// 	conf := &service.FalcoServiceConfig{}
	// 	err := verifyResources(conf)
	// 	Expect(err).NotTo(BeNil(), "Ressources is nil but not detected as such")

	// 	nonSenseRessource := "gardenerr"
	// 	conf.Resources = &nonSenseRessource
	// 	err = verifyResources(conf)
	// 	Expect(err).NotTo(BeNil(), "Resource is of wrong value %s but not detected as such", nonSenseRessource)

	// 	goodRessource := "falcoctl"
	// 	conf.Resources = &goodRessource
	// 	conf.FalcoCtl = &service.FalcoCtl{
	// 		Indexes: []service.FalcoCtlIndex{
	// 			{
	// 				Name: stringValue("myrepo"),
	// 				Url:  stringValue("https://myrepo.com"),
	// 			},
	// 		},
	// 	}
	// 	err = verifyResources(conf)
	// 	Expect(err).To(BeNil(), "Resource is of correct value %s but is detected as invalid", goodRessource)
	// })

	It("verify falco version", func(ctx SpecContext) {

		var err error
		supportedVersion := "1.2.3"
		depreatedVersion := "3.2.1"
		expiredVersion := "9.9.9"
		supportedV := profile.FalcoVersion{Version: supportedVersion, Classification: "supported"}
		depreatedV := profile.FalcoVersion{Version: depreatedVersion, Classification: "deprecated"}
		expiredV := profile.FalcoVersion{Version: expiredVersion, Classification: "deprecated", ExpirationDate: &time.Time{}}
		falcoVersions := map[string]profile.FalcoVersion{supportedVersion: supportedV, depreatedVersion: depreatedV, expiredVersion: expiredV}

		profile.GetDummyFalcoProfileManager(
			&falcoVersions,
			&map[string]profile.Image{},
			&map[string]profile.Version{},
			&map[string]profile.Image{},
			&map[string]profile.Version{},
			&map[string]profile.Image{},
		)

		conf := &service.FalcoServiceConfig{}
		err = verifyFalcoVersion(conf, nil)
		Expect(err).NotTo(BeNil(), "FalcoVersion is nil but not detected as such")

		conf.FalcoVersion = &supportedVersion
		err = verifyFalcoVersion(conf, nil)
		Expect(err).To(BeNil(), "FalcoVersion was supported but detected as invalid")

		err = verifyFalcoVersionInVersions(conf, &falcoVersions)
		Expect(err).To(BeNil(), "Supported FalcoVersion is set but detected as invalid")

		conf.FalcoVersion = &depreatedVersion
		err = verifyFalcoVersionInVersions(conf, &falcoVersions)
		Expect(err).To(BeNil(), "Deprecated FalcoVersion without expiration is set but detected as invalid %s", err)

		conf.FalcoVersion = &expiredVersion
		err = verifyFalcoVersionInVersions(conf, &falcoVersions)
		Expect(err).NotTo(BeNil(), "Expired FalcoVersion is set but accepted as valid")

		nonVersion := "0.0.0"
		conf.FalcoVersion = &nonVersion
		err = verifyFalcoVersionInVersions(conf, &falcoVersions)
		Expect(err).NotTo(BeNil(), "Nonsensical FalcoVersion is set but accepted as valid")

		oldConf := &service.FalcoServiceConfig{}
		conf.FalcoVersion = &expiredVersion
		oldConf.FalcoVersion = &expiredVersion
		err = verifyFalcoVersion(conf, oldConf)
		Expect(err).To(BeNil(), "FalcoVersion was expired but stayed the same between old and new config")

		conf.FalcoVersion = &expiredVersion
		oldConf.FalcoVersion = &supportedVersion
		err = verifyFalcoVersion(conf, oldConf)
		Expect(err).NotTo(BeNil(), "FalcoVersion was suppored but changed to expired between old and new config")
	})

	It("verify event destinations", func(ctx SpecContext) {
		s := &shoot{}
		falcoConf := &service.FalcoServiceConfig{
			Destinations: nil,
		}
		err := s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Nil destinations not detected")

		falcoConf.Destinations = []service.Destination{}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Empty destinations not detected")

		falcoConf.Destinations = []service.Destination{
			{
				Name: "abcdgarbage",
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Invalid destination was accepted")

		falcoConf.Destinations = []service.Destination{}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Empty destinations not detected")

		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Valid destination was not accepted")

		falcoConf.Destinations = []service.Destination{}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Empty destinations not detected")

		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
			{
				Name: constants.FalcoEventDestinationCentral,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Dublicate destination was accepted")

		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
			{
				Name: constants.FalcoEventDestinationStdout,
			},
			{
				Name: constants.FalcoEventDestinationLogging,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Three destinations were not accepted")

		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
			{
				Name: constants.FalcoEventDestinationStdout,
			},
			{
				Name: constants.FalcoEventDestinationLogging,
			},
			{
				Name: constants.FalcoEventDestinationOTLP,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Four destinations should be accepted")

		falcoConf.Destinations = []service.Destination{
			{Name: constants.FalcoEventDestinationLogging},
			{Name: constants.FalcoEventDestinationCustom},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "logging+custom destinations were accepted")

		falcoConf.Destinations = []service.Destination{
			{Name: constants.FalcoEventDestinationCustom},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Custom destinations w/o ref was accepted")

		falcoConf.Destinations = []service.Destination{
			{
				Name:               constants.FalcoEventDestinationCustom,
				ResourceSecretName: stringValue("garbage-non-existing-rules-ref"),
			},
			{
				Name: constants.FalcoEventDestinationStdout,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "False custom destinations was accepted")

		falcoConf.Destinations = []service.Destination{
			{
				Name:               constants.FalcoEventDestinationCustom,
				ResourceSecretName: stringValue("my-custom-webhook-ref"),
			},
			{
				Name: constants.FalcoEventDestinationStdout,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Correct custom destinations was not accepted")

		// Splunk destination tests
		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationSplunk,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Splunk destination without secret ref was accepted")

		falcoConf.Destinations = []service.Destination{
			{
				Name:               constants.FalcoEventDestinationSplunk,
				ResourceSecretName: stringValue("non-existing-splunk-secret"),
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Splunk destination with non-existent secret was accepted")

		falcoConf.Destinations = []service.Destination{
			{
				Name:               constants.FalcoEventDestinationSplunk,
				ResourceSecretName: stringValue("my-custom-webhook-ref"),
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Splunk destination with valid secret was not accepted")

		falcoConf.Destinations = []service.Destination{
			{
				Name:               constants.FalcoEventDestinationSplunk,
				ResourceSecretName: stringValue("my-custom-webhook-ref"),
			},
			{
				Name: constants.FalcoEventDestinationStdout,
			},
			{
				Name: constants.FalcoEventDestinationLogging,
			},
		}
		err = s.verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Splunk with two other destinations was not accepted")
	})

	It("can verify rules", func(ctx SpecContext) {
		var err error
		conf := &service.FalcoServiceConfig{}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Standard and custom rules are nil but not detected as such")

		conf.Rules = &service.Rules{}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Empty rules config is not detected as such")

		conf.Rules = &service.Rules{
			StandardRules: []string{},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Empty standard rules are not detected as such")

		conf.Rules = &service.Rules{
			CustomRules: []service.CustomRule{},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Empty custom rules are not detected as such")

		conf.Rules = &service.Rules{
			StandardRules: []string{"rulecfg1", "rulecfg2"},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Non existing standard rules are not detected as such")

		conf.Rules = &service.Rules{
			StandardRules: []string{constants.AllowedStandardRules[0], constants.AllowedStandardRules[1]},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).To(BeNil(), "Faulty rejected standard rules")

		conf.Rules = &service.Rules{
			StandardRules: []string{constants.AllowedStandardRules[0], constants.AllowedStandardRules[0]},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Accepted standard dublicate rules")

		conf.Rules = &service.Rules{
			CustomRules: []service.CustomRule{
				{
					ResourceName: "",
				},
			},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Empty custom rules are not detected as such")

		conf.Rules = &service.Rules{
			CustomRules: []service.CustomRule{
				{
					ResourceName: "non-existing",
				},
			},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Non existing custom rules are not detected as such")

		conf.Rules = &service.Rules{
			CustomRules: []service.CustomRule{
				{
					ResourceName: "dummy-custom-rules-ref",
				},
			},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).To(BeNil(), "Existing custom rules reference was rejected")

		conf.Rules = &service.Rules{
			CustomRules: []service.CustomRule{
				{
					ResourceName: "dummy-custom-rules-ref",
				},
				{
					ResourceName: "dummy-custom-rules-ref",
				},
			},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Dublicate custom rules are not detected as such")
	})

	It("verify namespace eligibility", func(ctx SpecContext) {
		otherNamespace := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "testNamespace",
			},
		}

		gardenNamespace := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "garden",
			},
		}

		fakeClient := fake.NewClientBuilder().WithObjects(otherNamespace, gardenNamespace).Build()
		s := &shoot{client: fakeClient}

		ok, err := s.verifyNamespaceEligibility(ctx, "wrongNamespace")
		Expect(err).NotTo(BeNil(), "Namespace does not exist but no error returned")
		Expect(ok).To(BeFalse(), "Namespace is nil but not detected as such")

		ok, err = s.verifyNamespaceEligibility(ctx, constants.AlwaysEnabledNamespaces[0])
		Expect(err).To(BeNil())
		Expect(ok).To(BeTrue(), "Always enabled project is not detected as such")

		ok, err = s.verifyNamespaceEligibility(ctx, otherNamespace.Name)
		Expect(err).To(BeNil())
		Expect(ok).To(BeFalse(), "Non annotated project is not detected as such")

		// Update the namespace with the annotation
		otherNamespace.Annotations = map[string]string{constants.NamespaceEnableAnnotation: "true"}
		Expect(fakeClient.Update(ctx, otherNamespace)).To(Succeed())
		ok, err = s.verifyNamespaceEligibility(ctx, otherNamespace.Name)
		Expect(err).To(BeNil())
		Expect(ok).To(BeTrue(), "Annotated project is falsely detected non-elegible")

		otherNamespace.Annotations = map[string]string{constants.NamespaceEnableAnnotation: "random.garbage"}
		Expect(fakeClient.Update(ctx, otherNamespace)).To(Succeed())
		ok, err = s.verifyNamespaceEligibility(ctx, otherNamespace.Name)
		Expect(err).To(BeNil())
		Expect(ok).To(BeFalse(), "Falsely annotated project is detected elegible")
	})

	It("can verify legal extensions", func(ctx SpecContext) {
		managerOptions := sigsmanager.Options{}
		mgr, err := sigsmanager.New(&rest.Config{}, managerOptions)
		Expect(err).To(BeNil(), "Manager could not be created")
		err = serviceinstall.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Scheme could not be added")
		s := NewShootValidator(mgr)

		f := func(extensionSpec string) error {
			providerConfig := genericShootWithSecret.Spec.Extensions[0].ProviderConfig
			providerConfig.Raw = []byte(extensionSpec)
			err = s.Validate(context.TODO(), genericShootWithSecret, nil)
			return err
		}

		err = f(falcoExtension1)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtension2)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtension3)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionCustomWebhook)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionCustomWebookCustomRules)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionwithShootRules1)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionwithShootRules2)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionSplunk)
		Expect(err).To(BeNil(), "Legal splunk extension is not detected as such")
	})

	It("verify illegal extensions", func(ctx SpecContext) {
		managerOptions := sigsmanager.Options{}
		mgr, err := sigsmanager.New(&rest.Config{}, managerOptions)
		Expect(err).To(BeNil(), "Manager could not be created")
		err = serviceinstall.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Scheme could not be added")
		s := NewShootValidator(mgr)

		f := func(extensionSpec string) error {
			providerConfig := genericShoot.Spec.Extensions[0].ProviderConfig
			providerConfig.Raw = []byte(extensionSpec)
			err = s.Validate(context.TODO(), genericShoot, nil)
			return err
		}

		err = f(falcoExtensionIllegalNoDestination)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("no event destination is set"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegalDoubleDestination)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("logging and custom destinations cannot be used together"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegalNoRules)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("falco deployment without any rules is not allowed"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegalAdditionalUnknownField)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")

		err = f(falcoExtensionIllegalVersion)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("version not found in possible versions"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegalCustomDestWithoutRef)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("custom event destination is set but no custom config is defined"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegalCustomRuleWithoutRef)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("found custom rule with neither resource name nor shoot config map defined"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegal7)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("failed to decode shoot-falco-service provider config"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegalWrongCustomRule1)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("found custom rule with neither resource name nor shoot config map defined"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegalWrongCustomRule2)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("found custom rule with both resource name and shoot config map defined"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionSplunkNoSecret)
		Expect(err).To(Not(BeNil()), "Splunk without secret ref is not detected as illegal")
		Expect(err.Error()).To(ContainSubstring("splunk event destination is set but no secret config is defined"), "Splunk without secret ref error message mismatch")
	})

	It("checks if central logging is enabled", func(ctx SpecContext) {
		falcoConf := &service.FalcoServiceConfig{}

		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
		}
		enabled := isCentralLoggingEnabled(falcoConf)
		Expect(enabled).To(BeTrue(), "Central logging should be enabled when the destination is set to central")

		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationStdout,
			},
		}
		enabled = isCentralLoggingEnabled(falcoConf)
		Expect(enabled).To(BeFalse(), "Central logging should not be enabled when the destination is not central")

		falcoConf.Destinations = []service.Destination{
			{
				Name: constants.FalcoEventDestinationStdout,
			},
			{
				Name: constants.FalcoEventDestinationCentral,
			},
		}
		enabled = isCentralLoggingEnabled(falcoConf)
		Expect(enabled).To(BeTrue(), "Central logging should be enabled when one of the destinations is central")
	})

	It("check seed objects with Falco installation", func(ctx SpecContext) {
		managerOptions := sigsmanager.Options{}
		mgr, err := sigsmanager.New(&rest.Config{}, managerOptions)
		Expect(err).To(BeNil(), "Manager could not be created")
		err = serviceinstall.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Scheme could not be added")
		s := NewShootValidator(mgr)

		f := func(extensionSpec string) error {
			providerConfig := genericSeed.Spec.Extensions[0].ProviderConfig
			providerConfig.Raw = []byte(extensionSpec)
			err = s.Validate(context.TODO(), genericSeed, nil)
			return err
		}
		err = f(falcoExtension2)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionCustomWebhook)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionCustomWebookCustomRules)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionwithShootRules1)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionwithShootRules2)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtensionForSeedIllegal)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("unknown event destination: logging"))
		Expect(err.Error()).To(ContainSubstring("found custom rule with both resource name and shoot config map defined"))
	})

	It("accepts seed and garden with falco extension removed", func(ctx SpecContext) {
		managerOptions := sigsmanager.Options{}
		mgr, err := sigsmanager.New(&rest.Config{}, managerOptions)
		Expect(err).To(BeNil())
		err = serviceinstall.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil())
		err = operatorv1alpha1.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil())
		s := NewShootValidator(mgr)

		seedNoFalco := &core.Seed{
			Spec: core.SeedSpec{
				Extensions: []core.Extension{},
			},
		}
		err = s.Validate(context.TODO(), seedNoFalco, nil)
		Expect(err).To(BeNil(), "removing falco extension from seed must not be rejected by the validator")

		gardenNoFalco := &operatorv1alpha1.Garden{
			Spec: operatorv1alpha1.GardenSpec{},
		}
		err = s.Validate(context.TODO(), gardenNoFalco, nil)
		Expect(err).To(BeNil(), "removing falco extension from garden must not be rejected by the validator")
	})

	It("check garden objects with Falco installation", func(ctx SpecContext) {
		managerOptions := sigsmanager.Options{}
		mgr, err := sigsmanager.New(&rest.Config{}, managerOptions)
		Expect(err).To(BeNil(), "Manager could not be created")
		err = serviceinstall.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Scheme could not be added")
		err = operatorv1alpha1.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Operator scheme could not be added")
		s := NewShootValidator(mgr)

		f := func(extensionSpec string) error {
			providerConfig := genericGarden.Spec.Extensions[0].ProviderConfig
			providerConfig.Raw = []byte(extensionSpec)
			return s.Validate(context.TODO(), genericGarden, nil)
		}

		// Legal destinations for garden
		err = f(falcoExtension2) // stdout
		Expect(err).To(BeNil(), "stdout destination should be legal for garden")

		err = f(falcoExtensionCustomWebhook) // custom with secret ref
		Expect(err).To(BeNil(), "custom destination with secret ref should be legal for garden")

		err = f(falcoExtensionCustomWebookCustomRules) // custom with custom rules
		Expect(err).To(BeNil(), "custom destination with custom rules should be legal for garden")

		// Illegal: logging destination is not allowed for garden
		err = f(falcoExtensionForGardenIllegalLogging)
		Expect(err).To(Not(BeNil()), "logging destination must be rejected for garden")
		Expect(err.Error()).To(ContainSubstring("unknown event destination: logging"))

		// Illegal: otlp destination is not allowed for garden
		err = f(falcoExtensionForGardenIllegalOTLP)
		Expect(err).To(Not(BeNil()), "otlp destination must be rejected for garden")
		Expect(err.Error()).To(ContainSubstring("unknown event destination: otlp"))
	})

	It("checks opensearch and splunk destinations for seed and garden", func(ctx SpecContext) {
		managerOptions := sigsmanager.Options{}
		mgr, err := sigsmanager.New(&rest.Config{}, managerOptions)
		Expect(err).To(BeNil(), "Manager could not be created")
		err = serviceinstall.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Scheme could not be added")
		err = operatorv1alpha1.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Operator scheme could not be added")
		s := NewShootValidator(mgr)

		seedF := func(extensionSpec string) error {
			genericSeed.Spec.Extensions[0].ProviderConfig.Raw = []byte(extensionSpec)
			return s.Validate(context.TODO(), genericSeed, nil)
		}
		gardenF := func(extensionSpec string) error {
			genericGarden.Spec.Extensions[0].ProviderConfig.Raw = []byte(extensionSpec)
			return s.Validate(context.TODO(), genericGarden, nil)
		}

		// opensearch with secret ref is valid for both seed and garden
		err = seedF(falcoExtensionOpenSearch)
		Expect(err).To(BeNil(), "opensearch with secret ref should be valid for seed")

		err = gardenF(falcoExtensionOpenSearch)
		Expect(err).To(BeNil(), "opensearch with secret ref should be valid for garden")

		// opensearch without resourceSecretName is rejected
		err = seedF(falcoExtensionOpenSearchNoSecret)
		Expect(err).To(Not(BeNil()), "opensearch without secret ref must be rejected for seed")
		Expect(err.Error()).To(ContainSubstring("opensearch event destination is set but no secret config is defined"))

		err = gardenF(falcoExtensionOpenSearchNoSecret)
		Expect(err).To(Not(BeNil()), "opensearch without secret ref must be rejected for garden")
		Expect(err.Error()).To(ContainSubstring("opensearch event destination is set but no secret config is defined"))

		// splunk with secret ref (my-custom-webhook-ref is a Secret in both genericSeed and genericGarden)
		err = seedF(falcoExtensionSplunk)
		Expect(err).To(BeNil(), "splunk with secret ref should be valid for seed")

		err = gardenF(falcoExtensionSplunk)
		Expect(err).To(BeNil(), "splunk with secret ref should be valid for garden")

		// splunk without resourceSecretName is rejected
		err = seedF(falcoExtensionSplunkNoSecret)
		Expect(err).To(Not(BeNil()), "splunk without secret ref must be rejected for seed")
		Expect(err.Error()).To(ContainSubstring("splunk event destination is set but no secret config is defined"))

		err = gardenF(falcoExtensionSplunkNoSecret)
		Expect(err).To(Not(BeNil()), "splunk without secret ref must be rejected for garden")
		Expect(err.Error()).To(ContainSubstring("splunk event destination is set but no secret config is defined"))

		// central-splunk as a global default: use a validator with globalDefaultKeys configured
		sWithDefaults := &shoot{
			decoder:           s.(*shoot).decoder,
			globalDefaultKeys: map[string]string{"central-splunk": "splunk"},
		}
		centralSplunkConf := &service.FalcoServiceConfig{
			FalcoVersion: stringValue("1.2.3"),
			Rules:        &service.Rules{StandardRules: []string{"falco-rules"}},
			Destinations: []service.Destination{{Name: "central-splunk"}},
		}
		err = sWithDefaults.verifyEventDestinationsCommon(centralSplunkConf, genericSeed.Spec.Resources, constants.AllowedDestinationsSeed)
		Expect(err).To(BeNil(), "central-splunk global default should be valid for seed")

		err = sWithDefaults.verifyEventDestinationsCommon(centralSplunkConf, toNamedResourceRefs(genericGarden.Spec.Resources), constants.AllowedDestinationsGarden)
		Expect(err).To(BeNil(), "central-splunk global default should be valid for garden")
	})

	Context("global default destinations", func() {
		It("should accept a destination whose name is a global default", func() {
			s := &shoot{
				globalDefaultKeys: map[string]string{
					"central-splunk": "splunk",
				},
			}
			falcoConf := &service.FalcoServiceConfig{
				Destinations: []service.Destination{
					{Name: "central-splunk"},
				},
			}
			err := s.verifyEventDestinations(falcoConf, genericShootWithSecret)
			Expect(err).To(BeNil())
		})

		It("should reject an unknown destination not in global defaults", func() {
			s := &shoot{
				globalDefaultKeys: map[string]string{
					"central-splunk": "splunk",
				},
			}
			falcoConf := &service.FalcoServiceConfig{
				Destinations: []service.Destination{
					{Name: "unknown-thing"},
				},
			}
			err := s.verifyEventDestinations(falcoConf, genericShootWithSecret)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("unknown event destination"))
		})

		It("should detect output key conflict between standard and global default", func() {
			s := &shoot{
				globalDefaultKeys: map[string]string{
					"central-splunk": "splunk",
				},
			}
			falcoConf := &service.FalcoServiceConfig{
				Destinations: []service.Destination{
					{Name: constants.FalcoEventDestinationSplunk, ResourceSecretName: stringValue("my-splunk-secret")},
					{Name: "central-splunk"},
				},
			}
			err := s.verifyEventDestinations(falcoConf, genericShootWithSecret)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("same output key"))
		})

		It("should skip disabled destinations in output key conflict check", func() {
			s := &shoot{
				globalDefaultKeys: map[string]string{
					"central-splunk": "splunk",
				},
			}
			falcoConf := &service.FalcoServiceConfig{
				Destinations: []service.Destination{
					{Name: constants.FalcoEventDestinationSplunk, Enabled: boolValue(false), ResourceSecretName: stringValue("my-splunk-secret")},
					{Name: "central-splunk"},
				},
			}
			err := s.verifyEventDestinations(falcoConf, genericShootWithSecret)
			Expect(err).To(BeNil())
		})

		It("should allow multiple global defaults with different output keys", func() {
			s := &shoot{
				globalDefaultKeys: map[string]string{
					"central-splunk":  "splunk",
					"central-elastic": "elasticsearch",
				},
			}
			falcoConf := &service.FalcoServiceConfig{
				Destinations: []service.Destination{
					{Name: "central-splunk"},
					{Name: "central-elastic"},
				},
			}
			err := s.verifyEventDestinations(falcoConf, genericShootWithSecret)
			Expect(err).To(BeNil())
		})
	})
})
