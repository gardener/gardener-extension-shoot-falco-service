// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
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

	// "looging" destination is not allowed for seed
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
		falcoConf := &service.FalcoServiceConfig{
			Destinations: nil,
		}
		err := verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Nil destinations not detected")

		falcoConf.Destinations = &[]service.Destination{}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Empty destinations not detected")

		falcoConf.Destinations = &[]service.Destination{
			{
				Name: "abcdgarbage",
			},
		}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Invalid destination was accepted")

		falcoConf.Destinations = &[]service.Destination{}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Empty destinations not detected")

		falcoConf.Destinations = &[]service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
		}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Valid destination was not accepted")

		falcoConf.Destinations = &[]service.Destination{}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Empty destinations not detected")

		falcoConf.Destinations = &[]service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
			{
				Name: constants.FalcoEventDestinationCentral,
			},
		}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Dublicate destination was accepted")

		falcoConf.Destinations = &[]service.Destination{
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
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Three destinations were accepted")

		falcoConf.Destinations = &[]service.Destination{
			{Name: constants.FalcoEventDestinationLogging},
			{Name: constants.FalcoEventDestinationCustom},
		}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "logging+custom destinations were accepted")

		falcoConf.Destinations = &[]service.Destination{
			{Name: constants.FalcoEventDestinationCustom},
		}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "Custom destinations w/o ref was accepted")

		falcoConf.Destinations = &[]service.Destination{
			{
				Name:               constants.FalcoEventDestinationCustom,
				ResourceSecretName: stringValue("garbage-non-existing-rules-ref"),
			},
			{
				Name: constants.FalcoEventDestinationStdout,
			},
		}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).NotTo(BeNil(), "False custom destinations was accepted")

		falcoConf.Destinations = &[]service.Destination{
			{
				Name:               constants.FalcoEventDestinationCustom,
				ResourceSecretName: stringValue("my-custom-webhook-ref"),
			},
			{
				Name: constants.FalcoEventDestinationStdout,
			},
		}
		err = verifyEventDestinations(falcoConf, genericShootWithSecret)
		Expect(err).To(BeNil(), "Correct custom destinations was not accepted")
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
			StandardRules: &[]string{},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Empty standard rules are not detected as such")

		conf.Rules = &service.Rules{
			CustomRules: &[]service.CustomRule{},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Empty custom rules are not detected as such")

		conf.Rules = &service.Rules{
			StandardRules: &[]string{"rulecfg1", "rulecfg2"},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Non existing standard rules are not detected as such")

		conf.Rules = &service.Rules{
			StandardRules: &[]string{constants.AllowedStandardRules[0], constants.AllowedStandardRules[1]},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).To(BeNil(), "Faulty rejected standard rules")

		conf.Rules = &service.Rules{
			StandardRules: &[]string{constants.AllowedStandardRules[0], constants.AllowedStandardRules[0]},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Accepted standard dublicate rules")

		conf.Rules = &service.Rules{
			CustomRules: &[]service.CustomRule{
				{
					ResourceName: "",
				},
			},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Empty custom rules are not detected as such")

		conf.Rules = &service.Rules{
			CustomRules: &[]service.CustomRule{
				{
					ResourceName: "non-existing",
				},
			},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).NotTo(BeNil(), "Non existing custom rules are not detected as such")

		conf.Rules = &service.Rules{
			CustomRules: &[]service.CustomRule{
				{
					ResourceName: "dummy-custom-rules-ref",
				},
			},
		}
		err = verifyRules(conf, genericShoot.Spec.Resources)
		Expect(err).To(BeNil(), "Existing custom rules reference was rejected")

		conf.Rules = &service.Rules{
			CustomRules: &[]service.CustomRule{
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
		otherNamespace := v1.Namespace{}
		otherNamespace.Name = "testNamespace"

		gardenNamespace := v1.Namespace{}
		gardenNamespace.Name = "garden"

		NamespacesInstance = &Namespaces{}
		NamespacesInstance.namespaces = map[string]*v1.Namespace{
			otherNamespace.Name:                  &otherNamespace,
			constants.AlwaysEnabledNamespaces[0]: &gardenNamespace,
		}

		Expect(verifyNamespaceEligibility("wrongNamespace")).To(BeFalse(), "Namespace is nil but not detected as such")

		Expect(verifyNamespaceEligibility(constants.AlwaysEnabledNamespaces[0])).To(BeTrue(), "Always enabled project is not detected as such")

		Expect(verifyNamespaceEligibility(otherNamespace.Name)).To(BeFalse(), "Non annotated project is not detected as such")

		otherNamespace.Annotations = map[string]string{constants.NamespaceEnableAnnotation: "true"}
		Expect(verifyNamespaceEligibility(otherNamespace.Name)).To(BeTrue(), "Annotated project is falsely detected non-elegible")

		otherNamespace.Annotations = map[string]string{constants.NamespaceEnableAnnotation: "random.garbage"}
		Expect(verifyNamespaceEligibility(otherNamespace.Name)).To(BeFalse(), "Falsely annotated project is detected elegible")
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
	})

	It("checks if central logging is enabled", func(ctx SpecContext) {
		falcoConf := &service.FalcoServiceConfig{}

		falcoConf.Destinations = &[]service.Destination{
			{
				Name: constants.FalcoEventDestinationCentral,
			},
		}
		enabled := isCentralLoggingEnabled(falcoConf)
		Expect(enabled).To(BeTrue(), "Central logging should be enabled when the destination is set to central")

		falcoConf.Destinations = &[]service.Destination{
			{
				Name: constants.FalcoEventDestinationStdout,
			},
		}
		enabled = isCentralLoggingEnabled(falcoConf)
		Expect(enabled).To(BeFalse(), "Central logging should not be enabled when the destination is not central")

		falcoConf.Destinations = &[]service.Destination{
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
})
