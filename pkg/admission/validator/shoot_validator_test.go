// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
		},
	}

	falcoExtension1 = `
	{
	    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
      	"kind": "FalcoServiceConfig",
		"falcoVersion": "1.2.3",
		"output": {
			"eventCollector": "cluster"
		},
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":true
		}
	}`

	falcoExtension2 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"central",
			"logFalcoEvents":false
		}
	}`

	falcoExtension3 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"none",
			"logFalcoEvents":true
		}
	}`

	// falcoctl
	falcoExtension4 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "falcoctl",
		"falcoCtl": {
			"indexes": [
				{
					"name": "myrepo",
					"url": "https://myrepo.com"
				}
			]
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"none",
			"logFalcoEvents":true
		}
	}`

	// wenhook
	falcoExtension5 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "falcoctl",
		"falcoCtl": {
			"indexes": [
				{
					"name": "myrepo",
					"url": "https://myrepo.com"
				}
			]
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"custom",
			"customWebhook": {
				"address": "https://mywebhook.com",
				"customHeaders": "a:b,c:d",
				"checkcerts": true
			}
		}
	}`

	// custom rules
	falcoExtension6 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false,
			"customRules": [ "rulecfg1", "rulecfg2" ]
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"none",
			"logFalcoEvents":true
		}
	}`

	falcoExtensionIllegal1 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"nonsense",
			"logFalcoEvents":false
		}
	}`

	// does not log anything, this does not make sense
	falcoExtensionIllegal2 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"none",
			"logFalcoEvents":false
		}
	}`

	// add extra fields
	falcoExtensionIllegal3 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"nonsense" : "nonsense",
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"none",
			"logFalcoEvents":true
		}
	}`

	// falco version does not exist
	falcoExtensionIllegal4 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"7.8.9",
		"resources": "gardener",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"none",
			"logFalcoEvents":true
		}
	}`

	// specify "falcoctl" as resource but don't specify anything
	falcoExtensionIllegal5 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "falcoctl",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"none",
			"logFalcoEvents":true
		}
	}`

	// specify custom as event collector but don't provide a webhook
	falcoExtensionIllegal6 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "falcoctl",
		"gardener": {
			"useFalcoIncubatingRules":false,
			"useFalcoRules":true,
			"useFalcoSandboxRules":false
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"custom",
			"logFalcoEvents":false
		}
	}`

	// wrong object type
	falcoExtensionIllegal7 = `
	{
		"apiVersion":"nonsense.extensions.gardener.cloud/v1alpha1",
		"kind":"dFalcoServiceConfig",
		"autoUpdate":true
	}`

	// expected outputs from mutator test
	expectedMutate1 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"1.2.3",
		"autoUpdate":true,
		"resources":"gardener",
		"gardener": {
			"useFalcoRules":true,
			"useFalcoIncubatingRules":false,
			"useFalcoSandboxRules":false
		},
		"output": {
			"logFalcoEvents":false,
			"eventCollector":"central"
		}
	}`

	expectedMutate2 = `
	{
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"autoUpdate":true,
		"falcoVersion":"1.2.3",
		"resources": "falcoctl",
		"falcoCtl": {
			"indexes": [
				{
					"name": "myrepo",
					"url": "https://myrepo.com"
				}
			]
		},
		"kind":"FalcoServiceConfig",
		"output": {
			"eventCollector":"central",
			"logFalcoEvents":false
		}
	}`

	expectedMutate3 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"1.2.3",
		"autoUpdate":false,
		"resources":"gardener",
		"gardener": {
			"useFalcoRules":false,
			"useFalcoIncubatingRules":true,
			"useFalcoSandboxRules":true
		},
		"output": {
			"logFalcoEvents":false,
			"eventCollector":"custom",
			"customWebhook": {
				"address": "https://gardener.cloud"
			}
		}
	}`

	expectedMutate4 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"1.2.3",
		"autoUpdate":false,
		"resources":"gardener",
		"gardener": {
			"useFalcoRules":true,
			"useFalcoIncubatingRules":false,
			"useFalcoSandboxRules":true
		},
		"output": {
			"logFalcoEvents":false,
			"eventCollector":"custom",
			"customWebhook": {
				"address": "https://gardener.cloud"
			}
		}
	}`

	expectedMutate6 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"1.2.3",
		"autoUpdate":false,
		"resources":"gardener",
		"gardener": {
			"useFalcoRules":true,
			"useFalcoIncubatingRules":false,
			"useFalcoSandboxRules":true
		},
		"output": {
			"logFalcoEvents":false,
			"eventCollector":"central"
		}
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

	It("verfiy resources", func(ctx SpecContext) {
		conf := &service.FalcoServiceConfig{}
		err := verifyResources(conf)
		Expect(err).NotTo(BeNil(), "Ressources is nil but not detected as such")

		nonSenseRessource := "gardenerr"
		conf.Resources = &nonSenseRessource
		err = verifyResources(conf)
		Expect(err).NotTo(BeNil(), "Resource is of wrong value %s but not detected as such", nonSenseRessource)

		goodRessource := "falcoctl"
		conf.Resources = &goodRessource
		conf.FalcoCtl = &service.FalcoCtl{
			Indexes: []service.FalcoCtlIndex{
				{
					Name: stringValue("myrepo"),
					Url:  stringValue("https://myrepo.com"),
				},
			},
		}
		err = verifyResources(conf)
		Expect(err).To(BeNil(), "Resource is of correct value %s but is detected as invalid", goodRessource)
	})

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

	// currently not implemented
	//
	/*
		It("verify falcoctl", func(ctx SpecContext) {
			var err error
			conf := &service.FalcoServiceConfig{}
			err = verifyFalcoCtl(conf)
			Expect(err).NotTo(BeNil(), "FalcoCtl is nil but not detected as such")

			falcoCtlVal := service.FalcoCtl{}
			conf.FalcoCtl = &falcoCtlVal
			err = verifyFalcoCtl(conf)
			Expect(err).To(BeNil(), "FalcoCtl is not nil but detected as such")
		})
	*/

	It("verify gardener set", func(ctx SpecContext) {
		var err error
		conf := &service.FalcoServiceConfig{}
		err = verifyGardenerSet(conf)
		Expect(err).NotTo(BeNil(), "Gardener is nil but not detected as such")

		gardenerVal := service.Gardener{}
		conf.Gardener = &gardenerVal
		err = verifyGardenerSet(conf)
		Expect(err).NotTo(BeNil(), "Gardener rules are nil but not detected as such")

		commonRulesBool := false
		gardenerVal.UseFalcoRules, gardenerVal.UseFalcoIncubatingRules, gardenerVal.UseFalcoSandboxRules = &commonRulesBool, &commonRulesBool, &commonRulesBool
		err = verifyGardenerSet(conf)
		Expect(err).To(BeNil(), "Gardener rules are not nil but detected as such")
	})

	It("verify project eligibility", func(ctx SpecContext) {
		namespace := "testNamespace"
		project := v1beta1.Project{}

		gardenProject := v1beta1.Project{}
		gardenProject.Name = "garden"

		ProjectsInstance = &Projects{}
		ProjectsInstance.projects = map[string]*v1beta1.Project{namespace: &project, constants.AlwaysEnabledProjects[0]: &gardenProject}

		Expect(verifyProjectEligibility("wrongNamespace")).To(BeFalse(), "Project is nil but not detected as such")

		Expect(verifyProjectEligibility(constants.AlwaysEnabledProjects[0])).To(BeTrue(), "Always enabled project is not detected as such")

		Expect(verifyProjectEligibility(namespace)).To(BeFalse(), "Non annotated project is not detected as such")

		project.Annotations = map[string]string{constants.ProjectEnableAnnotation: "true"}
		Expect(verifyProjectEligibility(namespace)).To(BeTrue(), "Annotated project is falsely detected non-elegible")

		project.Annotations = map[string]string{constants.ProjectEnableAnnotation: "randoma.skjdnasdj"}
		Expect(verifyProjectEligibility(namespace)).To(BeFalse(), "Falsely annotated project is detected elegible")
	})

	It("verify legal extensions", func(ctx SpecContext) {
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
		err = f(falcoExtension1)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtension2)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtension3)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtension4)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtension5)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(falcoExtension6)
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
		err = f(falcoExtensionIllegal1)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("output.eventCollector needs to be set to a value"), "Illegal extension is not detected as such")

		err = f(falcoExtensionIllegal2)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("output.eventCollector is set to none and logFalcoEvents is false - no output would be generated"), "Illegal extension is not detected as such ")

		// additional field (or typo)
		err = f(falcoExtensionIllegal3)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("failed to decode shoot-falco-service provider config: strict decoding error: unknown field \"nonsense\""), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegal4)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("version not found in possible versions"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegal5)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("falcoctl is set as resource but falcoctl property is not defined"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegal6)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("output.eventCollector is set to custom but customWebhook is not defined"), "Illegal extension is not detected as such ")

		err = f(falcoExtensionIllegal7)
		Expect(err).To(Not(BeNil()), "Illegal extension is not detected as such")
		Expect(err.Error()).To(ContainSubstring("failed to decode shoot-falco-service provider confi"), "Illegal extension is not detected as such ")
	})

	It("make sure outputs from mutator validate", func(ctx SpecContext) {
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

		err = f(expectedMutate1)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(expectedMutate2)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(expectedMutate3)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(expectedMutate4)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")

		err = f(expectedMutate6)
		Expect(err).To(BeNil(), "Legal extension is not detected as such")
	})
})
