// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"time"

	service "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

	// resources          = "gardener"
	// falcoServiceConfig = &apisservice.FalcoServiceConfig{
	// 	Resources: &resources,
	// 	Gardener: &apisservice.Gardener{
	// 		CustomRules: []string{"rules1", "rules3"},
	// 	},
	// }
	// falcoServiceConfigBad = &apisservice.FalcoServiceConfig{
	// 	Resources: &resources,
	// 	Gardener: &apisservice.Gardener{
	// 		CustomRules: []string{"rules1", "rules2"},
	// 	},
	// }
	// falcoServiceConfigWrongCustomRules = &apisservice.FalcoServiceConfig{
	// 	Resources: &resources,
	// 	Gardener: &apisservice.Gardener{
	// 		CustomRules: []string{"rules1", "rules_wrong"},
	// 	},
	// }
	// falcoServiceConfigCustomWebhook = &apisservice.FalcoServiceConfig{
	// 	FalcoVersion: stringValue("0.38.0"),
	// 	Resources:    &resources,
	// 	Gardener: &apisservice.Gardener{
	// 		UseFalcoRules: boolValue(true),
	// 	},
	// 	CustomWebhook: &apisservice.Webhook{
	// 		Enabled:       boolValue(true),
	// 		Address:       stringValue("https://webhook.example.com"),
	// 		CustomHeaders: stringValue("my-custom-headers"),
	// 		Checkcerts:    boolValue(true),
	// 	},
	// }
	// rulesConfigMap = &corev1.ConfigMapList{
	// 	Items: []corev1.ConfigMap{
	// 		{
	// 			ObjectMeta: metav1.ObjectMeta{
	// 				Namespace: "shoot--test--foo",
	// 				Name:      "ref-rules1",
	// 			},
	// 			Data: map[string]string{
	// 				"dummyrules.yaml": "# dummy rules 1",
	// 			},
	// 		},
	// 		{
	// 			ObjectMeta: metav1.ObjectMeta{
	// 				Namespace: "shoot--test--foo",
	// 				Name:      "ref-rules2",
	// 			},
	// 			Data: map[string]string{
	// 				"dummyrules.yaml": "# dummy rules 2",
	// 			},
	// 		},
	// 		{
	// 			ObjectMeta: metav1.ObjectMeta{
	// 				Namespace: "shoot--test--foo",
	// 				Name:      "ref-rules3",
	// 			},
	// 			Data: map[string]string{
	// 				"dummyrules-other.yaml": "# dummy rules 3",
	// 			},
	// 		},
	// 	},
	// }
)

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

	It("verify webhook", func(ctx SpecContext) {

		err := verifyWebhook(nil)
		Expect(err).NotTo(BeNil(), "Webhook is nil but not detected as such")

		webhook := &service.Webhook{}
		err = verifyWebhook(webhook)
		Expect(err).NotTo(BeNil(), "Enabled flag in webhook is nil but not detected as such")

		webhook.Enabled = boolValue(false)
		err = verifyWebhook(webhook)
		Expect(err).To(BeNil(), "Disabled flag in webhook is not nil not detected as invalid")

		webhook.Enabled = boolValue(true)
		err = verifyWebhook(webhook)
		Expect(err).NotTo(BeNil(), "Webhook is enabled but nil address is not detected")
	})

	It("verfiy resources", func(ctx SpecContext) {
		conf := &service.FalcoServiceConfig{}
		err := verifyResources(conf)
		Expect(err).NotTo(BeNil(), "Ressources is nil but not detected as such")

		nonSenseRessource := "gardenerr"
		conf.Resources = &nonSenseRessource
		err = verifyResources(conf)
		Expect(err).NotTo(BeNil(), "Ressources is of wrong value %s but not detected as such", nonSenseRessource)

		goodRessource := "falcoctl"
		conf.Resources = &goodRessource
		err = verifyResources(conf)
		Expect(err).To(BeNil(), "Ressources is of correct value %s but is detected as invalid", goodRessource)
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
})
