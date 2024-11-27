// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"testing"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

func TestExtractFalcoConf(t *testing.T) {
	s := &shoot{}
	exampleShoot := &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{},
		},
	}

	conf, err := s.extractFalcoConfig(exampleShoot)
	if err != nil && conf != nil {
		t.Errorf("FalcoConf not present but extracted")
	}
}

func TestValidateShoot(t *testing.T) {
	disabledSet := true
	exampleShoot := &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{
				{Type: "shoot-falco-service", Disabled: &disabledSet},
			},
		},
	}
	s := &shoot{}

	if err := s.validateShoot(context.Background(), exampleShoot, nil); err != nil {
		t.Error("Extension disabled but validated")
	}
}

func TestExtensionIsDisabled(t *testing.T) {
	disabledSet := false
	exampleShoot := &core.Shoot{
		Spec: core.ShootSpec{
			Extensions: []core.Extension{
				{Type: "shoot-falco-service", Disabled: &disabledSet},
			},
		},
	}

	s := &shoot{}
	disabled := s.isDisabled(exampleShoot)
	if disabled {
		t.Error("Extension is present but not found")
	}

	disabledSet = true
	disabled = s.isDisabled(exampleShoot)
	if !disabled {
		t.Error("Extension is disabled but found")
	}

	exampleShoot.Spec.Extensions[0].Disabled = nil
	disabled = s.isDisabled(exampleShoot)
	if disabled {
		t.Error("Extension is present and not explicitly disabled but not found")
	}

	exampleShoot.Spec.Extensions = []core.Extension{}
	disabled = s.isDisabled(exampleShoot)
	if !disabled {
		t.Error("No extension is present but reported found")
	}
}

func TestVerifyWebhook(t *testing.T) {
	conf := &service.FalcoServiceConfig{}
	if err := verifyWebhook(conf); err == nil {
		t.Fatalf("Webhook is nil but not detected as such")
	}

	webhook := service.Webhook{}
	conf.CustomWebhook = &webhook
	if err := verifyWebhook(conf); err == nil {
		t.Fatalf("Enabled flag in webhook is nil but not detected as such")
	}

	disable := false
	conf.CustomWebhook.Enabled = &disable
	if err := verifyWebhook(conf); err != nil {
		t.Fatalf("Disabled flag in webhook is not nil not detected as invalid")
	}

	enable := true
	conf.CustomWebhook.Enabled = &enable
	if err := verifyWebhook(conf); err == nil {
		t.Fatalf("Webhook is enabled but nil address is not detected")
	}
}

func TestVerifyResources(t *testing.T) {
	conf := &service.FalcoServiceConfig{}
	if err := verifyResources(conf); err == nil {
		t.Fatalf("Ressources is nil but not detected as such")
	}

	nonSenseRessource := "gardenerr"
	conf.Resources = &nonSenseRessource
	if err := verifyResources(conf); err == nil {
		t.Fatalf("Ressources is of wrong value %s but not detected as such", nonSenseRessource)
	}

	goodRessource := "falcoctl"
	conf.Resources = &goodRessource
	if err := verifyResources(conf); err != nil {
		t.Fatalf("Ressources is of correct value %s but is detected as invalid", goodRessource)
	}
}

func TestVerifyFalcoVersion(t *testing.T) {

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
	if err := verifyFalcoVersion(conf, nil); err == nil {
		t.Fatalf("FalcoVersion is nil but not detected as such")
	}

	conf.FalcoVersion = &supportedVersion
	if err := verifyFalcoVersion(conf, nil); err != nil {
		t.Fatalf("FalcoVersion was supported but detected as invalid")
	}

	if err := verifyFalcoVersionInVersions(conf, &falcoVersions); err != nil {
		t.Fatalf("Supported FalcoVersion is set but detected as invalid")
	}

	conf.FalcoVersion = &depreatedVersion
	if err := verifyFalcoVersionInVersions(conf, &falcoVersions); err != nil {
		t.Fatalf("Deprecated FalcoVersion without expiration is set but detected as invalid %s", err)
	}

	conf.FalcoVersion = &expiredVersion
	if err := verifyFalcoVersionInVersions(conf, &falcoVersions); err == nil {
		t.Fatalf("Expired FalcoVersion is set but accepted as valid")
	}

	nonVersion := "0.0.0"
	conf.FalcoVersion = &nonVersion
	if err := verifyFalcoVersionInVersions(conf, &falcoVersions); err == nil {
		t.Fatalf("Nonsensical FalcoVersion is set but accepted as valid")
	}

	oldConf := &service.FalcoServiceConfig{}
	conf.FalcoVersion = &expiredVersion
	oldConf.FalcoVersion = &expiredVersion
	if err := verifyFalcoVersion(conf, oldConf); err != nil {
		t.Fatalf("FalcoVersion was expired but stayed the same between old and new config")
	}

	conf.FalcoVersion = &expiredVersion
	oldConf.FalcoVersion = &supportedVersion
	if err := verifyFalcoVersion(conf, oldConf); err == nil {
		t.Fatalf("FalcoVersion was suppored but changed to expired between old and new config")
	}
}

func TestVerifyFalcoCtl(t *testing.T) {
	conf := &service.FalcoServiceConfig{}
	if err := verifyFalcoCtl(conf); err == nil {
		t.Fatalf("FalcoCtl is nil but not detected as such")
	}

	falcoCtlVal := service.FalcoCtl{}
	conf.FalcoCtl = &falcoCtlVal
	if err := verifyFalcoCtl(conf); err != nil {
		t.Fatalf("FalcoCtl is not nil but detected as such")
	}
}

func TestVerifyGardenerSet(t *testing.T) {
	conf := &service.FalcoServiceConfig{}
	if err := verifyGardenerSet(conf); err == nil {
		t.Fatalf("Gardener is nil but not detected as such")
	}

	gardenerVal := service.Gardener{}
	conf.Gardener = &gardenerVal
	if err := verifyGardenerSet(conf); err == nil {
		t.Fatalf("Gardener rules are nil but not detected as such")
	}

	commonRulesBool := false
	gardenerVal.UseFalcoRules, gardenerVal.UseFalcoIncubatingRules, gardenerVal.UseFalcoSandboxRules = &commonRulesBool, &commonRulesBool, &commonRulesBool
	if err := verifyGardenerSet(conf); err != nil {
		t.Fatalf("Gardener rules are not nil but detected as such")
	}
}

func TestVerifyProjectEligibility(t *testing.T) {
	namespace := "testNamespace"
	project := v1beta1.Project{}

	gardenProject := v1beta1.Project{}
	gardenProject.Name = "garden"

	ProjectsInstance = &Projects{}
	ProjectsInstance.projects = map[string]*v1beta1.Project{namespace: &project, constants.AlwaysEnabledProjects[0]: &gardenProject}

	if verifyProjectEligibility("wrongNamespace") {
		t.Fatalf("Project is nil but not detected as such")
	}

	if !verifyProjectEligibility(constants.AlwaysEnabledProjects[0]) {
		t.Fatalf("Always enabled project is not detected as such")
	}

	if verifyProjectEligibility(namespace) {
		t.Fatalf("Non annotated project is not detected as such")
	}

	project.Annotations = map[string]string{constants.ProjectEnableAnnotation: "true"}
	if !verifyProjectEligibility(namespace) {
		t.Fatalf("Annotated project is falsely detected non-elegible")
	}

	project.Annotations = map[string]string{constants.ProjectEnableAnnotation: "randoma.skjdnasdj"}
	if verifyProjectEligibility(namespace) {
		t.Fatalf("Falsely nnotated project is detected elegible")
	}
}
