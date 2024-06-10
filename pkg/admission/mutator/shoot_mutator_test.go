// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"testing"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils/falcoversions"
)

func TestSetWebhook(t *testing.T) {
	falcoConf := &service.FalcoServiceConfig{}
	setCustomWebhook(falcoConf)
	if falcoConf.CustomWebhook == nil {
		t.Error("CustomWebhook not set")
	} else if falcoConf.CustomWebhook.Enabled == nil || *falcoConf.CustomWebhook.Enabled {
		t.Error("CustomWebhook enabled but should be disabled by default")
	}
}

func TestSetFalcoCtl(t *testing.T) {
	falcoConf := &service.FalcoServiceConfig{}
	setFalcoCtl(falcoConf)
	if falcoConf.FalcoCtl == nil {
		t.Error("FalcoCtl not set")
	}
}

func TestSetResources(t *testing.T) {
	falcoConf := &service.FalcoServiceConfig{}
	setResources(falcoConf)
	if falcoConf.Resources == nil {
		t.Error("Resources not set")
	} else if *falcoConf.Resources != "gardener" {
		t.Error("Resources not set to default gardener")
	}
}

func TestSetAutoUpdate(t *testing.T) {
	falcoConf := &service.FalcoServiceConfig{}
	setAutoUpdate(falcoConf)
	if falcoConf.AutoUpdate == nil {
		t.Error("Autoupdate not set")
	} else if !*falcoConf.AutoUpdate {
		t.Error("AutoUpdate not set to default true")
	}
}

func TestSetGardenerRules(t *testing.T) {
	falcoConf := &service.FalcoServiceConfig{}
	setGardenerRules(falcoConf)
	if falcoConf.Gardener == nil {
		t.Error("Gardener rules not set")
	}

	if falcoConf.Gardener.UseFalcoRules == nil {
		t.Error("UseFalcoRules not set to default true")
	} else if !*falcoConf.Gardener.UseFalcoRules {
		t.Error("UseFalcoRules not set to default true")
	}

	if falcoConf.Gardener.UseFalcoSandboxRules == nil {
		t.Error("UseFalcoSandboxRules not set to default true")
	} else if *falcoConf.Gardener.UseFalcoSandboxRules {
		t.Error("UseFalcoRules not set to default false")
	}

	if falcoConf.Gardener.UseFalcoIncubatingRules == nil {
		t.Error("UseFalcoIncubatingRules not set to default true")
	} else if *falcoConf.Gardener.UseFalcoIncubatingRules {
		t.Error("UseFalcoIncubatingRules not set to default false")
	}
}

func TestExtensionIsDisabled(t *testing.T) {
	disabledSet := false
	exampleShoot := &gardencorev1beta1.Shoot{
		Spec: gardencorev1beta1.ShootSpec{
			Extensions: []gardencorev1beta1.Extension{
				{Type: "shoot-falco-service", Disabled: &disabledSet},
			},
		},
	}

	s := &Shoot{}
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

	exampleShoot.Spec.Extensions = []gardencorev1beta1.Extension{}
	disabled = s.isDisabled(exampleShoot)
	if !disabled {
		t.Error("No extension is present but reported found")
	}

	exampleShoot.DeletionTimestamp = &v1.Time{}
	disabled = s.isDisabled(exampleShoot)
	if !disabled {
		t.Error("Extension reported found but shoot marked as to be deleted")
	}

	exampleShoot.DeletionTimestamp = nil
	exampleShoot.Status.LastOperation = &gardencorev1beta1.LastOperation{
		Type:  gardencorev1beta1.LastOperationTypeReconcile,
		State: gardencorev1beta1.LastOperationStateProcessing,
	}
	disabled = s.isDisabled(exampleShoot)
	if !disabled {
		t.Error("Extension reported found but shoot in reconcile processing state")
	}
}

func TestSetFalcoVersion(t *testing.T) {
	falcoConf := &service.FalcoServiceConfig{}

	err := setFalcoVersion(falcoConf)
	if err != nil {
		t.Error("Could not find supported FalcoVersion")
	}

	if falcoConf.FalcoVersion == nil {
		t.Error("FalcoVersion not set")
	}

	dummyVersion := "0.0.0"
	falcoConf.FalcoVersion = &dummyVersion
	err = setFalcoVersion(falcoConf)
	if err != nil {
		t.Error("FalcoVersion was set but possibly overwritten")
	}
}

func TestChooseHighestVersion(t *testing.T) {
	dummyClassification := "test"
	highVersion := "1.2.3"
	highV := falcoversions.FalcoVersion{Version: highVersion, Classification: dummyClassification}
	lowV := falcoversions.FalcoVersion{Version: "0.0.0", Classification: dummyClassification}
	falcoVersions := falcoversions.FalcoVersions{FalcoVersions: []falcoversions.FalcoVersion{highV, lowV}}

	vers, err := ChooseHighestVersion(&falcoVersions, dummyClassification)
	if err != nil {
		t.Errorf("Failed to find highest version: %s", err.Error())
	}

	if *vers != highVersion {
		t.Errorf("Falsely reported version %s as highest", *vers)
	}

	falcoVersions = falcoversions.FalcoVersions{FalcoVersions: []falcoversions.FalcoVersion{}}
	_, err = ChooseHighestVersion(&falcoVersions, dummyClassification)
	if err == nil {
		t.Errorf("Failed to detect no version found for classification")
	}

	brokenV := falcoversions.FalcoVersion{Version: "broken", Classification: dummyClassification}
	falcoVersions = falcoversions.FalcoVersions{FalcoVersions: []falcoversions.FalcoVersion{brokenV}}
	_, err = ChooseHighestVersion(&falcoVersions, dummyClassification)
	if err == nil {
		t.Errorf("Failed to detect broken version")
	}

}
