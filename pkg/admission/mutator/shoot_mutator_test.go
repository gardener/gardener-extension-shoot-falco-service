// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"context"
	"testing"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	sigsmanager "sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	serviceinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/install"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

var (
	profileManager1 = profile.GetDummyFalcoProfileManager(
		&map[string]profile.FalcoVersion{
			"0.99.0": {
				Version:        "0.99.0",
				Classification: "supported",
			},
			"0.100.0": {
				Version:        "0.100.0",
				Classification: "supported",
			},
			"0.101.0": {
				Version:        "0.101.0",
				Classification: "preview",
			},
		},
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
	)

	mutate1 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1"
	}`

	expectedMutate1 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
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

	mutate2 = ""

	expectedMutate2 = expectedMutate1

	mutate3 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
		"destinations": [
			{
				"name": "logging"
			}
		]
	}`

	expectedMutate3 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
		"rules": {
			"standard": ["falco-rules"]
		},
		"destinations": [
			{
				"name": "logging"
			}
		]
	}`

	mutate4 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
		"rules": {
			"standard": [
		    	"falco-rules"
			]
		}
	}`

	expectedMutate4 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
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

	mutate5 = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"aufoUpdate": true
	}`

	mutate6 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
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

	expectedMutate6 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
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

	mutate7 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"rules": {
			"standard": [
		    	"falco-rules",
				"falco-incubating-rules",
				"falco-sandbox-rules"
			]
		},
		"destinations": [
			{
				"name": "logging"
			}
		]
	}`

	expectedMutate7 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
		"rules": {
			"standard": [
		    	"falco-rules",
				"falco-incubating-rules",
				"falco-sandbox-rules"
			]
		},
		"destinations": [
			{
				"name": "logging"
			}
		]
	}`

	mutate8 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"rules": {
			"standard": [
		    	"falco-rules",
				"falco-incubating-rules",
				"falco-sandbox-rules-broken",
				"additional-broken-rule"
			]
		},
		"destinations": [
			{
				"name": "logging"
			}
		]
	}`

	expectedMutate8 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
		"rules": {
			"standard": [
		    	"falco-rules",
				"falco-incubating-rules",
				"falco-sandbox-rules-broken",
				"additional-broken-rule"
			]
		},
		"destinations": [
			{
				"name": "logging"
			}
		]
	}`

	mutate9 = `
	{
		"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
		"kind": "FalcoServiceConfig",
		"falcoVersion": "0.100.0"
	}`

	expectedMutate9 = `
	{
		"kind":"FalcoServiceConfig",
		"apiVersion":"falco.extensions.gardener.cloud/v1alpha1",
		"falcoVersion":"0.100.0",
		"autoUpdate": true,
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

	genericEmptyConf = &gardencorev1beta1.Shoot{
		Spec: gardencorev1beta1.ShootSpec{
			Extensions: []gardencorev1beta1.Extension{
				{
					Type:     "shoot-falco-service",
					Disabled: boolValue(false),
				},
			},
		},
	}

	genericShoot = &gardencorev1beta1.Shoot{
		Spec: gardencorev1beta1.ShootSpec{
			Extensions: []gardencorev1beta1.Extension{
				{
					Type:           "shoot-falco-service",
					Disabled:       boolValue(false),
					ProviderConfig: &runtime.RawExtension{},
				},
			},
		},
	}
)

func TestSetAutoUpdate(t *testing.T) {
	falcoConf := &service.FalcoServiceConfig{}
	setAutoUpdate(falcoConf)
	if falcoConf.AutoUpdate == nil {
		t.Error("Autoupdate not set")
	} else if !*falcoConf.AutoUpdate {
		t.Error("AutoUpdate not set to default true")
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
	versions := &map[string]profile.FalcoVersion{
		"0.99.0": {
			Version:        "0.99.0",
			Classification: "supported",
		},
	}

	falcoConf := &service.FalcoServiceConfig{}
	profile.GetDummyFalcoProfileManager(
		versions,
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
	)

	err := setFalcoVersion(falcoConf)
	if err != nil {
		t.Error("Could not find supported FalcoVersion")
	}

	if falcoConf.FalcoVersion == nil {
		t.Error("FalcoVersion not set")
	}

	dummyVersion := "0.0.0"
	falcoConf.FalcoVersion = &dummyVersion
	if err = setFalcoVersion(falcoConf); err != nil {
		t.Error("FalcoVersion was set but possibly overwritten")
	}

	// Test no falco version
	falcoConf.FalcoVersion = nil
	profile.GetDummyFalcoProfileManager(
		&map[string]profile.FalcoVersion{},
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
		&map[string]profile.Version{},
		&map[string]profile.Image{},
	)
	if err = setFalcoVersion(falcoConf); err == nil {
		t.Error("Set version even though none was provided")
	}
}

func TestChooseHighestVersion(t *testing.T) {
	dummyClassification := "test"
	highVersion := "1.2.3"
	lowVersion := "0.0.0"
	highV := profile.FalcoVersion{Version: highVersion, Classification: dummyClassification}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification}

	falcoVersions := map[string]profile.FalcoVersion{lowVersion: lowV, highVersion: highV}

	vers, err := chooseHighestVersion(falcoVersions, dummyClassification)

	if err != nil {
		t.Errorf("Failed to find highest version: %s", err.Error())
	}

	if *vers != highVersion {
		t.Errorf("Falsely reported version %s as highest", *vers)
	}

	falcoVersions = map[string]profile.FalcoVersion{}
	_, err = chooseHighestVersion(falcoVersions, dummyClassification)
	if err == nil {
		t.Errorf("Failed to detect no version found for classification")
	}

	brokenV := profile.FalcoVersion{Version: "broken", Classification: dummyClassification}
	falcoVersions["broken"] = brokenV
	_, err = chooseHighestVersion(falcoVersions, dummyClassification)
	if err == nil {
		t.Errorf("Failed to detect broken version")
	}
}

func TestChooseLowestVersionHigherThanCurrent(t *testing.T) {
	dummyClassification := "test"
	highVersion := "1.2.3"
	midVersion := "1.0.0"
	lowVersion := "0.0.0"
	highV := profile.FalcoVersion{Version: highVersion, Classification: dummyClassification}
	midV := profile.FalcoVersion{Version: midVersion, Classification: dummyClassification}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification}
	falcoVersions := map[string]profile.FalcoVersion{highVersion: highV, lowVersion: lowV, midVersion: midV}

	vers, err := chooseLowestVersionHigherThanCurrent(lowVersion, falcoVersions, []string{dummyClassification})
	if err != nil {
		t.Errorf("Failed to find lowest version higher than current: %s", err.Error())
	}

	if *vers != midVersion {
		t.Errorf("Falsely reported version %s as lowest higher than current version %s", *vers, lowVersion)
	}

	vers, err = chooseLowestVersionHigherThanCurrent(lowVersion, falcoVersions, []string{dummyClassification})
	if err != nil {
		t.Errorf("Failed to find lowest version higher than current: %s", err.Error())
	}

	if *vers != midVersion {
		t.Errorf("Falsely reported version %s as lowest higher than current version %s", *vers, lowVersion)
	}

	_, err = chooseLowestVersionHigherThanCurrent(highVersion, falcoVersions, []string{dummyClassification})
	if err == nil {
		t.Errorf("Found higher version than even though no higher version is present: %s", highVersion)
	}

	brokenS := ""
	_, err = chooseLowestVersionHigherThanCurrent(brokenS, falcoVersions, []string{dummyClassification})
	if err == nil {
		t.Errorf("Failed to detect broken current version")
	}

	// Test for empty versions
	falcoVersions = map[string]profile.FalcoVersion{}
	_, err = chooseLowestVersionHigherThanCurrent(lowVersion, falcoVersions, []string{dummyClassification})
	if err == nil {
		t.Errorf("Failed to detect no version found for classification")
	}

	// Test for broken version in the available versions
	brokenS = "broken"
	brokenV := profile.FalcoVersion{Version: brokenS, Classification: dummyClassification}
	falcoVersions[brokenS] = brokenV
	_, err = chooseLowestVersionHigherThanCurrent(lowVersion, falcoVersions, []string{dummyClassification})
	if err == nil {
		t.Errorf("Failed to detect broken version in available version")
	}
}

func TestSortVersionWithClassification(t *testing.T) {
	// Testing non existent classification
	dummyClassification := "test"
	lowVersion := "0.0.0"
	expiredVersion := "1.1.1"
	expiryDate := time.Time{}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification}
	expV := profile.FalcoVersion{Version: expiredVersion, Classification: dummyClassification, ExpirationDate: &expiryDate}
	falcoVersions := map[string]profile.FalcoVersion{lowVersion: lowV, expiredVersion: expV}

	// Check wrong classification
	sorted, _ := sortVersionsWithClassification(falcoVersions, []string{"wrong"})
	if sorted != nil {
		t.Errorf("Returned sorted versions with non-matching classification")
	}

	// Check one expired classification
	sorted, _ = sortVersionsWithClassification(falcoVersions, []string{dummyClassification})
	if len(sorted) != 1 {
		t.Errorf("Sort inlcudes expired version")
	}
}

func TestGetAutoUpdateVersion(t *testing.T) {
	dummyClassification := "supported"
	veryhighVersion := "3.2.3"
	highVersion := "1.2.3"
	midVersion := "1.0.0"
	lowVersion := "0.0.0"
	vHighV := profile.FalcoVersion{Version: veryhighVersion, Classification: "deprecated"}
	highV := profile.FalcoVersion{Version: highVersion, Classification: "deprecated", ExpirationDate: &time.Time{}}
	midV := profile.FalcoVersion{Version: midVersion, Classification: dummyClassification}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification}
	falcoVersions := map[string]profile.FalcoVersion{highVersion: highV, lowVersion: lowV, midVersion: midV, veryhighVersion: vHighV}

	vers, err := GetAutoUpdateVersion(falcoVersions)
	if err != nil {
		t.Errorf("Could not get auto update version %s", err.Error())
	}
	if vers == nil || *vers != midVersion {
		t.Errorf("Did not return expected version %s but %v", midVersion, vers)
	}
}

func TestGetForceUpdateVersionHigherVersionPresent(t *testing.T) {
	dummyClassification := "supported"
	veryhighVersion := "3.2.3"
	highVersion := "1.2.3"
	midVersion := "1.0.0"
	lowVersion := "0.0.0"
	vHighV := profile.FalcoVersion{Version: veryhighVersion, Classification: dummyClassification}
	highV := profile.FalcoVersion{Version: highVersion, Classification: "deprecated", ExpirationDate: &time.Time{}}
	midV := profile.FalcoVersion{Version: midVersion, Classification: dummyClassification}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification}
	falcoVersions := map[string]profile.FalcoVersion{highVersion: highV, lowVersion: lowV, midVersion: midV, veryhighVersion: vHighV}

	vers, err := GetForceUpdateVersion(lowVersion, falcoVersions)
	if err != nil {
		t.Errorf("Could not get auto update version %s", err.Error())
	}
	if vers == nil || *vers != midVersion {
		t.Errorf("Did not return expected version %s but %v", midVersion, vers)
	}
}

func TestGetForceUpdateVersionNoHigherVersionPresent(t *testing.T) {
	dummyClassification := "supported"
	highVersion := "1.2.3"
	midVersion := "1.0.0"
	lowVersion := "0.0.0"
	highV := profile.FalcoVersion{Version: highVersion, Classification: "deprecated", ExpirationDate: &time.Time{}}
	midV := profile.FalcoVersion{Version: midVersion, Classification: "deprecated", ExpirationDate: &time.Time{}}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification}
	falcoVersions := map[string]profile.FalcoVersion{highVersion: highV, lowVersion: lowV, midVersion: midV}

	vers, err := GetForceUpdateVersion(midVersion, falcoVersions)
	if err != nil {
		t.Errorf("Could not get auto update version %s", err.Error())
	}

	if *vers != lowVersion {
		t.Errorf("Did not return expected version %s but %v", midVersion, *vers)
	}
}

func TestGetForceUpdateVersionNoVersionFound(t *testing.T) {
	dummyClassification := "deprecated"
	highVersion := "1.2.3"
	midVersion := "1.0.0"
	lowVersion := "0.0.0"
	highV := profile.FalcoVersion{Version: highVersion, Classification: dummyClassification, ExpirationDate: &time.Time{}}
	midV := profile.FalcoVersion{Version: midVersion, Classification: dummyClassification, ExpirationDate: &time.Time{}}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification, ExpirationDate: &time.Time{}}
	falcoVersions := map[string]profile.FalcoVersion{highVersion: highV, lowVersion: lowV, midVersion: midV}

	if _, err := GetForceUpdateVersion(midVersion, falcoVersions); err == nil {
		t.Errorf("Found version for force update by all versions are expired")
	}
}

func TestChooseHighestVersionLowerThanCurrent(t *testing.T) {
	// Empty version
	if _, err := chooseHighestVersionLowerThanCurrent("0.0.0", map[string]profile.FalcoVersion{}); err == nil {
		t.Error("Empty version map did not lead to error")
	}

	// Nonsensical version in available version
	nonesenseVersion := "garba.ge"
	nonesenseV := profile.FalcoVersion{Version: nonesenseVersion, Classification: "supported"}
	falcoVersions := map[string]profile.FalcoVersion{nonesenseVersion: nonesenseV}
	if _, err := chooseHighestVersionLowerThanCurrent("0.0.0", falcoVersions); err == nil {
		t.Error("Empty version map did not lead to error")
	}

	// Nonesenscial current version
	goodVersion := "0.0.0"
	goodV := profile.FalcoVersion{Version: goodVersion, Classification: "supported"}
	falcoVersions = map[string]profile.FalcoVersion{goodVersion: goodV}
	if _, err := chooseHighestVersionLowerThanCurrent(nonesenseVersion, falcoVersions); err == nil {
		t.Error("Empty version map did not lead to error")
	}

	dummyClassification := "supported"
	highVersion := "1.2.3"
	midVersion := "1.0.0"
	lowVersion := "0.0.0"
	highV := profile.FalcoVersion{Version: highVersion, Classification: dummyClassification}
	midV := profile.FalcoVersion{Version: midVersion, Classification: dummyClassification}
	lowV := profile.FalcoVersion{Version: lowVersion, Classification: dummyClassification}
	falcoVersions = map[string]profile.FalcoVersion{highVersion: highV, lowVersion: lowV, midVersion: midV}

	currentVersion := "1.1.1"
	if ver, err := chooseHighestVersionLowerThanCurrent(currentVersion, falcoVersions); err != nil || *ver != midVersion {
		t.Errorf("Falsesly reported version %v to be maximum lower version than %s", *ver, currentVersion)
	}

}

var _ = Describe("Test mutator", Label("mutator"), func() {

	It("mutate for the smallest possible config", func(ctx SpecContext) {
		managerOptions := sigsmanager.Options{}
		mgr, err := sigsmanager.New(&rest.Config{}, managerOptions)
		Expect(err).To(BeNil(), "Manager could not be created")
		err = serviceinstall.AddToScheme(mgr.GetScheme())
		Expect(err).To(BeNil(), "Scheme could not be added")
		mutator := NewShootMutator(mgr)

		setProfileManager(profileManager1)

		f := func(extensionSpec string) error {
			providerConfig := genericShoot.Spec.Extensions[0].ProviderConfig
			providerConfig.Raw = []byte(extensionSpec)
			err = mutator.Mutate(context.TODO(), genericShoot, nil)
			return err
		}

		err = mutator.Mutate(context.TODO(), genericEmptyConf, nil)
		Expect(err).To(BeNil(), "Mutator failed")
		result := genericEmptyConf.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate1), "Mutator did not return expected result")

		err = f(mutate1)
		Expect(err).To(BeNil(), "Mutator failed")
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate1), "Mutator did not return expected result")

		err = f(mutate2)
		Expect(err).To(BeNil(), "Mutator failed")
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate2), "Mutator did not return expected result")

		err = f(mutate3)
		Expect(err).To(BeNil(), "Mutator failed")
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate3), "Mutator did not return expected result")

		err = f(mutate4)
		Expect(err).To(BeNil(), "Mutator failed")
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate4), "Mutator did not return expected result")

		err = f(mutate5)
		Expect(err).To(Not(BeNil()), "Mutator failed")
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(ContainSubstring("aufoUpdate"), "Mutator did not return expected result")

		err = f(mutate6)
		Expect(err).To(BeNil(), "Mutator failed", err)
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate6), "Mutator did not return expected result")

		err = f(mutate7)
		Expect(err).To(BeNil(), "Mutator failed", err)
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate7), "Mutator did not return expected result")

		err = f(mutate8)
		Expect(err).To(BeNil(), "Mutator failed", err)
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate8), "Mutator did not return expected result")

		err = f(mutate9)
		Expect(err).To(BeNil(), "Mutator failed", err)
		result = genericShoot.Spec.Extensions[0].ProviderConfig.Raw
		Expect(result).To(MatchJSON(expectedMutate9), "Mutator did not return expected result")

	})
})
