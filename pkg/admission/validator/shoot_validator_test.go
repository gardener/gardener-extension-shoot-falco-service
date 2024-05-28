// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

func getDeprecatedAndSupportedVersions() (*string, *string, error) {
	versions := falco.FalcoVersions().Falco
	var deprecated, supported string
	for _, ver := range versions.FalcoVersions {
		if deprecated == "" && ver.Classification == "deprecated" {
			deprecated = ver.Version
		}
		if supported == "" && ver.Classification == "supported" {
			supported = ver.Version
		}
	}

	var errSup, errDep error
	if supported == "" {
		errSup = fmt.Errorf("no supported FalcoVersion found")
	}
	if deprecated == "" {
		errDep = fmt.Errorf("no deprecated FalcoVersion found")
	}
	err := errors.Join(errSup, errDep)

	return &supported, &deprecated, err
}

func TestVerifyFalcoVersion(t *testing.T) {
	conf := &service.FalcoServiceConfig{}
	if err := verifyFalcoVersion(conf); err == nil {
        t.Fatalf("falcoversion is nil but not detected as such")
	}

	supported, deprecated, err := getDeprecatedAndSupportedVersions()
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	conf.FalcoVersion = supported
	if err := verifyFalcoVersion(conf); err != nil {
        t.Fatalf("Supported FalcoVersion is set but detected as invalid")
	}

	conf.FalcoVersion = deprecated
	if err := verifyFalcoVersion(conf); err == nil {
        t.Fatalf("Deprecated FalcoVersion is set but accepted as valid")
	}

	nonVersion := "0.0.0"
	conf.FalcoVersion = &nonVersion
	if err := verifyFalcoVersion(conf); err == nil {
        t.Fatalf("Nonsensical FalcoVersion is set but accepted as valid")
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
	gardenerVal.UseFalcoRules, gardenerVal.UseFalcoIncubatingRules, gardenerVal.UseFalcoSandboxRules = &commonRulesBool,  &commonRulesBool,  &commonRulesBool
	if err := verifyGardenerSet(conf); err != nil {
        t.Fatalf("Gardener rules are not nil but detected as such")
	}
}
