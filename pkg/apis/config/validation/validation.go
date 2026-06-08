// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"slices"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

// ValidateConfiguration validates the passed configuration.
func ValidateConfiguration(conf *config.Configuration) field.ErrorList {
	allErrs := field.ErrorList{}

	if conf.Falco != nil {
		allErrs = append(allErrs, validateFalco(conf.Falco, field.NewPath("falco"))...)
	}

	return allErrs
}

func validateFalco(falco *config.Falco, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateGlobalDefaultDestinations(falco.GlobalDefaultDestinations, fldPath.Child("globalDefaultDestinations"))...)

	return allErrs
}

func validateGlobalDefaultDestinations(gds []config.GlobalDefaultDestination, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	names := make(map[string]bool, len(gds))
	keys := make(map[string]string, len(gds))

	for i, gd := range gds {
		idxPath := fldPath.Index(i)

		if slices.Contains(constants.AllowedDestinations, gd.Name) {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("name"), gd.Name, "conflicts with standard destination name"))
		}

		if names[gd.Name] {
			allErrs = append(allErrs, field.Duplicate(idxPath.Child("name"), gd.Name))
		}
		names[gd.Name] = true

		if existing, ok := keys[gd.Key]; ok {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("key"), gd.Key, "already used by destination "+existing))
		}
		keys[gd.Key] = gd.Name
	}

	return allErrs
}
