// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"strconv"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

func ValidateFalcoServiceConfig(config *service.FalcoServiceConfig) field.ErrorList {
	allErrs := field.ErrorList{}
	if !isSupportedFalcoServiceVersion(*config.FalcoVersion) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("falcoVersion"), *config.FalcoVersion, "Falco version is not supported"))
	}
	if config.Resources != "gardener" && config.Resources != "falcoctl" {
		allErrs = append(allErrs, field.Invalid(field.NewPath("resources"), "", `resources must be set to "gardener" or "falcoctl"`))
		// no point to continue here
		return allErrs
	}
	if config.Resources == "gardener" {
		ruleRefs := config.Gardener.RuleRefs
		for i, rule := range ruleRefs {
			if rule.Ref == "" {
				allErrs = append(allErrs, field.Invalid(field.NewPath("gardener.ruleRefs["+strconv.Itoa(i)+"]"), "", "Rule reference is empty"))
			}
		}
	}
	return allErrs
}

func isSupportedFalcoServiceVersion(_ string) bool {
	return true
}
