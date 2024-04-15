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
	for i, rule := range config.RuleRefs {
		if rule == "" {
			allErrs = append(allErrs, field.Invalid(field.NewPath("ruleRefs["+strconv.Itoa(i)+"]"), "", "Rule reference is empty"))
		}
	}
	return allErrs
}

func isSupportedFalcoServiceVersion(_ string) bool {
	return true
}
