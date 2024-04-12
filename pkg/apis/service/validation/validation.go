// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

func ValidateFalcoServiceConfig(config *service.FalcoServiceConfig) field.ErrorList {
	allErrs := field.ErrorList{}
	// TODO
	return allErrs
}
