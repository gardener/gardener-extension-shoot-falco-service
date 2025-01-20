// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	"fmt"
	"regexp"

	v1beta1gardener "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
)

// technicalIDPattern addresses the ambiguity that one or two dashes could follow the prefix "shoot" in the technical ID of the shoot.
var technicalIDPattern = regexp.MustCompile(fmt.Sprintf("^%s-?", v1beta1constants.TechnicalIDPrefix))

// ComputeValiHost computes the host for vali ingress.
func ComputeValiHost(shoot v1beta1gardener.Shoot, seed v1beta1gardener.Seed) string {
	var seedIngressDomain string
	shortID := technicalIDPattern.ReplaceAllString(shoot.Status.TechnicalID, "")
	if seed.Spec.Ingress != nil {
		seedIngressDomain = seed.Spec.Ingress.Domain
	}
	return fmt.Sprintf("v-%s.%s", shortID, seedIngressDomain)
}
