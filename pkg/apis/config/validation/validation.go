// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/util/validation"
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
	allErrs = append(allErrs, validateAdditionalConfig(falco.Additional, fldPath.Child("additional"))...)

	if falco.ClusterIdentityToken != nil {
		allErrs = append(allErrs, validateClusterIdentityToken(falco.ClusterIdentityToken, fldPath.Child("clusterIdentityToken"))...)
	}

	return allErrs
}

func validateClusterIdentityToken(cfg *config.ClusterIdentityTokenConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if cfg.TokenIssuerPrivateKey == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("tokenIssuerPrivateKey"), "must be set when clusterIdentityToken is configured"))
		return allErrs
	}

	if err := validateRSAPrivateKey(cfg.TokenIssuerPrivateKey); err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("tokenIssuerPrivateKey"), "<redacted>", err.Error()))
	}

	return allErrs
}

func validateRSAPrivateKey(keyPEM string) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("must be a PEM-encoded RSA private key (expected block type \"RSA PRIVATE KEY\")")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	return nil
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

		if existing, ok := keys[gd.FalcosidekickOutput.Key]; ok {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("falcosidekickOutput").Child("key"), gd.FalcosidekickOutput.Key, "already used by destination "+existing))
		}
		keys[gd.FalcosidekickOutput.Key] = gd.Name
	}

	return allErrs
}

func validateAdditionalConfig(additional *config.AdditionalConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if additional == nil {
		return allErrs
	}

	names := make(map[string]bool, len(additional.SeedManagedResources))

	for i, res := range additional.SeedManagedResources {
		idxPath := fldPath.Child("seedManagedResources").Index(i)

		if res.Name == "" {
			allErrs = append(allErrs, field.Required(idxPath.Child("name"), "name must not be empty"))
		} else {
			if errs := validation.IsDNS1123Label(res.Name); len(errs) > 0 {
				allErrs = append(allErrs, field.Invalid(idxPath.Child("name"), res.Name, "must be a valid DNS label: "+errs[0]))
			}

			if names[res.Name] {
				allErrs = append(allErrs, field.Duplicate(idxPath.Child("name"), res.Name))
			}
			names[res.Name] = true
		}

		if res.Helm.OCIRepository.Ref == nil || *res.Helm.OCIRepository.Ref == "" {
			allErrs = append(allErrs, field.Required(idxPath.Child("helm").Child("ociRepository").Child("ref"), "OCI repository ref must not be empty"))
		}
	}

	return allErrs
}
