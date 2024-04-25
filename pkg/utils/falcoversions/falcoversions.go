// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falcoversions

import (
	im "github.com/gardener/gardener/pkg/utils/imagevector"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"
)

func ReadFalcoVersions(buf []byte) (*FalcoVersions, error) {
	vector := FalcoVersions{}

	if err := yaml.Unmarshal(buf, &vector); err != nil {
		return nil, err
	}

	if errs := ValidateFalcoVersionsVector(&vector); len(errs) > 0 {
		return nil, errs.ToAggregate()
	}

	return &vector, nil
}

func ValidateFalcoVersionsVector(versions *FalcoVersions) field.ErrorList {
	return field.ErrorList{}
}

func ReadFalcosidekickVersions(buf []byte) (*FalcosidekickVersions, error) {
	vector := FalcosidekickVersions{}

	if err := yaml.Unmarshal(buf, &vector); err != nil {
		return nil, err
	}

	if errs := ValidateFalcosidekickVersionsVector(&vector); len(errs) > 0 {
		return nil, errs.ToAggregate()
	}

	return &vector, nil
}

func ValidateFalcosidekickVersionsVector(versions *FalcosidekickVersions) field.ErrorList {
	return field.ErrorList{}
}

func GetImageForVersion(images im.ImageVector, image string, version string) *im.ImageSource {

	for _, is := range images {
		if is.Name == image && *is.Version == version {
			return is
		}
	}
	return nil
}
