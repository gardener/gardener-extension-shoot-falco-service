// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_Configuration sets default values for Configuration objects.
func SetDefaults_Configuration(obj *Configuration) {
	if obj.Falco != nil && obj.Falco.Additional != nil {
		for i := range obj.Falco.Additional.SeedManagedResources {
			if obj.Falco.Additional.SeedManagedResources[i].Namespace == "" {
				obj.Falco.Additional.SeedManagedResources[i].Namespace = "falco-splunk-ingestor"
			}
		}
	}
}
