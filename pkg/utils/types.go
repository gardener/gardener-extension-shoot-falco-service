// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
)

type ReconcileContext struct {
	Namespace               string
	ExtensionClass          *extensionsv1alpha1.ExtensionClass
	TargetClusterK8sVersion string
	ResourceSection         []gardenerv1beta1.NamedResourceReference
	ClusterIdentity         *string
	FalcoServiceConfig      *apisservice.FalcoServiceConfig
	ShootTechnicalId        string
	SeedIngressDomain       string
	ClusterName             string
	IsSeedDeployment        bool
	IsShootDeployment       bool
	IsGardenDeployment      bool
}
