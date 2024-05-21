// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

import "time"

const (
	// ExtensionType is the name of the extension type.
	ExtensionType = "shoot-falco-service"

	// ServiceName is the name of the service.
	ServiceName                  = ExtensionType
	ExtensionServiceName         = "extension-" + ServiceName
	GardenerExtensionServiceName = "gardener-" + ExtensionServiceName

	// ManagedResourceNamesControllerSeed is the name used to describe the managed seed resources for the controller.
	ManagedResourceNameFalco = ExtensionServiceName + "-shoot"

	// Name of the Falco certificate secret file in shoot namespace
	FalcoCertificatesSecretName = "falco-certificates"

	// NamespaceKubeSystem kube-system namespace
	NamespaceKubeSystem = "kube-system"

	// FalcoChartname is the name of the Falco Helm chart to be deployed in shoot clusters
	FalcoChartname = "falco"

	FalcoServerCaKey  = "ca.key"
	FalcoServerCaCert = "ca.cert"
	FalcoClientCaKey  = "client-ca.key"
	FalcoClientCaCert = "client-ca.crt"

	DefaultCertificateLifetime   = time.Hour * 24 * 365
	DefaultCertificateRenewAfter = time.Hour * 24 * 30
	DefaultTokenLifetime         = time.Hour * 24 * 7

	FalcoRules           = "falco_rules.yaml"
	FalcoIncubatingRules = "falco-incubating_rules.yaml"
	FalcoSandboxRules    = "falco-sandbox_rules.yaml"
)
