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

	ManagedResourceNameFalcoSeed = ExtensionServiceName + "-seed"

	// Name of the chart deployed in control plane (seed)
	ManagedResourceNameFalcoChartSeed = ExtensionServiceName + "-chart-seed"

	// Name of the Falco certificate secret file in shoot namespace
	FalcoCertificatesSecretName = GardenerExtensionServiceName + "-certificates"

	// NamespaceKubeSystem kube-system namespace
	NamespaceKubeSystem = "kube-system"

	// FalcoChartname is the name of the Falco Helm chart to be deployed in shoot clusters
	FalcoChartname = "falco"

	FalcoServerCaKey  = "server-ca.key"
	FalcoServerCaCert = "server-ca.cert"
	FalcoClientCaKey  = "client-ca.key"
	FalcoClientCaCert = "client-ca.crt"

	FalcoServerKey  = "server.key"
	FalcoServerCert = "server.crt"
	FalcoClientKey  = "client.key"
	FalcoClientCert = "client.crt"

	DefaultCALifetime   = time.Hour * 24 * 365 * 2
	DefaultCARenewAfter = DefaultCALifetime - 60

	DefaultCertificateLifetime   = time.Hour * 24 * 180
	DefaultCertificateRenewAfter = DefaultCertificateLifetime - 30

	DefaultTokenLifetime = time.Hour * 24 * 7

	FalcoRules           = "falco_rules.yaml"
	FalcoIncubatingRules = "falco-incubating_rules.yaml"
	FalcoSandboxRules    = "falco-sandbox_rules.yaml"

	CustomRulesMaxSize = 1048576 // 1 << 20 == 1MiB

	ProjectEnableAnnotation = "falco.gardener.cloud/enabled"
)

var (
	AlwaysEnabledProjects = []string{"garden"}
	AllowedOutputs        = []string{"none", "cluster", "central", "custom"}

	// Default Event logger if not specified in controller configuration
	// (apis.Falco.DefaultEventLogger)
	DefaultEventLogger string = "central"
)
