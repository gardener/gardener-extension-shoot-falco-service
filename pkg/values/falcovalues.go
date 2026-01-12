// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package values

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	semver3 "github.com/Masterminds/semver/v3"
	"github.com/go-logr/logr"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils"
)

var (
	versions falco.Falco
)

func init() {
	versions = falco.FalcoVersions()
}

type ConfigBuilder struct {
	client      client.Client
	config      *config.Configuration
	tokenIssuer *secrets.TokenIssuer
	profile     *profile.FalcoProfileManager
}

type customRulesFile struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}
type customRuleRef struct {
	RefName       string
	ConfigMapName string
}

type falcoOutputConfig struct {
	key   string
	value map[string]interface{}
}

func NewConfigBuilder(client client.Client, tokenIssuer *secrets.TokenIssuer, config *config.Configuration, profile *profile.FalcoProfileManager) *ConfigBuilder {
	return &ConfigBuilder{
		client:      client,
		config:      config,
		tokenIssuer: tokenIssuer,
		profile:     profile,
	}
}

func (c *ConfigBuilder) BuildFalcoValues(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext) (map[string]any, error) {

	// images
	falcoServiceConfig := reconcileCtx.FalcoServiceConfig
	falcoVersion := falcoServiceConfig.FalcoVersion
	falcoImage, err := c.getImageForVersion("falco", *falcoVersion)
	if err != nil {
		return nil, err
	}

	falcoOutputConfigs := make([]falcoOutputConfig, 0)
	falcoStdoutLog := false

	if falcoServiceConfig.Destinations == nil || len(*falcoServiceConfig.Destinations) == 0 {
		return nil, fmt.Errorf("no destinations configured")
	}

	// priority class names are different in infrastructure clusters
	var priorityClassName string
	if reconcileCtx.IsShootDeployment {
		priorityClassName = *c.config.Falco.PriorityClassName
	} else if reconcileCtx.IsSeedDeployment {
		priorityClassName = "gardener-system-900"
	}

	for _, dest := range *falcoServiceConfig.Destinations {
		switch dest.Name {
		case constants.FalcoEventDestinationStdout:
			falcoStdoutLog = true

		case constants.FalcoEventDestinationLogging:
			valiHost := utils.ComputeValiHost(reconcileCtx.ShootTechnicalId, reconcileCtx.SeedIngressDomain)
			loki := map[string]interface{}{
				"hostport":  "https://" + valiHost,
				"endpoint":  "/vali/api/v1/push",
				"format":    "json",
				"checkcert": false,
				"customheaders": map[string]string{
					"Authorization": "Bearer LOKI_TOKEN",
				},
			}
			outputConfig := falcoOutputConfig{
				key:   "loki",
				value: loki,
			}
			falcoOutputConfigs = append(falcoOutputConfigs, outputConfig)

		case constants.FalcoEventDestinationOTLP:
			otlpHost := utils.ComputeOTLPHost(reconcileCtx.ShootTechnicalId, reconcileCtx.SeedIngressDomain)
			otlp := map[string]any{
				"logs": map[string]any{
					"endpoint":  "https://" + otlpHost + "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
					"protocol":  "grpc",
					"headers":   "Authorization=Bearer OTLP_TOKEN",
					"checkcert": false,
				},
				// bug in falcosidekick
				"traces": map[string]string{
					"checkcert": "false",
				},
			}
			outputConfig := falcoOutputConfig{
				key:   "otlp",
				value: otlp,
			}
			falcoOutputConfigs = append(falcoOutputConfigs, outputConfig)

		case constants.FalcoEventDestinationCustom:
			webhook := map[string]any{}
			secret, err := c.loadCustomWebhookSecret(ctx, log, reconcileCtx, *dest.ResourceSecretName)
			if err != nil {
				return nil, err
			}
			if address, ok := secret.Data["address"]; ok {
				webhook["address"] = string(address)
			} else {
				return nil, fmt.Errorf("custom webhook address is missing")
			}
			if method, ok := secret.Data["method"]; ok {
				webhook["method"] = string(method)
			} else {
				webhook["method"] = "POST"
			}
			if customHeaders, ok := secret.Data["customheaders"]; ok {
				customHeadersMap := map[string]string{}
				if err := yaml.Unmarshal(customHeaders, &customHeadersMap); err != nil {
					return nil, fmt.Errorf("failed to parse custom headers: %w", err)
				}
				webhook["customheaders"] = customHeadersMap
			}
			if checkcerts, ok := secret.Data["checkcerts"]; ok {
				checkcertsBool, err := strconv.ParseBool(string(checkcerts))
				if err != nil {
					return nil, fmt.Errorf("failed to parse checkcerts value: %w", err)
				}
				webhook["checkcert"] = checkcertsBool
			} else {
				webhook["checkcert"] = true
			}
			outputConfig := falcoOutputConfig{
				key:   "webhook",
				value: webhook,
			}
			falcoOutputConfigs = append(falcoOutputConfigs, outputConfig)

		case constants.FalcoEventDestinationOpenSearch:
			opensearch := map[string]any{}
			secret, err := c.loadCustomWebhookSecret(ctx, log, reconcileCtx, *dest.ResourceSecretName)
			if err != nil {
				return nil, err
			}
			if hostport, ok := secret.Data["hostport"]; ok {
				opensearch["hostport"] = string(hostport)
			} else {
				return nil, fmt.Errorf("opensearch hostport is missing")
			}
			if index, ok := secret.Data["index"]; ok {
				opensearch["index"] = string(index)
			} else {
				opensearch["index"] = "falco"
			}
			if suffix, ok := secret.Data["suffix"]; ok {
				opensearch["suffix"] = string(suffix)
			} else {
				opensearch["suffix"] = "daily"
			}
			if username, ok := secret.Data["username"]; ok {
				opensearch["username"] = string(username)
			}
			if password, ok := secret.Data["password"]; ok {
				opensearch["password"] = string(password)
			}
			if checkcert, ok := secret.Data["checkcert"]; ok {
				checkcertBool, err := strconv.ParseBool(string(checkcert))
				if err != nil {
					return nil, fmt.Errorf("failed to parse checkcert value: %w", err)
				}
				opensearch["checkcert"] = checkcertBool
			} else {
				opensearch["checkcert"] = false
			}
			if minimumpriority, ok := secret.Data["minimumpriority"]; ok {
				opensearch["minimumpriority"] = string(minimumpriority)
			} else {
				opensearch["minimumpriority"] = "debug"
			}
			if customHeaders, ok := secret.Data["customheaders"]; ok {
				customHeadersMap := map[string]string{}
				if err := yaml.Unmarshal(customHeaders, &customHeadersMap); err != nil {
					return nil, fmt.Errorf("failed to parse custom headers: %w", err)
				}
				opensearch["customheaders"] = customHeadersMap
			}
			// Optional: number of shards
			if numberOfShards, ok := secret.Data["numberofshards"]; ok {
				shards, err := strconv.Atoi(string(numberOfShards))
				if err != nil {
					return nil, fmt.Errorf("failed to parse numberofshards value: %w", err)
				}
				opensearch["numberofshards"] = shards
			}
			// Optional: number of replicas
			if numberOfReplicas, ok := secret.Data["numberofreplicas"]; ok {
				replicas, err := strconv.Atoi(string(numberOfReplicas))
				if err != nil {
					return nil, fmt.Errorf("failed to parse numberofreplicas value: %w", err)
				}
				opensearch["numberofreplicas"] = replicas
			}
			// Optional: flatten fields
			if flattenFields, ok := secret.Data["flattenfields"]; ok {
				flatten, err := strconv.ParseBool(string(flattenFields))
				if err != nil {
					return nil, fmt.Errorf("failed to parse flattenfields value: %w", err)
				}
				opensearch["flattenfields"] = flatten
			}
			// Falcosidekick uses 'elasticsearch' config key
			outputConfig := falcoOutputConfig{
				key:   "elasticsearch",
				value: opensearch,
			}
			falcoOutputConfigs = append(falcoOutputConfigs, outputConfig)

		case constants.FalcoEventDestinationCentral:

			if c.config.Falco.CentralStorage == nil {
				return nil, fmt.Errorf("central storage is not configured")
			} else {
				if c.config.Falco.CentralStorage.URL == "" {
					return nil, fmt.Errorf("central storage URL was not provided")
				}
				if c.config.Falco.CentralStorage.TokenIssuerPrivateKey == "" {
					return nil, fmt.Errorf("central storage token issuer private key was not provided")
				}
			}

			// Gardener managed event store
			ingestorAddress := c.config.Falco.CentralStorage.URL

			// ok to generate new token on each reconcile
			token, _ := c.tokenIssuer.IssueToken(*reconcileCtx.ClusterIdentity)
			customHeaders := map[string]string{
				"Authorization": "Bearer " + token,
			}

			webhook := map[string]interface{}{
				"address":       ingestorAddress,
				"customheaders": customHeaders,
				"checkcert":     true,
			}
			outputConfig := falcoOutputConfig{
				key:   "webhook",
				value: webhook,
			}
			falcoOutputConfigs = append(falcoOutputConfigs, outputConfig)
		}
	}

	falcoSidekickVersion, err := c.getDefaultFalcosidekickVersion()
	if err != nil {
		return nil, err
	}

	falcosidekickImage, err := c.getImageForVersion("falcosidekick", falcoSidekickVersion)
	if err != nil {
		return nil, err
	}

	falcosidekickConfig := map[string]any{
		"image": map[string]string{
			"image": falcosidekickImage,
		},
		"enabled": false,
	}

	var falcosidekickCerts map[string]string
	if len(falcoOutputConfigs) > 0 {
		cas, certs, err := c.getFalcoCertificates(ctx, log, reconcileCtx)
		if err != nil {
			return nil, err
		}

		customFields := map[string]string{
			"cluster_id": *reconcileCtx.ClusterIdentity,
		}

		falcosidekickConfig = c.generateSidekickDefaultValues(falcosidekickImage, cas, certs, customFields, priorityClassName, reconcileCtx.IsShootDeployment)
		for _, outputConfig := range falcoOutputConfigs {
			falcosidekickConfig["config"].(map[string]any)[outputConfig.key] = outputConfig.value
		}

		falcosidekickCerts = map[string]string{
			"server_ca_crt": string(secrets.EncodeCertificate(cas.ServerCaCert)),
			"client_ca_crt": string(secrets.EncodeCertificate(cas.ClientCaCert)),
			"server_crt":    string(secrets.EncodeCertificate(certs.ServerCert)),
			"server_key":    string(secrets.EncodePrivateKey(certs.ServerKey)),
			"client_crt":    string(secrets.EncodeCertificate(certs.ClientCert)),
			"client_key":    string(secrets.EncodePrivateKey(certs.ClientKey)),
		}
	}

	destination := c.getDestination(falcoOutputConfigs)
	falcoChartValues := map[string]any{
		"clusterId":         *reconcileCtx.ClusterIdentity,
		"priorityClassName": priorityClassName,
		"falcoVersion":      *falcoVersion,
		"driver": map[string]any{
			"kind": "modern_ebpf",
			"loader": map[string]bool{
				"enabled": false,
			},
		},
		"image": map[string]string{
			"image": falcoImage,
		},
		"collectors": map[string]any{
			"crio": map[string]bool{
				"enabled": false,
			},
			"kubernetes": map[string]any{
				"enabled": false,
			},
			"docker": map[string]bool{
				"enabled": false,
			},
			"containerd": map[string]bool{
				"enabled": true,
			},
			"containerEngine": map[string]bool{
				"enabled": false,
			},
		},
		"extra": map[string]any{
			"env": []map[string]string{
				{"name": "SKIP_DRIVER_LOADER", "value": "yes"},
			},
		},
		"falco": map[string]any{
			"http_output": map[string]any{
				"enabled":  falcosidekickConfig["enabled"],
				"insecure": true,
				"url":      fmt.Sprintf("https://falcosidekick.%s.svc.cluster.local:%d", metav1.NamespaceSystem, 2801),
			},
			"json_output":                  true,
			"json_include_output_property": true,
			"log_level":                    "debug",
			"stdout_output": map[string]bool{
				"enabled": falcoStdoutLog,
			},
		},
		"scc": map[string]bool{
			"create": false,
		},
		"falcosidekick": falcosidekickConfig,
		"gardenerExtensionShootFalcoService": map[string]any{
			"output": map[string]string{
				"eventCollector": destination,
			},
		},
	}

	// only do this for non-Gardener managed clusters
	if reconcileCtx.IsShootDeployment {
		falcoChartValues["podLabels"] = map[string]string{
			"networking.gardener.cloud/to-dns":           "allowed",
			"networking.gardener.cloud/to-falcosidekick": "allowed",
		}
	}

	if falcosidekickConfig["enabled"] == true {
		falcoChartValues["falcocerts"] = falcosidekickCerts
	}

	if falcoServiceConfig.NodeSelector != nil {
		falcoChartValues["nodeSelector"] = *falcoServiceConfig.NodeSelector
	}

	if falcoServiceConfig.Tolerations != nil {
		falcoChartValues["tolerations"] = *falcoServiceConfig.Tolerations
	}

	if err := c.generatePreamble(falcoChartValues); err != nil {
		return nil, err
	}
	if err := c.generateStandardRules(falcoChartValues, falcoServiceConfig, falcoVersion); err != nil {
		return nil, err
	}
	if err := c.generateCustomRules(ctx, log, reconcileCtx, falcoChartValues); err != nil {
		return nil, err
	}
	if err := c.referenceShootCustomRules(falcoChartValues, falcoServiceConfig); err != nil {
		return nil, err
	}
	if err := c.generateHeartbeatRule(falcoChartValues, falcoServiceConfig, falcoVersion); err != nil {
		return nil, err
	}
	if err := c.enableContainerPlugin(falcoChartValues, falcoVersion); err != nil {
		return nil, err
	}
	// print values as yaml
	yamlValues, err := yaml.Marshal(falcoChartValues)
	if err == nil {
		fmt.Println(string(yamlValues))
	}
	return falcoChartValues, nil
}

func (*ConfigBuilder) getDestination(falcoOutputConfigs []falcoOutputConfig) string {
	for _, outputConfig := range falcoOutputConfigs {
		switch outputConfig.key {
		case "loki":
			return constants.FalcoEventDestinationLogging
		case "otlp":
			return constants.FalcoEventDestinationOTLP
		}
	}

	if len(falcoOutputConfigs) == 0 {
		return constants.FalcoEventDestinationStdout
	}

	return falcoOutputConfigs[0].key
}

func (c *ConfigBuilder) generateSidekickDefaultValues(
	falcosidekickImage string,
	cas *secrets.FalcoCas,
	certs *secrets.FalcoCertificates,
	customFields map[string]string,
	priorityClassName string,
	isShootDeployment bool) map[string]interface{} {

	sidekickValues := map[string]interface{}{
		"enabled":  true,
		"fullfqdn": true,
		"image": map[string]string{
			"image": falcosidekickImage,
		},
		"priorityClassName": priorityClassName,
		"config": map[string]interface{}{
			"debug": true,
			"tlsserver": map[string]interface{}{
				"deploy":        true,
				"mutualtls":     false,
				"server_key":    string(secrets.EncodePrivateKey(certs.ServerKey)),
				"server_crt":    string(secrets.EncodeCertificate(certs.ServerCert)),
				"server_ca_crt": string(secrets.EncodeCertificate(cas.ServerCaCert)),
			},
			"customfields": customFields,
		},
	}

	// Only set networking labels for Gardener-managed shoot clusters
	if isShootDeployment {
		sidekickValues["podLabels"] = map[string]string{
			"networking.gardener.cloud/to-dns":             "allowed",
			"networking.gardener.cloud/to-public-networks": "allowed",
			"networking.gardener.cloud/from-falco":         "allowed",
		}
	}
	return sidekickValues
}

func (c *ConfigBuilder) generatePreamble(falcoChartValues map[string]interface{}) error {
	falcoChartValues["configProvider"] = "gardener"
	// disable falcoctl
	falcoctl := map[string]interface{}{
		"artifact": map[string]interface{}{
			"install": map[string]interface{}{
				"enabled": false,
			},
			"follow": map[string]bool{
				"enabled": false,
			},
		},
	}
	falcoChartValues["falcoctl"] = falcoctl
	return nil
}

func (c *ConfigBuilder) generateHeartbeatRule(falcoChartValues map[string]interface{}, falcoServiceConfig *apisservice.FalcoServiceConfig, falcoVersion *string) error {
	if falcoServiceConfig.HeartbeatEvent != nil && *falcoServiceConfig.HeartbeatEvent {
		r, err := c.getFalcoRulesFile(constants.HeartbeatRule, *falcoVersion)
		if err != nil {
			return err
		}
		falcoChartValues["heartbeatRule"] = r
	}
	return nil
}

func (c *ConfigBuilder) enableContainerPlugin(falcoChartValues map[string]interface{}, falcoVersion *string) error {
	constraint, _ := semver3.NewConstraint(">= 0.41.2")
	v, err := semver3.NewVersion(*falcoVersion)
	if err != nil {
		return fmt.Errorf("invalid falco version %s: %w", *falcoVersion, err)
	}
	if !constraint.Check(v) {
		return nil
	}

	falcoChartValues["collectors"].(map[string]any)["containerEngine"].(map[string]bool)["enabled"] = true
	falcoChartValues["collectors"].(map[string]any)["containerd"].(map[string]bool)["enabled"] = false
	falcoChartValues["collectors"].(map[string]any)["crio"].(map[string]bool)["enabled"] = false
	falcoChartValues["collectors"].(map[string]any)["docker"].(map[string]bool)["enabled"] = false
	falcoChartValues["falco"].(map[string]any)["load_plugins"] = []string{"container"}
	pluginConfig := map[string]interface{}{
		"name":         "container",
		"library_path": "libcontainer.so",
		"init_config": map[string]interface{}{
			"engines": map[string]interface{}{
				"docker": map[string]interface{}{
					"enabled": false,
					"sockets": []string{"/var/run/docker.sock"},
				},
				"cri": map[string]interface{}{
					"enabled": true,
					"sockets": []string{
						"/run/containerd/containerd.sock",
						"/run/crio/crio.sock",
						"/run/k3s/containerd/containerd.sock",
					},
				},
				"containerd": map[string]interface{}{
					"enabled": false,
					"sockets": []string{"/run/containerd/containerd.sock"},
				},
				"podman": map[string]interface{}{
					"enabled": false,
					"sockets": []string{
						"/run/podman/podman.sock",
						"/run/user/1000/podman/podman.sock",
					},
				},
				"lxc": map[string]any{
					"enabled": false,
				},
				"libvirt_lxc": map[string]any{
					"enabled": false,
				},
				"bpm": map[string]any{
					"enabled": false,
				},
			},
		},
	}
	falcoChartValues["falco"].(map[string]any)["plugins"] = []interface{}{pluginConfig}

	return nil
}

func (c *ConfigBuilder) generateStandardRules(falcoChartValues map[string]interface{}, falcoServiceConfig *apisservice.FalcoServiceConfig, falcoVersion *string) error {
	if falcoServiceConfig.Rules.StandardRules != nil {
		for _, rule := range *falcoServiceConfig.Rules.StandardRules {
			switch rule {
			case constants.ConfigFalcoRules:
				r, err := c.getFalcoRulesFile(constants.FalcoRules, *falcoVersion)
				if err != nil {
					return err
				}
				falcoChartValues["falcoRules"] = r
			case constants.ConfigFalcoIncubatingRules:
				r, err := c.getFalcoRulesFile(constants.FalcoIncubatingRules, *falcoVersion)
				if err != nil {
					return err
				}
				falcoChartValues["falcoIncubatingRules"] = r

			case constants.ConfigFalcoSandboxRules:
				r, err := c.getFalcoRulesFile(constants.FalcoSandboxRules, *falcoVersion)
				if err != nil {
					return err
				}
				falcoChartValues["falcoSandboxRules"] = r
			}
		}
	}
	return nil
}

func (c *ConfigBuilder) generateCustomRules(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext, falcoChartValues map[string]interface{}) error {
	customRules, err := c.getCustomRules(ctx, log, reconcileCtx)
	if err != nil {
		return err
	}
	falcoChartValues["customRules"] = customRules
	return nil
}

func (c *ConfigBuilder) referenceShootCustomRules(falcoChartValues map[string]interface{}, falcoServiceConfig *apisservice.FalcoServiceConfig) error {

	if falcoServiceConfig.Rules.CustomRules == nil || len(*falcoServiceConfig.Rules.CustomRules) == 0 {
		return nil
	}
	shoot_custom_rules := []map[string]string{}
	rules_files := []string{}
	for _, rule := range *falcoServiceConfig.Rules.CustomRules {
		if rule.ShootConfigMap != "" {
			ruleConfigMapDir := filepath.Join("/etc", "falco", "shoot-custom-rules", rule.ShootConfigMap)
			rules_files = append(rules_files, ruleConfigMapDir)
			cr := map[string]string{
				"name": rule.ShootConfigMap,
			}
			shoot_custom_rules = append(shoot_custom_rules, cr)
		}
	}
	falcoChartValues["shoot_custom_rules"] = shoot_custom_rules
	falcoChartValues["rules_files_source"] = rules_files
	return nil
}

// get the latest Falcosidekick version tagged as "supported"
func (c *ConfigBuilder) getDefaultFalcosidekickVersion() (string, error) {
	latestVersion := ""
	for _, version := range *c.profile.GetFalcosidekickVersions() {
		if version.Classification == "supported" {
			if latestVersion == "" || semver.Compare("v"+version.Version, "v"+latestVersion) == 1 {
				latestVersion = version.Version
			}
		}
	}
	if latestVersion != "" {
		return latestVersion, nil
	} else {
		return "", fmt.Errorf("no supported Falcosidekick version found")
	}
}

func (c *ConfigBuilder) getImageForVersion(name string, version string) (string, error) {
	isDigest := func(tag string) bool {
		return strings.HasPrefix(tag, "sha256:")
	}

	var image *profile.Image

	switch name {
	case "falco":
		image = c.profile.GetFalcoImage(version)
	case "falcosidekick":
		image = c.profile.GetFalcosidekickImage(version)
	case "falcoctl":
		image = c.profile.GetFalcoctlImage(version)
	default:
		return "", fmt.Errorf("unknown image name %s", name)
	}

	if image == nil {
		return "", fmt.Errorf("no image found for %s version %s", name, version)
	}

	if isDigest(image.Tag) {
		return image.Repository + "@" + image.Tag, nil
	} else if image.Tag != "" {
		return image.Repository + ":" + image.Tag, nil
	} else {
		return image.Repository, nil
	}
}

func (c *ConfigBuilder) storeFalcoCas(ctx context.Context, namespace string, cas *secrets.FalcoCas, certs *secrets.FalcoCertificates) error {
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.FalcoCertificatesSecretName,
			Namespace: namespace,
		},
	}
	secrets.StoreFalcoCasInSecret(cas, certs, &secret)
	err := c.client.Update(ctx, &secret)
	if err != nil {
		// secret might not exist, create it
		return c.client.Create(ctx, &secret)
	} else {
		return nil
	}
}

func (c *ConfigBuilder) loadFalcoCertificates(ctx context.Context, namespace string) (*secrets.FalcoCas, *secrets.FalcoCertificates, error) {
	certs := &corev1.Secret{}
	err := c.client.Get(ctx,
		client.ObjectKey{
			Namespace: namespace,
			Name:      constants.FalcoCertificatesSecretName},
		certs)
	if err != nil {
		return nil, nil, err
	}
	return secrets.LoadCertificatesFromSecret(certs)
}

func (c *ConfigBuilder) getFalcoCertificates(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext) (*secrets.FalcoCas, *secrets.FalcoCertificates, error) {

	cas, certs, err := c.loadFalcoCertificates(ctx, reconcileCtx.Namespace)
	if err != nil {
		log.Info("cannot load Falco certificates from secret, generating new certificates: " + err.Error())
		// need to generate everything
		cas, err = secrets.GenerateFalcoCas(reconcileCtx.ClusterName, constants.DefaultCALifetime)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate Falco CAs: %w", err)
		}
		certs, err = secrets.GenerateKeysAndCerts(cas, reconcileCtx.ClusterName, c.config.Falco.CertificateLifetime.Duration)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate Falco certificates: %w", err)
		}
		err = c.storeFalcoCas(ctx, reconcileCtx.Namespace, cas, certs)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// check whether CA and/or certificates are expired and re-generate as needed
		renewed := false
		if secrets.CaNeedsRenewal(cas, constants.DefaultCARenewAfter) {
			renewed = true
			cas, err = secrets.GenerateFalcoCas(reconcileCtx.ClusterName, constants.DefaultCALifetime)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot generate Falco CAs: %w", err)
			}
		}
		if renewed || secrets.CertsNeedRenewal(certs, c.config.Falco.CertificateRenewAfter.Duration) {
			renewed = true
			certs, err = secrets.GenerateKeysAndCerts(cas, reconcileCtx.ClusterName, c.config.Falco.CertificateLifetime.Duration)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot generate Falco certificates: %w", err)
			}
		}
		if renewed {
			err = c.storeFalcoCas(ctx, reconcileCtx.Namespace, cas, certs)
			if err != nil {
				return nil, nil, err
			}

		}
	}
	return cas, certs, nil
}

func (c *ConfigBuilder) extractCustomRules(reconcileCtx *utils.ReconcileContext) ([]customRuleRef, error) {
	if reconcileCtx.FalcoServiceConfig.Rules.CustomRules == nil || len(*reconcileCtx.FalcoServiceConfig.Rules.CustomRules) == 0 {
		// no custom rules to apply
		return nil, nil
	}
	allConfigMaps := make(map[string]string)
	for _, r := range reconcileCtx.ResourceSection {
		if r.ResourceRef.Kind == "ConfigMap" && r.ResourceRef.APIVersion == "v1" {
			allConfigMaps[r.Name] = r.ResourceRef.Name
		}
	}
	var selectedConfigMaps []customRuleRef
	for _, customRule := range *reconcileCtx.FalcoServiceConfig.Rules.CustomRules {
		if customRule.ResourceName == "" {
			// ignore shoot configmap rules here
			continue
		}
		if configMapName, ok := allConfigMaps[customRule.ResourceName]; ok {
			cr := customRuleRef{
				RefName:       customRule.ResourceName,
				ConfigMapName: configMapName,
			}
			selectedConfigMaps = append(selectedConfigMaps, cr)
		} else {
			return nil, fmt.Errorf("no resource for custom rule reference %s found", customRule)
		}
	}
	return selectedConfigMaps, nil
}

func (c *ConfigBuilder) getCustomRules(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext) ([]customRulesFile, error) {
	selectedConfigMaps, err := c.extractCustomRules(reconcileCtx)
	if err != nil {
		return nil, err
	}
	return c.loadRuleConfig(ctx, log, reconcileCtx.Namespace, selectedConfigMaps)
}

func (c *ConfigBuilder) loadCustomWebhookSecret(ctx context.Context, log logr.Logger, reconcileCtx *utils.ReconcileContext, secretRefName string) (*corev1.Secret, error) {
	secretName := ""
	for _, ref := range reconcileCtx.ResourceSection {
		if ref.ResourceRef.Kind == "Secret" && ref.ResourceRef.APIVersion == "v1" && ref.Name == secretRefName {
			secretName = ref.ResourceRef.Name
			break
		}
	}

	if secretName == "" {
		return nil, fmt.Errorf("custom webhook secretRef %s not found in resources", secretRefName)
	}

	customWebhookSecretName := "ref-" + secretName

	secret := corev1.Secret{}
	err := c.client.Get(ctx,
		client.ObjectKey{
			Namespace: reconcileCtx.Namespace,
			Name:      customWebhookSecretName,
		},
		&secret)

	if err != nil {
		return nil, fmt.Errorf("failed to get custom webhook secretRef %s: %v", customWebhookSecretName, err)
	}
	return &secret, err
}

// load rule files from named configmap and return them in alphanumeric order
// based on the filename
func (c *ConfigBuilder) loadRulesFromConfigmap(ctx context.Context, log logr.Logger, ruleFilenames map[string]bool, namespace string, configmapName string) ([]customRulesFile, error) {

	var files []customRulesFile
	refConfigMapName := "ref-" + configmapName
	log.Info("loading custom rule configmap", "ruleRef", refConfigMapName, "configMapName", configmapName)
	configMap := corev1.ConfigMap{}
	err := c.client.Get(ctx,
		client.ObjectKey{
			Namespace: namespace,
			Name:      refConfigMapName},
		&configMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get custom rule configmap %s: %w", refConfigMapName, err)
	}
	if len(configMap.Data)+len(configMap.BinaryData) > constants.MaxCustomRulesFilesPerConfigMap {
		return nil, fmt.Errorf("too many custom rule files in configmap \"%s\"", refConfigMapName)
	}
	for name, file := range configMap.Data {
		if !strings.HasSuffix(name, ".yaml") {
			return nil, fmt.Errorf("rule file %s is not a yaml file", name)
		}
		if _, ok := ruleFilenames[name]; ok {
			return nil, fmt.Errorf("duplicate rule file %s", name)
		}
		if err := validateYaml(file); err != nil {
			return nil, fmt.Errorf("rule file %s of configmap %s is not valid yaml: %v", name, configmapName, err)
		}
		ruleFilenames[name] = true
		files = append(files, customRulesFile{
			Filename: name,
			Content:  file,
		})
	}
	for name, file := range configMap.BinaryData {
		if !strings.HasSuffix(name, ".yaml.gz") {
			return nil, fmt.Errorf("rule file %s of configmap %s is not a gzipped yaml file", name, configmapName)
		}
		nogzName := name[:len(name)-3]
		if _, ok := ruleFilenames[nogzName]; ok {
			return nil, fmt.Errorf("duplicate rule file %s", name)
		}
		rawData, err := decompressRulesFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress rule file %s: %v", name, err)
		}
		if err := validateYaml(rawData); err != nil {
			return nil, fmt.Errorf("rule file %s of configmap %s is not valid yaml: %v", name, configmapName, err)
		}
		ruleFilenames[nogzName] = true
		files = append(files, customRulesFile{
			Filename: nogzName,
			Content:  rawData,
		})
	}
	slices.SortFunc(files, func(a, b customRulesFile) int {
		return strings.Compare(a.Filename, b.Filename)
	})
	return files, nil
}

func (c *ConfigBuilder) loadRuleConfig(ctx context.Context, log logr.Logger, namespace string, selectedConfigMaps []customRuleRef) ([]customRulesFile, error) {
	ruleFilenames := map[string]bool{}
	var customRules []customRulesFile

	for _, crf := range selectedConfigMaps {
		configMapName := crf.ConfigMapName
		crf, err := c.loadRulesFromConfigmap(ctx, log, ruleFilenames, namespace, configMapName)
		if err != nil {
			return nil, err
		}
		customRules = append(customRules, crf...)
	}
	return customRules, nil
}

func (c *ConfigBuilder) getFalcoRulesFile(rulesFile string, falcoVersion string) (string, error) {
	falcoVersions := profile.FalcoProfileManagerInstance.GetFalcoVersions()
	rules := versions.Rules
	rulesVersion := ""
	for _, fv := range *falcoVersions {
		if falcoVersion == fv.Version {
			rulesVersion = fv.RulesVersion
		}
	}
	if rulesVersion == "" {
		return "", fmt.Errorf("cannot find rules %s for Falco version %s", rulesFile, falcoVersion)
	}
	dir := "rules/" + rulesVersion + "/" + rulesFile
	if f, err := rules.ReadFile(dir); err != nil {
		return "", err
	} else {
		return string(f[:]), nil
	}
}

func decompressRulesFile(datagz []byte) (string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(datagz))
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	isize, err := checkUncompressedSize(datagz)
	if err != nil {
		return "", err
	}

	// Create a LimitedReader to limit the number of bytes read to isize
	limitedReader := io.LimitedReader{R: reader, N: int64(isize)}

	data := make([]byte, isize)
	n, err := io.ReadFull(&limitedReader, data) // Read the entire compressed data
	if err != nil {
		return "", fmt.Errorf("failed to read gzipped data: %v", err)
	}

	if n != int(isize) {
		return "", fmt.Errorf("failed to read gzipped data: read %d bytes, expected %d bytes", n, isize)
	}

	// Check if there are any bytes left in the gzip reader
	extraByte := make([]byte, 1)
	_, err = reader.Read(extraByte)
	if err != io.EOF {
		return "", fmt.Errorf("isize in gzip trailer did not match the actual uncompressed size")
	}

	return string(data), nil
}

// Checks wether the advertised uncompressed size is less than expected
func checkUncompressedSize(datagz []byte) (uint32, error) {
	_, isize, err := readGzTrailer(datagz)
	if err != nil {
		return 0, err
	}

	if isize > constants.CustomRulesMaxSize {
		return 0, fmt.Errorf("uncompressed size is larger than 1 MiB: %d bytes", isize)
	}

	return isize, nil
}

// Reads the gzip trailer from the given gzip reader
func readGzTrailer(datagz []byte) (uint32, uint32, error) {
	if len(datagz) < 8 {
		return 0, 0, fmt.Errorf("gzip data is too short to contain a valid trailer")
	}

	// The trailer is the last 8 bytes of the gzip stream
	trailer := datagz[len(datagz)-8:]

	// Extract the CRC32 and ISIZE from the trailer
	crc32 := binary.LittleEndian.Uint32(trailer[0:4])
	isize := binary.LittleEndian.Uint32(trailer[4:8])

	return crc32, isize, nil
}

// Validates the given data as YAML
func validateYaml(data string) error {
	var yamlData any
	if err := yaml.Unmarshal([]byte(data), &yamlData); err != nil {
		return fmt.Errorf("data is not in valid yaml format: %v", err)
	}
	return nil
}
