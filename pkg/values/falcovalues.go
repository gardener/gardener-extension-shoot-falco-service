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
	"slices"
	"strconv"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/pkg/extensions"
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

func (c *ConfigBuilder) BuildFalcoValues(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) (map[string]interface{}, error) {

	// images
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

	for _, dest := range *falcoServiceConfig.Destinations {
		switch dest.Name {
		case constants.FalcoEventDestinationStdout:
			falcoStdoutLog = true

		case constants.FalcoEventDestinationLogging:
			valiHost := utils.ComputeValiHost(*cluster.Shoot, *cluster.Seed)
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

		case constants.FalcoEventDestinationCustom:
			webhook := map[string]any{}
			secret, err := c.loadCustomWebhookSecret(ctx, log, cluster, namespace, *dest.ResourceSecretName)
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
			token, _ := c.tokenIssuer.IssueToken(*cluster.Shoot.Status.ClusterIdentity)
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

	falcosidekickConfig := make(map[string]interface{})
	falcosidekickConfig["enabled"] = false

	var falcosidekickCerts map[string]string
	if len(falcoOutputConfigs) > 0 {
		cas, certs, err := c.getFalcoCertificates(ctx, log, cluster, namespace)
		if err != nil {
			return nil, err
		}
		customFields := map[string]string{
			"cluster_id": *cluster.Shoot.Status.ClusterIdentity,
		}
		falcoSidekickVersion, err := c.getDefaultFalcosidekickVersion()
		if err != nil {
			return nil, err
		}
		falcosidekickImage, err := c.getImageForVersion("falcosidekick", falcoSidekickVersion)
		if err != nil {
			return nil, err
		}
		falcosidekickConfig = c.generateSidekickDefaultValues(falcosidekickImage, cas, certs, customFields)
		for _, outputConfig := range falcoOutputConfigs {
			falcosidekickConfig["config"].(map[string]interface{})[outputConfig.key] = outputConfig.value
		}
		falcosidekickCerts = map[string]string{
			"server_ca_crt": string(secrets.EncodeCertificate(cas.ServerCaCert)),
			"client_ca_crt": string(secrets.EncodeCertificate(cas.ClientCaCert)),
			"server_crt":    string(secrets.EncodeCertificate(certs.ServerCert)),
			"server_key":    string(secrets.EncodePrivateKey(certs.ServerKey)),
			"client_crt":    string(secrets.EncodeCertificate(certs.ClientCert)),
			"client_key":    string(secrets.EncodePrivateKey(certs.ClientKey)),
		}
	} else {
	}

	destination := c.getDestination(falcoOutputConfigs)
	falcoChartValues := map[string]interface{}{
		"clusterId": *cluster.Shoot.Status.ClusterIdentity,
		"tolerations": []map[string]string{
			{"effect": "NoSchedule", "operator": "Exists"},
			{"effect": "NoExecute", "operator": "Exists"},
		},
		"podLabels": map[string]string{
			"networking.gardener.cloud/to-dns":           "allowed",
			"networking.gardener.cloud/to-falcosidekick": "allowed",
		},
		"priorityClassName": *c.config.Falco.PriorityClassName,
		"driver": map[string]string{
			"kind": "modern-bpf",
		},
		"image": map[string]string{
			"image": falcoImage,
		},
		"collectors": map[string]interface{}{
			"crio": map[string]bool{
				"enabled": false,
			},
			"kubernetes": map[string]interface{}{
				"enabled": false,
			},
			"docker": map[string]bool{
				"enabled": false,
			},
		},
		"extra": map[string]interface{}{
			"env": []map[string]string{
				{"name": "SKIP_DRIVER_LOADER", "value": "yes"},
			},
		},
		"falco": map[string]interface{}{
			"http_output": map[string]interface{}{
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
		"gardenerExtensionShootFalcoService": map[string]interface{}{
			"output": map[string]string{
				"eventCollector": destination,
			},
		},
	}

	if falcosidekickConfig["enabled"] == true {
		falcoChartValues["falcocerts"] = falcosidekickCerts
	}

	if falcoServiceConfig.NodeSelector != nil {
		falcoChartValues["nodeSelector"] = *falcoServiceConfig.NodeSelector
	}

	if err := c.generatePreamble(falcoChartValues, falcoServiceConfig, falcoVersion); err != nil {
		return nil, err
	}
	if err := c.generateStandardRules(falcoChartValues, falcoServiceConfig, falcoVersion); err != nil {
		return nil, err
	}
	if err := c.generateCustomRules(ctx, log, cluster, namespace, falcoChartValues, falcoServiceConfig, falcoVersion); err != nil {
		return nil, err
	}
	return falcoChartValues, nil
}

func (*ConfigBuilder) getDestination(falcoOutputConfigs []falcoOutputConfig) string {
	for _, outputConfig := range falcoOutputConfigs {
		if outputConfig.key == "loki" {
			return constants.FalcoEventDestinationLogging
		}
	}

	if len(falcoOutputConfigs) == 0 {
		return constants.FalcoEventDestinationStdout
	}

	return falcoOutputConfigs[0].key
}

func (c *ConfigBuilder) generateSidekickDefaultValues(falcosidekickImage string, cas *secrets.FalcoCas, certs *secrets.FalcoCertificates, customFields map[string]string) map[string]interface{} {
	return map[string]interface{}{
		"podLabels": map[string]string{
			"networking.gardener.cloud/to-dns":             "allowed",
			"networking.gardener.cloud/to-public-networks": "allowed",
		},
		"enabled":  true,
		"fullfqdn": true,
		"image": map[string]string{
			"image": falcosidekickImage,
		},
		"priorityClassName": *c.config.Falco.PriorityClassName,
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
}

func (c *ConfigBuilder) generatePreamble(falcoChartValues map[string]interface{}, falcoServiceConfig *apisservice.FalcoServiceConfig, falcoVersion *string) error {
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

func (c *ConfigBuilder) generateCustomRules(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, falcoChartValues map[string]interface{}, falcoServiceConfig *apisservice.FalcoServiceConfig, falcoVersion *string) error {
	customRules, err := c.getCustomRules(ctx, log, cluster, namespace, falcoServiceConfig)
	if err != nil {
		return err
	}
	falcoChartValues["customRules"] = customRules
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

func (c *ConfigBuilder) getFalcoCertificates(ctx context.Context, log logr.Logger, cluster *controller.Cluster, namespace string) (*secrets.FalcoCas, *secrets.FalcoCertificates, error) {

	cas, certs, err := c.loadFalcoCertificates(ctx, namespace)
	if err != nil {
		log.Info("cannot load Falco certificates from secret, generating new certificates: " + err.Error())
		// need to generate everything
		cas, err = secrets.GenerateFalcoCas(cluster.Shoot.Name, constants.DefaultCALifetime)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate Falco CAs: %w", err)
		}
		certs, err = secrets.GenerateKeysAndCerts(cas, cluster.Shoot.Name, c.config.Falco.CertificateLifetime.Duration)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate Falco certificates: %w", err)
		}
		err = c.storeFalcoCas(ctx, namespace, cas, certs)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// check whether CA and/or certificates are expired and re-generate as needed
		renewed := false
		if secrets.CaNeedsRenewal(cas, constants.DefaultCARenewAfter) {
			renewed = true
			cas, err = secrets.GenerateFalcoCas(cluster.Shoot.Name, constants.DefaultCALifetime)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot generate Falco CAs: %w", err)
			}
		}
		if renewed || secrets.CertsNeedRenewal(certs, c.config.Falco.CertificateRenewAfter.Duration) {
			renewed = true
			certs, err = secrets.GenerateKeysAndCerts(cas, cluster.Shoot.Name, c.config.Falco.CertificateLifetime.Duration)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot generate Falco certificates: %w", err)
			}
		}
		if renewed {
			err = c.storeFalcoCas(ctx, namespace, cas, certs)
			if err != nil {
				return nil, nil, err
			}

		}
	}
	return cas, certs, nil
}

func (c *ConfigBuilder) extractCustomRules(cluster *extensions.Cluster, falcoServiceConfig *apisservice.FalcoServiceConfig) ([]customRuleRef, error) {
	if falcoServiceConfig.Rules.CustomRules == nil || len(*falcoServiceConfig.Rules.CustomRules) == 0 {
		// no custom rules to apply
		return nil, nil
	}
	allConfigMaps := make(map[string]string)
	for _, r := range cluster.Shoot.Spec.Resources {
		if r.ResourceRef.Kind == "ConfigMap" && r.ResourceRef.APIVersion == "v1" {
			allConfigMaps[r.Name] = r.ResourceRef.Name
		}
	}
	var selectedConfigMaps []customRuleRef
	for _, customRule := range *falcoServiceConfig.Rules.CustomRules {
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

func (c *ConfigBuilder) getCustomRules(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) ([]customRulesFile, error) {
	selectedConfigMaps, err := c.extractCustomRules(cluster, falcoServiceConfig)
	if err != nil {
		return nil, err
	}
	return c.loadRuleConfig(ctx, log, namespace, selectedConfigMaps)
}

func (c *ConfigBuilder) loadCustomWebhookSecret(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, secretRefName string) (*corev1.Secret, error) {
	secretName := ""
	for _, ref := range cluster.Shoot.Spec.Resources {
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
			Namespace: namespace,
			Name:      customWebhookSecretName,
		},
		&secret)

	if err != nil {
		return nil, fmt.Errorf("failed to get custom webhook secretRef %s: %v", customWebhookSecretName, err)
	}
	return &secret, err
}

// load rule files from named configmap and retrun them in alphanumeric order
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
