// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falcovalues

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/go-logr/logr"
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
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

func NewConfigBuilder(client client.Client, tokenIssuer *secrets.TokenIssuer, config *config.Configuration, profile *profile.FalcoProfileManager) *ConfigBuilder {
	return &ConfigBuilder{
		client:      client,
		config:      config,
		tokenIssuer: tokenIssuer,
		profile:     profile,
	}
}

func (c *ConfigBuilder) BuildFalcoValues(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) (map[string]interface{}, error) {

	cas, certs, err := c.getFalcoCertificates(ctx, log, cluster, namespace)
	if err != nil {
		return nil, err
	}

	// images
	falcoVersion := falcoServiceConfig.FalcoVersion
	falcoImage, err := c.getImageForVersion("falco", *falcoVersion)
	if err != nil {
		return nil, err
	}

	// falco sidekick
	falcoSidekickVersion, err := c.getDefaultFalcosidekickVersion()
	if err != nil {
		return nil, err
	}
	falcosidekickImage, err := c.getImageForVersion("falcosidekick", falcoSidekickVersion)
	if err != nil {
		return nil, err
	}

	customFieldsMap := map[string]string{
		"cluster_id": *cluster.Shoot.Status.ClusterIdentity,
	}
	customFields := serializeCustomHeaders(customFieldsMap)

	customRules, err := c.getCustomRules(ctx, log, cluster, namespace, falcoServiceConfig)
	if err != nil {
		return nil, err
	}

	falcoChartValues := map[string]interface{}{
		"clusterId": *cluster.Shoot.Status.ClusterIdentity,
		"tolerations": []map[string]string{
			{"effect": "NoSchedule", "operator": "Exists"},
			{"effect": "NoExecute", "operator": "Exists"},
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
		"falcocerts": map[string]interface{}{
			"server_ca_crt": string(secrets.EncodeCertificate(cas.ServerCaCert)),
			"client_ca_crt": string(secrets.EncodeCertificate(cas.ClientCaCert)),
			"server_crt":    string(secrets.EncodeCertificate(certs.ServerCert)),
			"server_key":    string(secrets.EncodePrivateKey(certs.ServerKey)),
			"client_crt":    string(secrets.EncodeCertificate(certs.ClientCert)),
			"client_key":    string(secrets.EncodePrivateKey(certs.ClientKey)),
		},
		"falco": map[string]interface{}{
			"http_output": map[string]interface{}{
				"enabled":  true,
				"insecure": true,
				"url":      fmt.Sprintf("https://falcosidekick.%s.svc.cluster.local:%d", metav1.NamespaceSystem, 2801),
			},
			"json_output":                  true,
			"json_include_output_property": true,
			"log_level":                    "debug",
		},
		"scc": map[string]bool{
			"create": false,
		},
		"falcoctl": map[string]interface{}{
			"artifact": map[string]interface{}{
				"install": map[string]interface{}{
					"enabled": false,
				},
				"follow": map[string]bool{
					"enabled": false,
				},
			},
		},
		"falcosidekick": map[string]interface{}{
			"enabled":  true,
			"fullfqdn": true,
			"webui": map[string]bool{
				"enabled": false,
			},
			"image": map[string]string{
				"image": falcosidekickImage,
			},
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
		},
		"customRules": customRules,
	}

	if falcoServiceConfig.CustomWebhook == nil || falcoServiceConfig.CustomWebhook.Enabled != nil || !*falcoServiceConfig.CustomWebhook.Enabled {
		// Gardener managed event store
		ingestorAddress := c.config.Falco.IngestorURL
		// ok to generate new token on each reconcile
		token, _ := c.tokenIssuer.IssueToken(*cluster.Shoot.Status.ClusterIdentity)
		customHeadersMap := map[string]string{
			"Authorization": "Bearer " + token,
		}
		customHeaders := serializeCustomHeaders(customHeadersMap)
		webhook := map[string]string{
			"address":       ingestorAddress,
			"customheaders": customHeaders,
		}
		config := falcoChartValues["falcosidekick"].(map[string]interface{})["config"].(map[string]interface{})
		config["webhook"] = webhook
	} else {
		// user has defined a custom location, we just pass it
		customWebhook := falcoServiceConfig.CustomWebhook
		webhook := map[string]string{
			"address": *customWebhook.Address,
		}
		if customWebhook.CustomHeaders != nil {
			webhook["customHeaders"] = *customWebhook.CustomHeaders
		}
		config := falcoChartValues["falcosidekick"].(map[string]interface{})["config"].(map[string]interface{})
		config["webhook"] = webhook
	}

	if falcoServiceConfig.Gardener.UseFalcoRules != nil && *falcoServiceConfig.Gardener.UseFalcoRules {
		r, err := c.getFalcoRulesFile(constants.FalcoRules, *falcoVersion)
		if err != nil {
			return nil, err
		}
		falcoChartValues["falcoRules"] = r
	}
	if falcoServiceConfig.Gardener.UseFalcoIncubatingRules != nil && *falcoServiceConfig.Gardener.UseFalcoIncubatingRules {
		r, err := c.getFalcoRulesFile(constants.FalcoIncubatingRules, *falcoVersion)
		if err != nil {
			return nil, err
		}
		falcoChartValues["falcoIncubatingRules"] = r
	}
	if falcoServiceConfig.Gardener.UseFalcoSandboxRules != nil && *falcoServiceConfig.Gardener.UseFalcoSandboxRules {
		r, err := c.getFalcoRulesFile(constants.FalcoSandboxRules, *falcoVersion)
		if err != nil {
			return nil, err
		}
		falcoChartValues["falcoSandboxRules"] = r
	}
	return falcoChartValues, nil
}

// get the latest Falco version tagged as "supported"
// func (c *ConfigBuilder) getDefaultFalcoVersion() (string, error) {
// 	var latestVersion string = ""
// 	for _, version := range c.falcoVersions.Falco.FalcoVersions {
// 		if version.Classification == "supported" {
// 			if latestVersion == "" || semver.Compare("v"+version.Version, "v"+latestVersion) == 1 {
// 				latestVersion = version.Version
// 			}
// 		}
// 	}
// 	if latestVersion != "" {
// 		return latestVersion, nil
// 	} else {
// 		return "", fmt.Errorf("no supported Falco version found")
// 	}
// }

// get the latest Falcosidekick version tagged as "supported"
func (c *ConfigBuilder) getDefaultFalcosidekickVersion() (string, error) {
	var latestVersion string = ""
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
	if name == "falco" {
		image = c.profile.GetFalcoImage(version)
	} else if name == "falcosidekick" {
		image = c.profile.GetFalcosidekickImage(version)
	} else {
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
		log.Info("cannot load Falco certificates from secret: " + err.Error())
	}
	if err != nil {
		// need to generate everything
		cas, err = secrets.GenerateFalcoCas(cluster.Shoot.Name, constants.DefaultCALifetime)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate Falco CAs: %w", err)
		}
		certs, err = secrets.GenerateKeysAndCerts(cas, cluster.Shoot.Name, constants.DefaultCertificateLifetime)
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
		if renewed || secrets.CertsNeedRenewal(certs, constants.DefaultCertificateRenewAfter) {
			renewed = true
			certs, err = secrets.GenerateKeysAndCerts(cas, cluster.Shoot.Name, constants.DefaultCertificateLifetime)
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

func serializeCustomHeaders(customHeadersMap map[string]string) string {
	customHeaders := ""
	for k, v := range customHeadersMap {
		customHeaders += k + ":" + v + ","
	}
	return customHeaders[:len(customHeaders)-1]
}

func (c *ConfigBuilder) extractCustomRules(cluster *extensions.Cluster, falcoServiceConfig *apisservice.FalcoServiceConfig) (map[string]string, error) {
	if len(falcoServiceConfig.Gardener.CustomRules) == 0 {
		// no custom rules to apply
		return nil, nil
	}
	allConfigMaps := make(map[string]string)
	for _, r := range cluster.Shoot.Spec.Resources {
		if r.ResourceRef.Kind == "ConfigMap" && r.ResourceRef.APIVersion == "v1" {
			allConfigMaps[r.Name] = r.ResourceRef.Name
		}
	}
	selectedConfigMaps := make(map[string]string)
	for _, customRule := range falcoServiceConfig.Gardener.CustomRules {
		if configMapName, ok := allConfigMaps[customRule]; ok {
			selectedConfigMaps[customRule] = configMapName
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

func (c *ConfigBuilder) loadRuleConfig(ctx context.Context, log logr.Logger, namespace string, selectedConfigMaps map[string]string) ([]customRulesFile, error) {
	ruleFiles := map[string]string{}
	for ruleRef, configMapName := range selectedConfigMaps {
		log.Info("loading custom rule", "ruleRef", ruleRef, "configMapName", configMapName)
		configMap := corev1.ConfigMap{}
		refConfigMapName := "ref-" + configMapName
		err := c.client.Get(ctx,
			client.ObjectKey{
				Namespace: namespace,
				Name:      refConfigMapName},
			&configMap)
		if err != nil {
			return nil, fmt.Errorf("failed to get custom rule configmap %s (resource %s): %w", refConfigMapName, ruleRef, err)
		}
		for name, file := range configMap.Data {
			if _, ok := ruleFiles[name]; ok {
				return nil, fmt.Errorf("duplicate rule file %s", name)
			}
			ruleFiles[name] = file
		}
	}
	rules := make([]customRulesFile, len(ruleFiles))
	i := 0
	for name, content := range ruleFiles {
		rules[i] = customRulesFile{
			Filename: name,
			Content:  content,
		}
		i++
	}
	slices.SortFunc(rules, func(a, b customRulesFile) int {
		return strings.Compare(a.Filename, b.Filename)
	})
	return rules, nil
}

func (c *ConfigBuilder) getFalcoRulesFile(rulesFile string, falcoVersion string) (string, error) {
	rules := versions.Rules
	rulesVersion := ""
	for _, fv := range versions.Falco.FalcoVersions {
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
