// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falcovalues

import (
	"context"
	"fmt"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils/imagevector"
	"github.com/go-logr/logr"
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	images "github.com/gardener/gardener-extension-shoot-falco-service/imagevector"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
)

var (
	versions falco.Falco
)

func init() {
	versions = falco.FalcoVersions()
}

type ConfigBuilder struct {
	client        client.Client
	config        *config.Configuration
	tokenIssuer   *secrets.TokenIssuer
	imageVector   imagevector.ImageVector
	falcoVersions *falco.Falco
}

func NewConfigBuilder(client client.Client, tokenIssuer *secrets.TokenIssuer, config *config.Configuration, falcoVersions *falco.Falco) *ConfigBuilder {
	return &ConfigBuilder{
		client:        client,
		config:        config,
		tokenIssuer:   tokenIssuer,
		imageVector:   images.ImageVector(),
		falcoVersions: falcoVersions,
	}
}

func (c *ConfigBuilder) BuildFalcoValues(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) (map[string]interface{}, error) {

	// ok to generate new token on each reconcile
	token, _ := c.tokenIssuer.IssueToken(*cluster.Shoot.Status.ClusterIdentity)

	certs, err := c.getFalcoCaCertificates(ctx, log, cluster, namespace)
	if err != nil {
		return nil, err
	}
	log.Info("Generating Falco client- and server certifictes for cluster " + cluster.Shoot.Name + " in namespace " + namespace)
	certificates, err := secrets.GenerateKeysAndCerts(certs, constants.NamespaceKubeSystem)
	if err != nil {
		return nil, err
	}

	// images
	falcoVersion, err := c.getDefaultFalcoVersion()
	if err != nil {
		return nil, err
	}
	falcoImage, err := c.getImageForVersion("falco", falcoVersion)
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

	ingestorAddress := c.config.Falco.IngestorURL

	customHeadersMap := map[string]string{
		"Authorization": "Bearer " + token,
	}
	customHeaders := serializeCustomHeaders(customHeadersMap)

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
		"priorityClassName": c.config.Falco.PriorityClassName,
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
			"server_ca_crt": certificates.ServerCaCrt,
			"client_ca_crt": certificates.ClientCaCrt,
			"server_crt":    certificates.ServerCrt,
			"server_key":    certificates.ServerKey,
			"client_crt":    certificates.ClientCrt,
			"client_key":    certificates.ClientKey,
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
			"priorityClassName": c.config.Falco.PriorityClassName,
			"config": map[string]interface{}{
				"debug": true,
				"tlsserver": map[string]interface{}{
					"deploy":        true,
					"mutualtls":     false,
					"server_key":    certificates.ServerKey,
					"server_crt":    certificates.ServerCrt,
					"server_ca_crt": certificates.ServerCaCrt,
				},
				"customfields": customFields,
				"webhook": map[string]interface{}{
					"address":       ingestorAddress,
					"customheaders": customHeaders,
				},
			},
		},
		"customRules": customRules,
	}
	if falcoServiceConfig.Gardener.UseFalcoRules {
		r, err := c.getFalcoRulesFile(constants.FalcoRules, falcoVersion)
		if err != nil {
			return nil, err
		}
		falcoChartValues["falcoRules"] = r
	}
	if falcoServiceConfig.Gardener.UseFalcoIncubatingRules {
		r, err := c.getFalcoRulesFile(constants.FalcoIncubatingRules, falcoVersion)
		if err != nil {
			return nil, err
		}
		falcoChartValues["falcoIncubatingRules"] = r
	}
	if falcoServiceConfig.Gardener.UseFalcoSandboxRules {
		r, err := c.getFalcoRulesFile(constants.FalcoSandboxRules, falcoVersion)
		if err != nil {
			return nil, err
		}
		falcoChartValues["falcoSandboxRules"] = r
	}
	return falcoChartValues, nil
}

// get the latest Falco version tagged as "supported"
func (c *ConfigBuilder) getDefaultFalcoVersion() (string, error) {
	var latestVersion string = ""
	for _, version := range c.falcoVersions.Falco.FalcoVersions {
		if version.Classification == "supported" {
			if latestVersion == "" || semver.Compare("v"+version.Version, "v"+latestVersion) == 1 {
				latestVersion = version.Version
			}
		}
	}
	if latestVersion != "" {
		return latestVersion, nil
	} else {
		return "", fmt.Errorf("no supported Falco version found")
	}
}

// get the latest Falco version tagged as "supported"
func (c *ConfigBuilder) getDefaultFalcosidekickVersion() (string, error) {
	var latestVersion string = ""
	for _, version := range c.falcoVersions.FalcoSidekickVersions.FalcosidekickVersions {
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

	for _, image := range c.imageVector {
		if *image.Version == version && image.Name == name {
			if isDigest(*image.Tag) {
				return image.Repository + "@" + *image.Tag, nil
			} else if *image.Tag != "" {
				return image.Repository + ":" + *image.Tag, nil
			} else {
				return image.Repository, nil
			}
		}
	}
	return "", fmt.Errorf("no images found for %s version %s", name, version)
}

func (c *ConfigBuilder) storeFalcoCas(ctx context.Context, namespace string, cas *secrets.FalcoCas) error {
	certs := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.FalcoCertificatesSecretName,
			Namespace: namespace,
		},
	}
	secrets.StoreFalcoCasInSecret(cas, &certs)
	return c.client.Create(ctx, &certs)
}

func (c *ConfigBuilder) loadFalcoCertificates(ctx context.Context, namespace string) (*secrets.FalcoCas, error) {
	certs := &corev1.Secret{}
	err := c.client.Get(ctx,
		client.ObjectKey{
			Namespace: namespace,
			Name:      constants.FalcoCertificatesSecretName},
		certs)
	if err != nil {
		return nil, err
	}
	return secrets.LoadCertificatesFromSecret(certs)
}

func (c *ConfigBuilder) getFalcoCaCertificates(ctx context.Context, log logr.Logger, cluster *controller.Cluster, namespace string) (*secrets.FalcoCas, error) {

	certs, err := c.loadFalcoCertificates(ctx, namespace)
	if err != nil {
		log.Info("Cannot load Falco certificates from secret: " + err.Error())
	}
	if err != nil || secrets.CaNeedsRenewal(certs) {
		log.Info("Generating new falco ca certificates for cluster " + cluster.Shoot.Name + " in namespace " + namespace)
		certs, err = secrets.GenerateFalcoCas(cluster.Shoot.Name)
		if err != nil {
			return nil, err
		}
		err = c.storeFalcoCas(ctx, namespace, certs)
		if err != nil {
			return nil, err
		}
	}
	return certs, nil
}

func serializeCustomHeaders(customHeadersMap map[string]string) string {
	customHeaders := ""
	for k, v := range customHeadersMap {
		customHeaders += k + ":" + v + ","
	}
	return customHeaders[:len(customHeaders)-1]
}

func (c *ConfigBuilder) getCustomRules(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) (map[string]string, error) {

	if len(falcoServiceConfig.Gardener.RuleRefs) == 0 {
		// no custom rules to apply
		return nil, nil
	}
	allConfigMaps := map[string]string{}
	for _, r := range cluster.Shoot.Spec.Resources {
		if r.ResourceRef.Kind == "ConfigMap" && r.ResourceRef.APIVersion == "v1" {
			allConfigMaps[r.Name] = r.ResourceRef.Name
		}
	}
	selectedConfigMaps := map[string]string{}
	for _, ruleRef := range falcoServiceConfig.Gardener.RuleRefs {
		if configMapName, ok := allConfigMaps[ruleRef.Ref]; ok {
			selectedConfigMaps[ruleRef.Ref] = configMapName
		} else {
			return nil, fmt.Errorf("no resource for curstom rule ref %s found", ruleRef)
		}
	}
	return c.loadRuleConfig(ctx, log, namespace, &selectedConfigMaps)
}

func (c *ConfigBuilder) loadRuleConfig(ctx context.Context, log logr.Logger, namespace string, selectedConfigMaps *map[string]string) (map[string]string, error) {
	ruleFiles := map[string]string{}
	for ruleRef, configMapName := range *selectedConfigMaps {
		log.Info("loading custom rule", "ruleRef", ruleRef, "configMapName", configMapName)
		configMap := corev1.ConfigMap{}
		refConfigMapName := "ref-" + configMapName
		err := c.client.Get(ctx,
			client.ObjectKey{
				Namespace: namespace,
				Name:      refConfigMapName},
			&configMap)
		if err != nil {
			return nil, fmt.Errorf("failed to get custom rule configmap %s (resource %s): %v", refConfigMapName, ruleRef, err)
		}
		for name, file := range configMap.Data {
			if _, ok := ruleFiles[name]; ok {
				return nil, fmt.Errorf("duplicate rule file %s", name)
			}
			ruleFiles[name] = file
		}
	}
	return ruleFiles, nil
}

func (c *ConfigBuilder) getCustomRules1(ctx context.Context, log logr.Logger, cluster *extensions.Cluster, namespace string, falcoServiceConfig *apisservice.FalcoServiceConfig) (map[string]string, []string, error) {

	if len(falcoServiceConfig.Gardener.RuleRefs) == 0 {
		// no custom rules to apply
		return nil, nil, nil
	}
	allConfigMaps := map[string]string{}
	for _, r := range cluster.Shoot.Spec.Resources {
		if r.ResourceRef.Kind == "ConfigMap" && r.ResourceRef.APIVersion == "v1" {
			allConfigMaps[r.Name] = r.ResourceRef.Name
		}
	}
	selectedConfigMaps := map[string]string{}
	for _, ruleRef := range falcoServiceConfig.Gardener.RuleRefs {
		if configMapName, ok := allConfigMaps[ruleRef.Ref]; ok {
			selectedConfigMaps[ruleRef.Ref] = configMapName
		} else {
			return nil, nil, fmt.Errorf("no resource for curstom rule ref %s found", ruleRef)
		}
	}
	return c.loadRuleConfig1(ctx, log, namespace, &selectedConfigMaps)
}

// TODO: better error messages as direct user interaction
func (c *ConfigBuilder) loadRuleConfig1(ctx context.Context, log logr.Logger, namespace string, selectedConfigMaps *map[string]string) (map[string]string, []string, error) {
	ruleFiles := map[string]string{}
	customRuleConfigMaps := make([]string, 0)
	for ruleRef, configMapName := range *selectedConfigMaps {
		log.Info("loading custom rule", "ruleRef", ruleRef, "configMapName", configMapName)
		configMap := corev1.ConfigMap{}
		refConfigMapName := "ref-" + configMapName
		err := c.client.Get(ctx,
			client.ObjectKey{
				Namespace: namespace,
				Name:      refConfigMapName},
			&configMap)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get configmap %s: %v", refConfigMapName, err)
		}
		customRuleConfigMaps = append(customRuleConfigMaps, refConfigMapName)
		for name, file := range configMap.Data {
			if _, in := ruleFiles[name]; in {
				return nil, nil, fmt.Errorf("duplicate file %s in configmap %s", name, configMapName)
			}
			ruleFiles[name] = file
		}
	}
	return ruleFiles, customRuleConfigMaps, nil
}

func (c *ConfigBuilder) getFalcoRulesFile(rulesFile string, falcoVersion string) (string, error) {
	rules := versions.Rules
	for _, fv := range versions.Falco.FalcoVersions {
		dir := "rules/" + fv.RulesVersion + "/" + rulesFile
		f, err := rules.ReadFile(dir)
		if err != nil {
			return "", err
		} else {
			return string(f[:]), nil
		}
	}
	return "", fmt.Errorf("cannot find rules %s for Falco version %s", rulesFile, falcoVersion)
}
