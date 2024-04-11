// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package falcovalues

import (
	"context"
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-falco/pkg/apis/config"
	apisservice "github.com/gardener/gardener-extension-falco/pkg/apis/service"
	"github.com/gardener/gardener-extension-falco/pkg/constants"
	"github.com/gardener/gardener-extension-falco/pkg/secrets"
)

type ConfigBuilder struct {
	client      client.Client
	config      *config.Configuration
	tokenIssuer *secrets.TokenIssuer
}

func NewConfigBuilder(client client.Client, tokenIssuer *secrets.TokenIssuer, config *config.Configuration) *ConfigBuilder {
	return &ConfigBuilder{
		client:      client,
		config:      config,
		tokenIssuer: tokenIssuer,
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
	falcoImages, err := c.getImagesForVersion(falcoVersion)
	if err != nil {
		return nil, err
	}

	// falco sidekick
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
			"image": falcoImages.FalcoImage,
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
				"image": falcoImages.FalcosidekickImage,
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
		"useFalcoSandboxRules":    falcoServiceConfig.UseFalcoSandboxRules,
		"useFalcoIncubatingRules": falcoServiceConfig.UseFalcoIncubatingRules,
		"customRules":             customRules,
	}
	return falcoChartValues, nil
}

func (c *ConfigBuilder) getDefaultFalcoVersion() (string, error) {
	for _, version := range c.config.Falco.FalcoVersions {
		if version.Classification == "supported" {
			return version.Version, nil
		}
	}
	return "", fmt.Errorf("no supported falco version found")
}

func (c *ConfigBuilder) getImagesForVersion(version string) (*config.FalcoImages, error) {
	for _, images := range c.config.Falco.FalcoImages {
		if images.Version == version {
			return &images, nil
		}
	}
	return nil, fmt.Errorf("no images found for falco version %s", version)
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

	if len(falcoServiceConfig.RuleRefs) == 0 {
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
	for _, ruleRef := range falcoServiceConfig.RuleRefs {
		if configMapName, ok := allConfigMaps[ruleRef]; ok {
			selectedConfigMaps[ruleRef] = configMapName
		} else {
			return nil, fmt.Errorf("no resource for curstom rule ref %s found", ruleRef)
		}
	}
	return c.loadRuleConfig(ctx, log, namespace, &selectedConfigMaps)
}

// TODO: better error messages as direct user interaction
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
			return nil, fmt.Errorf("failed to get configmap %s: %v", refConfigMapName, err)
		}
		for name, file := range configMap.Data {
			if _, in := ruleFiles[name]; in {
				return nil, fmt.Errorf("duplicate file %s in configmap %s", name, configMapName)
			}
			ruleFiles[name] = file
		}
	}
	return ruleFiles, nil
}
