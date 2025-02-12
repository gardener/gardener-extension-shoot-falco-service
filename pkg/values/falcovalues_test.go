// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package values

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/gardener/gardener/extensions/pkg/util"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	"github.com/gardener/gardener/pkg/extensions"
	glogger "github.com/gardener/gardener/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/releaseutil"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	yaml "sigs.k8s.io/yaml"

	"github.com/gardener/gardener-extension-shoot-falco-service/charts"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
)

var (
	extensionConfiguration = &config.Configuration{
		Falco: &config.Falco{
			PriorityClassName:     stringValue("falco-test-priority-dummy-classname"),
			CertificateLifetime:   &metav1.Duration{Duration: constants.DefaultCertificateLifetime},
			CertificateRenewAfter: &metav1.Duration{Duration: constants.DefaultCertificateRenewAfter},
			TokenLifetime:         &metav1.Duration{Duration: constants.DefaultTokenLifetime},
			TokenIssuerPrivateKey: tokenIssuerPrivateKey,
			IngestorURL:           "https://ingestor.example.com",
		},
	}
	shootExtension = &service.FalcoServiceConfig{
		FalcoVersion: stringValue("0.38.0"),
		Resources:    stringValue("gardener"),
		Gardener: &service.Gardener{
			CustomRules:   []string{"rules1"},
			UseFalcoRules: boolValue(true),
		},
		Output: &service.Output{
			EventCollector: stringValue("central"),
		},
	}
	shootExtensionFalcoctl = &service.FalcoServiceConfig{
		FalcoVersion: stringValue("0.38.0"),
		Resources:    stringValue("falcoctl"),
		FalcoCtl: &service.FalcoCtl{
			Indexes: []service.FalcoCtlIndex{
				{
					Name: stringValue("falcosecurity"),
					Url:  stringValue("https://falcosecurity.github.io/falcoctl/index.yaml"),
				},
			},
			AllowedTypes: []string{"rulesfile"},
			Install: &service.Install{
				Refs: []string{
					"falco-rules3.1",
					"flaco-incubating-rules:4",
				},
				ResolveDeps: boolValue(true),
			},
		},
		Output: &service.Output{
			EventCollector: stringValue("central"),
		},
	}

	falcoProfileManager = profile.GetDummyFalcoProfileManager(
		&map[string]profile.FalcoVersion{
			"0.38.0": {
				Version:        "0.38.0",
				Classification: "supported",
				RulesVersion:   "3.2.0",
			},
		},
		&map[string]profile.Image{
			"0.38.0": {
				Repository: "falcosecurity/falco",
				Tag:        "0.38.0",
				Version:    "0.38.0",
			},
		},
		&map[string]profile.Version{
			"1.2.3": {
				Version:        "1.2.3",
				Classification: "supported",
			},
		},
		&map[string]profile.Image{
			"1.2.3": {
				Repository: "falcosecurity/falcosidekick",
				Tag:        "1.2.3",
				Version:    "1.2.3",
			},
		},
		&map[string]profile.Version{
			"0.9.23": {
				Version:        "0.9.23",
				Classification: "supported",
			},
		},
		&map[string]profile.Image{
			"0.9.23": {
				Repository: "falcosecurity/falcoctl",
				Tag:        "0.9.23",
				Version:    "0.9.23",
			},
		},
	)

	shootSpec = &extensions.Cluster{
		Seed: &gardencorev1beta1.Seed{
			Spec: gardencorev1beta1.SeedSpec{
				Ingress: &gardencorev1beta1.Ingress{
					Domain: "seed-mock-ingress.com",
				},
			},
		},
		Shoot: &gardencorev1beta1.Shoot{
			Spec: gardencorev1beta1.ShootSpec{
				Resources: []gardencorev1beta1.NamedResourceReference{
					{
						Name: "rules1",
						ResourceRef: autoscalingv1.CrossVersionObjectReference{
							Kind:       "ConfigMap",
							Name:       "rules1",
							APIVersion: "v1",
						},
					},
					{
						Name: "rules3",
						ResourceRef: autoscalingv1.CrossVersionObjectReference{
							Kind:       "ConfigMap",
							Name:       "rules3",
							APIVersion: "v1",
						},
					},
				},
			},
			Status: gardencorev1beta1.ShootStatus{
				ClusterIdentity: stringValue("this-is-the-cluster-identify"),
			},
		},
	}
	resources          = "gardener"
	falcoServiceConfig = &apisservice.FalcoServiceConfig{
		Resources: &resources,
		Gardener: &apisservice.Gardener{
			CustomRules: []string{"rules1", "rules3"},
		},
	}
	falcoServiceConfigBad = &apisservice.FalcoServiceConfig{
		Resources: &resources,
		Gardener: &apisservice.Gardener{
			CustomRules: []string{"rules1", "rules2"},
		},
	}
	falcoServiceConfigWrongCustomRules = &apisservice.FalcoServiceConfig{
		Resources: &resources,
		Gardener: &apisservice.Gardener{
			CustomRules: []string{"rules1", "rules_wrong"},
		},
	}
	falcoServiceConfigCustomWebhook = &apisservice.FalcoServiceConfig{
		FalcoVersion: stringValue("0.38.0"),
		Resources:    &resources,
		Gardener: &apisservice.Gardener{
			UseFalcoRules: boolValue(true),
		},
		Output: &apisservice.Output{
			EventCollector: stringValue("custom"),
			CustomWebhook: &apisservice.Webhook{
				Enabled:       boolValue(true),
				Address:       stringValue("https://webhook.example.com"),
				CustomHeaders: stringValue("my-custom-headers"),
				Checkcerts:    boolValue(true),
			},
		},
	}
	falcoServiceConfigCluster = &apisservice.FalcoServiceConfig{
		FalcoVersion: stringValue("0.38.0"),
		Resources:    &resources,
		Gardener: &apisservice.Gardener{
			UseFalcoRules: boolValue(true),
		},
		Output: &apisservice.Output{
			EventCollector: stringValue("cluster"),
		},
	}
	rulesConfigMap = &corev1.ConfigMapList{
		Items: []corev1.ConfigMap{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "shoot--test--foo",
					Name:      "ref-rules1",
				},
				Data: map[string]string{
					"dummyrules.yaml": "# dummy rules 1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "shoot--test--foo",
					Name:      "ref-rules2",
				},
				Data: map[string]string{
					"dummyrules.yaml": "# dummy rules 2",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "shoot--test--foo",
					Name:      "ref-rules3",
				},
				Data: map[string]string{
					"dummyrules-other.yaml": "# dummy rules 3",
				},
			},
		},
	}
)

var _ = Describe("Test value generation for helm chart", Label("falcovalues"), func() {

	BeforeEach(func() {
		fakeclient := crfake.NewFakeClient(rulesConfigMap)
		tokenIssuer, err := secrets.NewTokenIssuer(tokenIssuerPrivateKey, &metav1.Duration{Duration: constants.DefaultTokenLifetime})
		Expect(err).To(BeNil())
		configBuilder = NewConfigBuilder(fakeclient, tokenIssuer, extensionConfiguration, falcoProfileManager)
		logger, _ = glogger.NewZapLogger(glogger.InfoLevel, glogger.FormatJSON)
	})

	It("custom rules in shoot spec", func(ctx SpecContext) {
		res, err := configBuilder.extractCustomRules(shootSpec, falcoServiceConfig)
		Expect(err).To(BeNil())
		Expect(len(res)).To(Equal(2))
		Expect(res).To(HaveKey("rules1"))
		Expect(res).To(HaveKey("rules3"))

		_, err = configBuilder.extractCustomRules(shootSpec, falcoServiceConfigBad)
		Expect(err).NotTo(BeNil())
	})

	It("Test loading rules from configmap", func(ctx SpecContext) {
		err := configBuilder.client.Get(context.TODO(), client.ObjectKey{Namespace: "shoot--test--foo", Name: "ref-rules1"}, &corev1.ConfigMap{})
		Expect(err).To(BeNil())
		selectedConfigs := map[string]string{
			"rules1": "rules1",
			"rules2": "rules2",
		}
		res, err := configBuilder.loadRuleConfig(context.TODO(), logger, "shoot--test--foo", selectedConfigs)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(Equal("duplicate rule file dummyrules.yaml"))
		Expect(res).To(BeNil())

		selectedConfigs = map[string]string{
			"rules1": "rules1",
			"rules3": "rules3",
		}
		res, err = configBuilder.loadRuleConfig(context.TODO(), logger, "shoot--test--foo", selectedConfigs)
		Expect(err).To(BeNil())
		Expect(len(res)).To(Equal(2))
		cr1 := customRulesFile{
			Filename: "dummyrules-other.yaml",
			Content:  "# dummy rules 3",
		}
		cr2 := customRulesFile{
			Filename: "dummyrules.yaml",
			Content:  "# dummy rules 1",
		}
		cr3 := customRulesFile{
			Filename: "dummyrulesfdsfa-other.yaml",
			Content:  "# dummy rules",
		}
		Expect(res).To(ContainElement(cr1))
		Expect(res).To(ContainElement(cr2))
		Expect(res).NotTo(ContainElement(cr3))

	})

	It("Test custom webhook functionality", func(ctx SpecContext) {

		values, err := configBuilder.BuildFalcoValues(context.TODO(), logger, shootSpec, "shoot--test--foo", falcoServiceConfigCustomWebhook)
		Expect(err).To(BeNil())
		js, err := json.MarshalIndent((values), "", "    ")
		Expect(err).To(BeNil())
		Expect(len(js)).To(BeNumerically(">", 100))
		// fmt.Println(string(js))
		config := values["falcosidekick"].(map[string]interface{})["config"].(map[string]interface{})

		Expect(config).To(HaveKey("webhook"))
		webhook := config["webhook"].(map[string]interface{})
		Expect(webhook).To(HaveKey("address"))
		Expect(webhook["address"].(string)).To(Equal("https://webhook.example.com"))
		Expect(webhook).To(HaveKey("checkcert"))
		Expect(webhook["checkcert"].(bool)).To(BeTrue())
		Expect(webhook).To(HaveKey("customheaders"))
		Expect(webhook["customheaders"].(string)).To(Equal("my-custom-headers"))
	})

	It("Test cluster logging functionality", func(ctx SpecContext) {
		values, err := configBuilder.BuildFalcoValues(context.TODO(), logger, shootSpec, "shoot--test--foo", falcoServiceConfigCluster)
		Expect(err).To(BeNil())
		js, err := json.MarshalIndent((values), "", "    ")
		Expect(err).To(BeNil())
		Expect(len(js)).To(BeNumerically(">", 100))
		config := values["falcosidekick"].(map[string]interface{})["config"].(map[string]interface{})

		Expect(config).To(HaveKey("loki"))

		loggingConf := config["loki"].(map[string]interface{})
		Expect(loggingConf).To(HaveKey("hostport"))

		Expect(loggingConf["hostport"].(string)).To(And(
			ContainSubstring("https://v-"),
			ContainSubstring(shootSpec.Seed.Spec.Ingress.Domain),
		))

		Expect(loggingConf).To(HaveKey("checkcert"))
		Expect(loggingConf["checkcert"].(bool)).To(BeFalse())

		Expect(loggingConf).To(HaveKey("format"))
		Expect(loggingConf["format"].(string)).To(Equal("json"))

		Expect(loggingConf).To(HaveKey("endpoint"))
		Expect(loggingConf["endpoint"].(string)).To(Equal("/vali/api/v1/push"))
	})

	It("Test values generation gardener", func(ctx SpecContext) {
		values, err := configBuilder.BuildFalcoValues(context.TODO(), logger, shootSpec, "shoot--test--foo", shootExtension)
		Expect(err).To(BeNil())
		js, err := json.MarshalIndent((values), "", "    ")
		Expect(err).To(BeNil())
		//fmt.Println(string(js))
		Expect(len(js)).To(BeNumerically(">", 100))
		cr := values["customRules"].([]customRulesFile)
		Expect(len(cr)).To(Equal(1))
		Expect(cr[0].Content).To(Equal("# dummy rules 1"))

		frules := values["falcoRules"].(string)
		Expect(len(frules)).To(BeNumerically(">", 1000))
		_, ok := values["falcoIncubatingRules"]
		Expect(ok).To(BeFalse())
		_, ok = values["falcoSandboxRules"]
		Expect(ok).To(BeFalse())

		prioriyClass := values["priorityClassName"].(string)
		Expect(prioriyClass).To(Equal("falco-test-priority-dummy-classname"))

		// render chart and check if the values are set correctly
		//
		renderer, err := util.NewChartRendererForShoot("1.30.2")
		Expect(err).To(BeNil())
		release, err := renderer.RenderEmbeddedFS(charts.InternalChart, filepath.Join(charts.InternalChartsPath, constants.FalcoChartname), constants.FalcoChartname, metav1.NamespaceSystem, values)
		Expect(err).To(BeNil())

		// fmt.Println((release.ChartName))
		// for _, mf := range release.Manifests {
		// 	fmt.Println(mf.Name + " " + mf.Head.Kind)
		// 	fmt.Println(mf.Content)
		// }

		// check custom rules
		customRules := getManifest(release, "falco/templates/falco-custom-rules.yaml")
		Expect(customRules).NotTo(BeNil())
		m := make(map[string]interface{})
		falcoConfigmap := getManifest((release), "falco/templates/falco-configmap.yaml")
		fc := corev1.ConfigMap{}
		err = yaml.Unmarshal([]byte(falcoConfigmap.Content), &fc)
		Expect(err).To(BeNil())
		falcoYaml := make(map[string]interface{})
		err = yaml.Unmarshal([]byte(fc.Data["falco.yaml"]), &falcoYaml)
		Expect(err).To(BeNil())
		rules := falcoYaml["rules_files"].([]interface{})
		Expect(len(rules)).To(Equal(2))
		Expect(rules[0]).To(Equal("/etc/falco/rules.d/falco_rules.yaml"))
		Expect(rules[1]).To(Equal("/etc/falco/rules.d/dummyrules.yaml"))
		fmt.Println(customRules.Content)
		err = yaml.Unmarshal([]byte(customRules.Content), &m)
		Expect(err).To(BeNil())
		data := m["data"].(map[string]interface{})
		rulesFile := data["dummyrules.yaml"].(string)
		Expect(rulesFile).To(Equal("# dummy rules 1"))

		// check priority class in falco deamonset
		falcoDaemonset := getManifest(release, "falco/templates/falco-daemonset.yaml")
		Expect(falcoDaemonset).NotTo(BeNil())
		ds := appsv1.DaemonSet{}
		fmt.Println(falcoDaemonset.Content)
		err = yaml.Unmarshal([]byte(falcoDaemonset.Content), &ds)
		Expect(err).To(BeNil())
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("falcosecurity/falco:0.38.0"))
		Expect(ds.Spec.Template.Spec.Containers[0].ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal("falco-test-priority-dummy-classname"))
		// fmt.Println((customRules.Content))

		// default gardener webhook
		config := values["falcosidekick"].(map[string]interface{})["config"].(map[string]interface{})
		Expect(config).To(HaveKey("webhook"))
		webhook := config["webhook"].(map[string]interface{})
		Expect(webhook).To(HaveKey("address"))
		Expect(webhook["address"].(string)).To(Equal("https://ingestor.example.com"))
		Expect(webhook).To(HaveKey("checkcert"))
		Expect(webhook["checkcert"].(bool)).To(BeTrue())
		Expect(webhook).To(HaveKey("customheaders"))
		Expect(webhook["customheaders"].(string)).To(ContainSubstring("Bearer"))

	})

	It("Test values generation falcoctl", func(ctx SpecContext) {
		values, err := configBuilder.BuildFalcoValues(context.TODO(), logger, shootSpec, "shoot--test--foo", shootExtensionFalcoctl)
		Expect(err).To(BeNil())
		js, err := json.MarshalIndent((values), "", "    ")
		Expect(err).To(BeNil())
		//fmt.Println(string(js))
		Expect(len(js)).To(BeNumerically(">", 100))
		Expect(values).NotTo(HaveKey("customRules"))
		Expect(values).NotTo(HaveKey("falcoRules"))
		Expect(values).NotTo(HaveKey("falcoIncubatingRules"))
		Expect(values).NotTo(HaveKey("falcoSandboxRules"))
		prioriyClass := values["priorityClassName"].(string)
		Expect(prioriyClass).To(Equal("falco-test-priority-dummy-classname"))

		// render chart and check if the values are set correctly
		//
		renderer, err := util.NewChartRendererForShoot("1.30.2")
		Expect(err).To(BeNil())
		release, err := renderer.RenderEmbeddedFS(charts.InternalChart, filepath.Join(charts.InternalChartsPath, constants.FalcoChartname), constants.FalcoChartname, metav1.NamespaceSystem, values)
		Expect(err).To(BeNil())

		// check custom rules
		customRules := getManifest(release, "falco/templates/falco-custom-rules.yaml")
		Expect(customRules).To(BeNil())
		falcoConfigmap := getManifest((release), "falco/templates/falco-configmap.yaml")
		fc := corev1.ConfigMap{}
		err = yaml.Unmarshal([]byte(falcoConfigmap.Content), &fc)
		Expect(err).To(BeNil())
		falcoYaml := make(map[string]interface{})
		err = yaml.Unmarshal([]byte(fc.Data["falco.yaml"]), &falcoYaml)
		Expect(err).To(BeNil())
		rules := falcoYaml["rules_files"].([]interface{})
		Expect(len(rules)).To(Equal(3))
		Expect(rules[0]).To(Equal("/etc/falco/falco_rules.yaml"))
		Expect(rules[1]).To(Equal("/etc/falco/falco_rules.local.yaml"))
		Expect(rules[2]).To(Equal("/etc/falco/rules.d"))

		// check priority class in falco deamonset
		falcoDaemonset := getManifest(release, "falco/templates/falco-daemonset.yaml")
		Expect(falcoDaemonset).NotTo(BeNil())
		ds := appsv1.DaemonSet{}
		fmt.Println(falcoDaemonset.Content)
		err = yaml.Unmarshal([]byte(falcoDaemonset.Content), &ds)
		Expect(err).To(BeNil())
		Expect(ds.Spec.Template.Spec.Containers[0].Image).To(Equal("falcosecurity/falco:0.38.0"))
		Expect(ds.Spec.Template.Spec.Containers[0].ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
		Expect(ds.Spec.Template.Spec.PriorityClassName).To(Equal("falco-test-priority-dummy-classname"))

		// default gardener webhook
		config := values["falcosidekick"].(map[string]interface{})["config"].(map[string]interface{})
		Expect(config).To(HaveKey("webhook"))
		webhook := config["webhook"].(map[string]interface{})
		Expect(webhook).To(HaveKey("address"))
		Expect(webhook["address"].(string)).To(Equal("https://ingestor.example.com"))
		Expect(webhook).To(HaveKey("checkcert"))
		Expect(webhook["checkcert"].(bool)).To(BeTrue())
		Expect(webhook).To(HaveKey("customheaders"))
		Expect(webhook["customheaders"].(string)).To(ContainSubstring("Bearer"))

		// check falcoctl configuration
		falcoCtlConfigmap := getManifest(release, "falco/templates/falcoctl-configmap.yaml")
		Expect(falcoCtlConfigmap).NotTo(BeNil())
		fctlcfg := corev1.ConfigMap{}
		err = yaml.Unmarshal([]byte(falcoCtlConfigmap.Content), &fctlcfg)
		Expect(err).To(BeNil())
		fctl, ok := fctlcfg.Data["falcoctl.yaml"]
		Expect(ok).To(BeTrue())
		fmt.Println("This is the configmap")
		fmt.Println(fctl)
		Expect(fctl).NotTo(BeNil())
		falcoCtlYaml := make(map[string]interface{})
		err = yaml.Unmarshal([]byte(fctl), &falcoCtlYaml)
		Expect(err).To(BeNil())
		install := falcoCtlYaml["install"].(map[string]interface{})
		resolveDeps := install["resolveDeps"].(bool)
		Expect(resolveDeps).To(BeTrue())
	})

})

var _ = Describe("Getter for custom rules", Label("falcovalues"), func() {

	BeforeEach(func() {
		fakeclient := crfake.NewFakeClient(rulesConfigMap)
		tokenIssuer, err := secrets.NewTokenIssuer(tokenIssuerPrivateKey, &metav1.Duration{Duration: constants.DefaultTokenLifetime})
		Expect(err).To(BeNil())
		configBuilder = NewConfigBuilder(fakeclient, tokenIssuer, extensionConfiguration, falcoProfileManager)
		logger, _ = glogger.NewZapLogger(glogger.InfoLevel, glogger.FormatJSON)
	})

	It("can not load custom rules from empty namespace", func(ctx SpecContext) {
		Expect(configBuilder.getCustomRules(context.TODO(), logger, shootSpec, "", falcoServiceConfig)).Error().ToNot(BeNil())
	})

	It("can not load faulty custom rules references", func(ctx SpecContext) {
		Expect(configBuilder.getCustomRules(context.TODO(), logger, shootSpec, "", falcoServiceConfigWrongCustomRules)).Error().ToNot(BeNil())
	})
})

var _ = Describe("Getter for Falco rules", Label("falcovalues"), func() {

	BeforeEach(func() {
		fakeclient := crfake.NewFakeClient(rulesConfigMap)
		tokenIssuer, err := secrets.NewTokenIssuer(tokenIssuerPrivateKey, &metav1.Duration{Duration: constants.DefaultTokenLifetime})
		Expect(err).To(BeNil())
		configBuilder = NewConfigBuilder(fakeclient, tokenIssuer, extensionConfiguration, falcoProfileManager)
	})

	It("can identify falco version and rules mismatches", func(ctx SpecContext) {
		Expect(configBuilder.getFalcoRulesFile(constants.FalcoRules, "999.999.999")).Error().ToNot(BeNil())
	})

	It("can identify falco a wrong rules file", func(ctx SpecContext) {
		Expect(configBuilder.getFalcoRulesFile("false_rules_file.yaml", "0.38.0")).Error().ToNot(BeNil())
	})
})

var falcoRuleYaml = `
- rule: Test rule
  desc: Test rule description
  condition: test_condition
  output: test_output
  priority: test_priority
  tags: test_tags
  examples: test_examples

- macro: test_macro
  condition: test_condition

- list: shell_binaries
  items: [ash, bash, csh, ksh, sh, tcsh, zsh, dash]
`

var _ = Describe("loadRulesFromRulesFiles", func() {
	It("should load rules from valid rule files", func() {
		ruleFilesData := map[string]string{
			"rule1.yaml": "valid_yaml_content_1",
			"rule2.yaml": "valid_yaml_content_2",
		}

		rules, err := loadRulesFromRulesFiles(ruleFilesData, nil)
		Expect(err).To(BeNil())
		Expect(len(rules)).To(Equal(2))
		Expect(rules[0].Filename).To(Equal("rule1.yaml"))
		Expect(rules[0].Content).To(Equal("valid_yaml_content_1"))
		Expect(rules[1].Filename).To(Equal("rule2.yaml"))
		Expect(rules[1].Content).To(Equal("valid_yaml_content_2"))
	})

	It("should decompress gzip content", func() {
		// Create a gzip compressed content
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte(falcoRuleYaml))
		Expect(err).To(BeNil())
		gz.Close()

		ruleFilesBinaryData := map[string][]byte{
			"rule1.yaml.gz": buf.Bytes(),
		}

		rules, err := loadRulesFromRulesFiles(nil, ruleFilesBinaryData)
		Expect(err).To(BeNil())
		Expect(len(rules)).To(Equal(1))
		Expect(rules[0].Filename).To(Equal("rule1.yaml.gz"))
		Expect(rules[0].Content).To(Equal(falcoRuleYaml))
	})

	It("should return an error for invalid gzip content", func() {
		invalidGzipContent := []byte("invalid_gzip_content")

		ruleFilesBinaryData := map[string][]byte{
			"rule1.yaml.gz": invalidGzipContent,
		}

		rules, err := loadRulesFromRulesFiles(nil, ruleFilesBinaryData)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("failed to decompress rule file"))
		Expect(rules).To(BeNil())
	})

	It("should return an error for invalid gzip content", func() {
		invalidGzipContent := base64.StdEncoding.EncodeToString([]byte("invalid_gzip_content"))

		ruleFiles := map[string][]byte{
			"rule1.yaml.gz": []byte(invalidGzipContent),
		}

		rules, err := loadRulesFromRulesFiles(nil, ruleFiles)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("failed to create gzip reader"))
		Expect(rules).To(BeNil())
	})

	It("should return an error for gzipped content that fails YAML validation", func() {
		invalidYaml := `
key1:
  subkey1: value1
 subkey2: value2  # Incorrect indentation
`
		// Create a gzip compressed content
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte(invalidYaml))
		Expect(err).To(BeNil())
		gz.Close()

		ruleFilesBinaryData := map[string][]byte{
			"rule1.yaml.gz": []byte(buf.Bytes()),
		}

		rules, err := loadRulesFromRulesFiles(nil, ruleFilesBinaryData)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("rule file rule1.yaml.gz is not valid yaml"))
		Expect(rules).To(BeNil())
	})

	It("should load and sort rules from mixed valid rule files and gzipped content", func() {
		// Create a gzip compressed content for rule3.yaml.gz
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte(falcoRuleYaml))
		Expect(err).To(BeNil())
		gz.Close()

		ruleFilesData := map[string]string{
			"rule3.yaml": "valid_yaml_content_3",
			"rule1.yaml": "valid_yaml_content_1",
		}

		ruleFilesBinaryData := map[string][]byte{
			"rule2.yaml.gz": []byte(buf.Bytes()),
		}

		rules, err := loadRulesFromRulesFiles(ruleFilesData, ruleFilesBinaryData)
		Expect(err).To(BeNil())
		Expect(len(rules)).To(Equal(3))
		Expect(rules[0].Filename).To(Equal("rule1.yaml"))
		Expect(rules[0].Content).To(Equal("valid_yaml_content_1"))
		Expect(rules[1].Filename).To(Equal("rule2.yaml.gz"))
		Expect(rules[1].Content).To(Equal(falcoRuleYaml))
		Expect(rules[2].Filename).To(Equal("rule3.yaml"))
		Expect(rules[2].Content).To(Equal("valid_yaml_content_3"))
	})
})

func getManifest(release *chartrenderer.RenderedChart, name string) *releaseutil.Manifest {
	for _, mf := range release.Manifests {
		if mf.Name == name {
			return &mf
		}
	}
	return nil
}

var _ = Describe("decompressRulesFile", func() {
	It("should decompress valid base64 encoded gzip content", func() {
		// Create a gzip compressed content
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte(falcoRuleYaml))
		Expect(err).To(BeNil())
		gz.Close()

		decompressedContent, err := decompressRulesFile(buf.Bytes())
		Expect(err).To(BeNil())
		Expect(decompressedContent).To(Equal(falcoRuleYaml))
	})

	It("should return an error for invalid gzip content", func() {
		invalidGzipContent := []byte("invalid_gzip_content")

		decompressedContent, err := decompressRulesFile(invalidGzipContent)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("failed to create gzip reader"))
		Expect(decompressedContent).To(BeEmpty())
	})

	It("should return an error when isize is smaller than expected", func() {
		// Create a gzip compressed content
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte(falcoRuleYaml))
		Expect(err).To(BeNil())
		gz.Close()

		// Modify the isize in the gzip trailer to be smaller than the actual size
		gzipContent := buf.Bytes()
		gzipContent[len(gzipContent)-4] = 0x00
		gzipContent[len(gzipContent)-3] = 0x00
		gzipContent[len(gzipContent)-2] = 0x00
		gzipContent[len(gzipContent)-1] = 0x00

		decompressedContent, err := decompressRulesFile(gzipContent)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("isize in gzip trailer did not match the actual uncompressed size"))
		Expect(decompressedContent).To(BeEmpty())
	})

	It("should return an error when isize is larger than expected", func() {
		// Create a gzip compressed content
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte(falcoRuleYaml))
		Expect(err).To(BeNil())
		gz.Close()

		// Modify the isize in the gzip trailer to be larger than the actual size
		gzipContent := buf.Bytes()
		gzipContent[len(gzipContent)-4] = 0xFF
		gzipContent[len(gzipContent)-3] = 0xFF
		gzipContent[len(gzipContent)-2] = 0xFF
		gzipContent[len(gzipContent)-1] = 0xFF

		decompressedContent, err := decompressRulesFile(gzipContent)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("uncompressed size is larger than 1 MiB"))
		Expect(decompressedContent).To(BeEmpty())
	})

	It("should return an error for broken gzip data", func() {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte("valid content for gzip but later destoryed"))
		Expect(err).To(BeNil())
		gz.Close()

		// Corrupt the gzip data
		gzipContent := buf.Bytes()
		for i := 10; i < 15; i++ {
			if gzipContent[i] == 0xFF {
				gzipContent[i] = 0x00
			} else {
				gzipContent[i] = 0xFF
			}
		}

		// Call decompressRulesFile
		decompressedContent, err := decompressRulesFile(gzipContent)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("failed to read gzipped data"))
		Expect(decompressedContent).To(BeEmpty())
	})
})

var _ = Describe("validateYaml", func() {
	It("should return nil for valid YAML content", func() {
		validYaml := `
key1:
  subkey1: value1
  subkey2: value2
`
		err := validateYaml(validYaml)
		Expect(err).To(BeNil())
	})

	It("should return an error for invalid YAML content", func() {
		invalidYaml := `
key1:
  subkey1: value1
 subkey2: value2  # Incorrect indentation
`
		err := validateYaml(invalidYaml)
		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("data is not in valid yaml format"))
	})
})
