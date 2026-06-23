// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	. "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config/validation"
)

func TestValidation(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Validation Suite")
}

func generateTestRSAKey() string {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	Expect(err).NotTo(HaveOccurred())
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

var _ = Describe("ValidateConfiguration", func() {
	It("should pass for nil Falco config", func() {
		conf := &config.Configuration{}
		Expect(ValidateConfiguration(conf)).To(BeEmpty())
	})

	It("should pass for empty global defaults", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{},
			},
		}
		Expect(ValidateConfiguration(conf)).To(BeEmpty())
	})

	It("should pass for valid global defaults", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "my-splunk", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
					{Name: "my-elastic", FalcosidekickOutput: config.FalcosidekickOutput{Key: "elasticsearch"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(BeEmpty())
	})

	It("should reject a name that conflicts with a standard destination", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "logging", FalcosidekickOutput: config.FalcosidekickOutput{Key: "loki"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(ConsistOf(
			PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("falco.globalDefaultDestinations[0].name"),
			})),
		))
	})

	It("should reject duplicate names", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "my-splunk", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
					{Name: "my-splunk", FalcosidekickOutput: config.FalcosidekickOutput{Key: "webhook"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(ConsistOf(
			PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeDuplicate),
				"Field": Equal("falco.globalDefaultDestinations[1].name"),
			})),
		))
	})

	It("should reject duplicate output keys", func() {
		conf := &config.Configuration{
			Falco: &config.Falco{
				GlobalDefaultDestinations: []config.GlobalDefaultDestination{
					{Name: "dest-a", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
					{Name: "dest-b", FalcosidekickOutput: config.FalcosidekickOutput{Key: "splunk"}},
				},
			},
		}
		Expect(ValidateConfiguration(conf)).To(ConsistOf(
			PointTo(MatchFields(IgnoreExtras, Fields{
				"Type":  Equal(field.ErrorTypeInvalid),
				"Field": Equal("falco.globalDefaultDestinations[1].falcosidekickOutput.key"),
			})),
		))
	})

	Describe("ClusterIdentityToken validation", func() {
		It("should pass when clusterIdentityToken is nil", func() {
			conf := &config.Configuration{
				Falco: &config.Falco{},
			}
			Expect(ValidateConfiguration(conf)).To(BeEmpty())
		})

		It("should pass for valid private key", func() {
			conf := &config.Configuration{
				Falco: &config.Falco{
					ClusterIdentityToken: &config.ClusterIdentityTokenConfig{
						TokenIssuerPrivateKey: generateTestRSAKey(),
					},
				},
			}
			Expect(ValidateConfiguration(conf)).To(BeEmpty())
		})

		It("should reject empty private key", func() {
			conf := &config.Configuration{
				Falco: &config.Falco{
					ClusterIdentityToken: &config.ClusterIdentityTokenConfig{
						TokenIssuerPrivateKey: "",
					},
				},
			}
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("falco.clusterIdentityToken.tokenIssuerPrivateKey"),
				})),
			))
		})

		It("should reject invalid PEM data", func() {
			conf := &config.Configuration{
				Falco: &config.Falco{
					ClusterIdentityToken: &config.ClusterIdentityTokenConfig{
						TokenIssuerPrivateKey: "not-a-valid-pem-key",
					},
				},
			}
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("falco.clusterIdentityToken.tokenIssuerPrivateKey"),
				})),
			))
		})

		It("should reject PEM with wrong block type", func() {
			wrongTypePEM := string(pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: []byte("fake-key-data"),
			}))
			conf := &config.Configuration{
				Falco: &config.Falco{
					ClusterIdentityToken: &config.ClusterIdentityTokenConfig{
						TokenIssuerPrivateKey: wrongTypePEM,
					},
				},
			}
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("falco.clusterIdentityToken.tokenIssuerPrivateKey"),
				})),
			))
		})
	})

	Context("AdditionalConfig validation", func() {
		var conf *config.Configuration

		BeforeEach(func() {
			conf = &config.Configuration{
				Falco: &config.Falco{
					Additional: &config.AdditionalConfig{
						SeedManagedResources: []config.AdditionalSeedManagedResource{
							{
								Name: "my-nginx",
								Helm: config.HelmConfig{
									OCIRepository: &gardencorev1.OCIRepository{
										Ref: ptr.To("registry-1.docker.io/bitnamicharts/nginx:25.0.5"),
									},
								},
							},
						},
					},
				},
			}
		})

		It("should pass for nil additional config", func() {
			conf.Falco.Additional = nil
			Expect(ValidateConfiguration(conf)).To(BeEmpty())
		})

		It("should pass for valid seed managed resources with OCI ref", func() {
			Expect(ValidateConfiguration(conf)).To(BeEmpty())
		})

		It("should pass for valid seed managed resources with inline chart", func() {
			conf.Falco.Additional.SeedManagedResources[0].Helm = config.HelmConfig{
				Chart: ptr.To("H4sIAAAAAAAAA+3BAQ0AAADCoPdPbQ8HFAAAAAAAAAAAAAAAAAB+BjG/"),
			}
			Expect(ValidateConfiguration(conf)).To(BeEmpty())
		})

		It("should reject empty name", func() {
			conf.Falco.Additional.SeedManagedResources[0].Name = ""
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("falco.additional.seedManagedResources[0].name"),
				})),
			))
		})

		It("should reject invalid DNS label name", func() {
			conf.Falco.Additional.SeedManagedResources[0].Name = "INVALID_NAME"
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("falco.additional.seedManagedResources[0].name"),
				})),
			))
		})

		It("should reject duplicate names", func() {
			conf.Falco.Additional.SeedManagedResources = append(
				conf.Falco.Additional.SeedManagedResources,
				conf.Falco.Additional.SeedManagedResources[0],
			)
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeDuplicate),
					"Field": Equal("falco.additional.seedManagedResources[1].name"),
				})),
			))
		})

		It("should reject when neither OCI ref nor chart is set", func() {
			conf.Falco.Additional.SeedManagedResources[0].Helm = config.HelmConfig{}
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("falco.additional.seedManagedResources[0].helm"),
				})),
			))
		})

		It("should reject when both OCI ref and chart are set", func() {
			conf.Falco.Additional.SeedManagedResources[0].Helm.Chart = ptr.To("H4sIAAAAAAAAA+3BAQ0AAADCoPdPbQ8HFAAAAAAAAAAAAAAAAAB+BjG/")
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("falco.additional.seedManagedResources[0].helm"),
				})),
			))
		})

		It("should reject nil OCI repository ref when no chart set", func() {
			conf.Falco.Additional.SeedManagedResources[0].Helm.OCIRepository.Ref = nil
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("falco.additional.seedManagedResources[0].helm"),
				})),
			))
		})

		It("should reject empty OCI repository ref when no chart set", func() {
			conf.Falco.Additional.SeedManagedResources[0].Helm.OCIRepository.Ref = ptr.To("")
			Expect(ValidateConfiguration(conf)).To(ConsistOf(
				PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("falco.additional.seedManagedResources[0].helm"),
				})),
			))
		})

		It("should report multiple errors at once", func() {
			conf.Falco.Additional.SeedManagedResources[0].Name = ""
			conf.Falco.Additional.SeedManagedResources[0].Helm = config.HelmConfig{}
			Expect(ValidateConfiguration(conf)).To(HaveLen(2))
		})
	})
})
