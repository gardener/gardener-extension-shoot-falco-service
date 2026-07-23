// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
)

var _ = Describe("Certificate", func() {
	Describe("Expiration", func() {
		It("should not require renewal when max age is longer than elapsed time", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummy", duration)
			Expect(err).NotTo(HaveOccurred())

			maxAgeLong := time.Minute * 30
			Expect(secrets.CaNeedsRenewal(cas, maxAgeLong)).To(BeFalse())
		})

		It("should require renewal when max age is zero", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummy", duration)
			Expect(err).NotTo(HaveOccurred())

			maxAgeShort := time.Minute * 0
			Expect(secrets.CaNeedsRenewal(cas, maxAgeShort)).To(BeTrue())
		})
	})

	Describe("Full generation", func() {
		It("should generate valid CAs and certs with correct renewal behavior", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			shortDuration := time.Minute * 5
			certs, err := secrets.GenerateKeysAndCerts(cas, "dummy", shortDuration)
			Expect(err).NotTo(HaveOccurred())

			Expect(secrets.CertsNeedRenewal(certs, time.Minute*5)).To(BeFalse())
			Expect(secrets.CertsNeedRenewal(certs, time.Minute*0)).To(BeTrue())
		})

		It("should verify client cert against client CA", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			shortDuration := time.Minute * 5
			certs, err := secrets.GenerateKeysAndCerts(cas, "dummy", shortDuration)
			Expect(err).NotTo(HaveOccurred())

			err = verifyCertAgainstCA(certs.ClientCert, cas.ClientCaCert)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should not verify server cert against client CA", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			shortDuration := time.Minute * 5
			certs, err := secrets.GenerateKeysAndCerts(cas, "dummy", shortDuration)
			Expect(err).NotTo(HaveOccurred())

			err = verifyCertAgainstCA(certs.ServerCert, cas.ClientCaCert)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("certificate signed by unknown authority")))
		})

		It("should generate client cert with ClientAuth extended key usage", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			certs, err := secrets.GenerateKeysAndCerts(cas, "kube-system", duration)
			Expect(err).NotTo(HaveOccurred())

			Expect(certs.ClientCert.ExtKeyUsage).To(ContainElement(x509.ExtKeyUsageClientAuth))
			Expect(certs.ClientCert.ExtKeyUsage).NotTo(ContainElement(x509.ExtKeyUsageServerAuth))
		})
	})

	Describe("CertsNeedRegeneration", func() {
		It("should not need regeneration when certs match the namespace", func() {
			namespace := "kube-system"
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			certs, err := secrets.GenerateKeysAndCerts(cas, namespace, duration)
			Expect(err).NotTo(HaveOccurred())

			Expect(secrets.CertsNeedRegeneration(certs, namespace)).To(BeFalse())
		})

		It("should need regeneration when namespace differs", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			certs, err := secrets.GenerateKeysAndCerts(cas, "old-namespace", duration)
			Expect(err).NotTo(HaveOccurred())

			Expect(secrets.CertsNeedRegeneration(certs, "kube-system")).To(BeTrue())
		})

		It("should need regeneration when client cert lacks ClientAuth usage", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			certs, err := secrets.GenerateKeysAndCerts(cas, "kube-system", duration)
			Expect(err).NotTo(HaveOccurred())

			// Simulate old cert with ServerAuth instead of ClientAuth
			certs.ClientCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

			Expect(secrets.CertsNeedRegeneration(certs, "kube-system")).To(BeTrue())
		})

		It("should need regeneration when client cert has no ExtKeyUsage", func() {
			duration := time.Hour
			cas, err := secrets.GenerateFalcoCas("dummyname", duration)
			Expect(err).NotTo(HaveOccurred())

			certs, err := secrets.GenerateKeysAndCerts(cas, "kube-system", duration)
			Expect(err).NotTo(HaveOccurred())

			certs.ClientCert.ExtKeyUsage = nil

			Expect(secrets.CertsNeedRegeneration(certs, "kube-system")).To(BeTrue())
		})
	})

	Describe("Renewal constants sanity", func() {
		It("CA renewal threshold should be meaningfully before expiry", func() {
			Expect(constants.DefaultCALifetime-constants.DefaultCARenewAfter).
				To(BeNumerically(">=", 24*time.Hour),
					"DefaultCARenewAfter must be at least 1 day before DefaultCALifetime")
		})

		It("certificate renewal threshold should be meaningfully before expiry", func() {
			Expect(constants.DefaultCertificateLifetime-constants.DefaultCertificateRenewAfter).
				To(BeNumerically(">=", 24*time.Hour),
					"DefaultCertificateRenewAfter must be at least 1 day before DefaultCertificateLifetime")
		})
	})

	Describe("Leaf cert lifetime capping", func() {
		It("should not cap leaf cert when lifetime is shorter than CA remaining life", func() {
			caLifetime := time.Hour * 24 * 10
			cas, err := secrets.GenerateFalcoCas("dummy", caLifetime)
			Expect(err).NotTo(HaveOccurred())

			leafLifetime := time.Hour * 24 * 5
			certs, err := secrets.GenerateKeysAndCerts(cas, "kube-system", leafLifetime)
			Expect(err).NotTo(HaveOccurred())

			// leaf must not outlive CA
			Expect(certs.ServerCert.NotAfter).To(BeTemporally("<=", cas.ServerCaCert.NotAfter))
			Expect(certs.ClientCert.NotAfter).To(BeTemporally("<=", cas.ClientCaCert.NotAfter))

			// leaf should be close to the requested lifetime (within a second of clock skew)
			Expect(certs.ServerCert.NotAfter).To(BeTemporally("~", time.Now().Add(leafLifetime), time.Second))
			Expect(certs.ClientCert.NotAfter).To(BeTemporally("~", time.Now().Add(leafLifetime), time.Second))
		})

		It("should cap leaf cert to CA expiry when requested lifetime exceeds CA remaining life", func() {
			caLifetime := time.Hour * 2
			cas, err := secrets.GenerateFalcoCas("dummy", caLifetime)
			Expect(err).NotTo(HaveOccurred())

			leafLifetime := time.Hour * 24 * 365
			certs, err := secrets.GenerateKeysAndCerts(cas, "kube-system", leafLifetime)
			Expect(err).NotTo(HaveOccurred())

			// leaf must be capped to CA expiry
			Expect(certs.ServerCert.NotAfter).To(BeTemporally("~", cas.ServerCaCert.NotAfter, time.Second))
			Expect(certs.ClientCert.NotAfter).To(BeTemporally("~", cas.ClientCaCert.NotAfter, time.Second))
		})

		It("should cap leaf cert when CA has very little time remaining", func() {
			caLifetime := time.Minute * 30
			cas, err := secrets.GenerateFalcoCas("dummy", caLifetime)
			Expect(err).NotTo(HaveOccurred())

			leafLifetime := time.Hour * 24
			certs, err := secrets.GenerateKeysAndCerts(cas, "kube-system", leafLifetime)
			Expect(err).NotTo(HaveOccurred())

			// leaf should be capped to CA expiry, not 24 hours
			Expect(certs.ServerCert.NotAfter).To(BeTemporally("~", cas.ServerCaCert.NotAfter, time.Second))
			Expect(certs.ClientCert.NotAfter).To(BeTemporally("~", cas.ClientCaCert.NotAfter, time.Second))
		})

		It("should cap leaf cert exactly at CA expiry boundary", func() {
			caLifetime := time.Hour * 24
			cas, err := secrets.GenerateFalcoCas("dummy", caLifetime)
			Expect(err).NotTo(HaveOccurred())

			// request exactly the same lifetime as the CA — leaf must not exceed it
			certs, err := secrets.GenerateKeysAndCerts(cas, "kube-system", caLifetime)
			Expect(err).NotTo(HaveOccurred())

			Expect(certs.ServerCert.NotAfter).To(BeTemporally("<=", cas.ServerCaCert.NotAfter))
			Expect(certs.ClientCert.NotAfter).To(BeTemporally("<=", cas.ClientCaCert.NotAfter))
		})
	})

})

func verifyCertAgainstCA(cert *x509.Certificate, ca *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
