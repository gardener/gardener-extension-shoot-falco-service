// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
