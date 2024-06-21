// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCertificateExpiration(t *testing.T) {

	duration := time.Hour
	cas, err := GenerateFalcoCas("dummy", duration)
	if err != nil {
		t.Error(err)
	}

	maxAgeLong := time.Minute * 30
	if caNeedsRenewal(cas.ClientCaCert, maxAgeLong) != false {
		t.Error("we should not require a new certifcate just now.")
	}
	if CaNeedsRenewal(cas, maxAgeLong) != false {
		t.Error("we should not require a new certifcate just now.")
	}

	maxAgeShort := time.Minute * 0
	if caNeedsRenewal(cas.ClientCaCert, maxAgeShort) != true {
		t.Error("we should require a new certifcate by now.")
	}
	if CaNeedsRenewal(cas, maxAgeShort) != true {
		t.Error("we should not require a new certifcate just now.")
	}
}

func isIssuer(cert *x509.Certificate, ca *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func TestFull(t *testing.T) {
	duration := time.Hour
	cas, err := GenerateFalcoCas("dummyname", duration)
	if err != nil {
		t.Error(err)
	}
	shortDuration := time.Minute * 5
	certs, err := GenerateKeysAndCerts(cas, "dummy", shortDuration)
	if err != nil {
		t.Error(err)
	}
	if CertsNeedRenewal(certs, time.Minute*5) {
		t.Error("Cert should not require renewal")
	}
	if !CertsNeedRenewal(certs, time.Minute*0) {
		t.Error("Cert should require renewal")
	}
	err = isIssuer(certs.ClientCert, cas.ClientCaCert)
	if err != nil {
		t.Error("Certificate should verify ok", err)
	}
	err = isIssuer(certs.ServerCert, cas.ClientCaCert)
	if err == nil {
		t.Error("Certificate should not verify ok")
	}
}
