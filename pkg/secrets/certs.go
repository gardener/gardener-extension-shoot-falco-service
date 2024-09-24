// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

const (
	keyBitSize = 4096
)

var (
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
)

type FalcoCas struct {
	ServerCaKey  *rsa.PrivateKey
	ServerCaCert *x509.Certificate
	ClientCaKey  *rsa.PrivateKey
	ClientCaCert *x509.Certificate
}

type FalcoCertificates struct {
	ServerKey  *rsa.PrivateKey
	ServerCert *x509.Certificate
	ClientKey  *rsa.PrivateKey
	ClientCert *x509.Certificate
}

func generateCACertificate(commonName string, customLifetime time.Duration) (*rsa.PrivateKey, *x509.Certificate, error) {

	key, err := rsa.GenerateKey(rand.Reader, keyBitSize)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	caKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA384WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(customLifetime),

		KeyUsage:              caKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	newCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, newCert, nil
}

func caNeedsRenewal(cert *x509.Certificate, maxAge time.Duration) bool {
	certAge := time.Since(cert.NotBefore)
	return certAge >= maxAge
}

func CaNeedsRenewal(certs *FalcoCas, maxAge time.Duration) bool {
	return caNeedsRenewal(certs.ServerCaCert, maxAge) || caNeedsRenewal(certs.ClientCaCert, maxAge)
}

func CertsNeedRenewal(certs *FalcoCertificates, maxAge time.Duration) bool {
	return caNeedsRenewal(certs.ServerCert, maxAge) || caNeedsRenewal(certs.ClientCert, maxAge)
}

func GenerateFalcoCas(clusterName string, lifetime time.Duration) (*FalcoCas, error) {

	falcoCas := FalcoCas{}

	skey, sca, err := generateCACertificate("ca-falco-falcosidekick-"+clusterName, lifetime)
	if err != nil {
		return nil, err
	}
	falcoCas.ServerCaKey = skey
	falcoCas.ServerCaCert = sca

	ckey, cca, err := generateCACertificate("ca-falco-falco-"+clusterName, lifetime)
	if err != nil {
		return nil, err
	}
	falcoCas.ClientCaKey = ckey
	falcoCas.ClientCaCert = cca
	return &falcoCas, nil
}

func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyBitSize)
}

func GenerateKeysAndCerts(cas *FalcoCas, namespace string, lifetime time.Duration) (*FalcoCertificates, error) {

	var certs FalcoCertificates
	serverKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	certs.ServerKey = serverKey

	clientKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	certs.ClientKey = clientKey

	serverCrtSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	serverCaUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	serverCrtTemplate := x509.Certificate{
		SerialNumber: serverCrtSerialNumber,
		Subject: pkix.Name{
			CommonName: "falcosidekick." + namespace + ".svc.cluster.local",
		},
		SignatureAlgorithm: x509.SHA384WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(lifetime),

		KeyUsage:              serverCaUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              getDnsNames(namespace),
	}
	serverCrtDerBytes, err := x509.CreateCertificate(rand.Reader, &serverCrtTemplate, cas.ServerCaCert, serverKey.Public(), cas.ServerCaKey)
	if err != nil {
		return nil, err
	}
	serverCrt, err := x509.ParseCertificate(serverCrtDerBytes)
	if err != nil {
		return nil, err
	}
	certs.ServerCert = serverCrt

	clientCrtSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	clientCaUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	clientCrtTemplate := x509.Certificate{
		SerialNumber: clientCrtSerialNumber,
		Subject: pkix.Name{
			CommonName: "falcosidekick." + namespace + ".svc.cluster.local",
		},
		SignatureAlgorithm: x509.SHA384WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(lifetime),

		KeyUsage:              clientCaUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              getDnsNames(namespace),
	}
	clientCrtDerBytes, err := x509.CreateCertificate(rand.Reader, &clientCrtTemplate, cas.ClientCaCert, clientKey.Public(), cas.ClientCaKey)
	if err != nil {
		return nil, err
	}
	clientCrt, err := x509.ParseCertificate(clientCrtDerBytes)
	if err != nil {
		return nil, err
	}
	certs.ClientCert = clientCrt
	return &certs, nil
}

func DecodePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(key)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode server ca key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func DecodeCertificate(cert []byte) (*x509.Certificate, error) {
	var block *pem.Block
	block, _ = pem.Decode(cert)
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("private key is of the wrong type, must be \"RSA PRIVATE KEY\", but is: %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func EncodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
}

func EncodeCertificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		},
	)
}

func LoadCertificatesFromSecret(certs *corev1.Secret) (*FalcoCas, *FalcoCertificates, error) {

	allKeys := []string{
		constants.FalcoServerCaKey,
		constants.FalcoServerCaCert,
		constants.FalcoClientCaKey,
		constants.FalcoClientCaCert,
		constants.FalcoServerKey,
		constants.FalcoServerCert,
		constants.FalcoClientKey,
		constants.FalcoClientCert,
	}
	for _, k := range allKeys {
		if _, ok := certs.Data[k]; !ok {
			return nil, nil, fmt.Errorf("stored secret does not contain expected key %s", k)
		}
	}
	serverCaKey, err := DecodePrivateKey(certs.Data[constants.FalcoServerCaKey])
	if err != nil {
		return nil, nil, err
	}
	serverCaCert, err := DecodeCertificate(certs.Data[constants.FalcoServerCaCert])
	if err != nil {
		return nil, nil, err
	}
	clientCaKey, err := DecodePrivateKey(certs.Data[constants.FalcoClientCaKey])
	if err != nil {
		return nil, nil, err
	}
	clientCaCert, err := DecodeCertificate(certs.Data[constants.FalcoClientCaCert])
	if err != nil {
		return nil, nil, err
	}
	serverKey, err := DecodePrivateKey(certs.Data[constants.FalcoServerKey])
	if err != nil {
		return nil, nil, err
	}
	serverCert, err := DecodeCertificate(certs.Data[constants.FalcoServerCert])
	if err != nil {
		return nil, nil, err
	}
	clientKey, err := DecodePrivateKey(certs.Data[constants.FalcoClientKey])
	if err != nil {
		return nil, nil, err
	}
	clientCert, err := DecodeCertificate(certs.Data[constants.FalcoClientCert])
	if err != nil {
		return nil, nil, err
	}
	return &FalcoCas{
			ServerCaKey:  serverCaKey,
			ServerCaCert: serverCaCert,
			ClientCaKey:  clientCaKey,
			ClientCaCert: clientCaCert,
		},
		&FalcoCertificates{
			ServerKey:  serverKey,
			ServerCert: serverCert,
			ClientKey:  clientKey,
			ClientCert: clientCert,
		}, nil
}

func StoreFalcoCasInSecret(cas *FalcoCas, certs *FalcoCertificates, secret *corev1.Secret) {
	secret.Data = map[string][]byte{
		constants.FalcoServerCaKey:  EncodePrivateKey(cas.ServerCaKey),
		constants.FalcoServerCaCert: EncodeCertificate(cas.ServerCaCert),
		constants.FalcoClientCaKey:  EncodePrivateKey(cas.ClientCaKey),
		constants.FalcoClientCaCert: EncodeCertificate(cas.ClientCaCert),
		constants.FalcoServerKey:    EncodePrivateKey(certs.ServerKey),
		constants.FalcoServerCert:   EncodeCertificate(certs.ServerCert),
		constants.FalcoClientKey:    EncodePrivateKey(certs.ClientKey),
		constants.FalcoClientCert:   EncodeCertificate(certs.ClientCert),
	}
}

func getDnsNames(namesapce string) []string {
	return []string{
		"falcosidekick",
		"falcosidekick." + namesapce,
		"falcosidekick." + namesapce + ".svc",
		"falcosidekick." + namesapce + ".svc.cluster",
		"falcosidekick." + namesapce + ".svc.cluster.local",
	}
}
