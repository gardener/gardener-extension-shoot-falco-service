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
	ServerCaKey string
	ServerCaCrt string
	ServerKey   string
	ServerCrt   string
	ClientCaKey string
	ClientCaCrt string
	ClientKey   string
	ClientCrt   string
}

func GenerateCertificate(commonName string) (*rsa.PrivateKey, *x509.Certificate, error) {

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
		NotAfter:           time.Now().Add(constants.DefaultCertificateLifetime),

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

func CaNeedsRenewal(certs *FalcoCas) bool {
	expiration := time.Now().Add(constants.DefaultCertificateRenewAfter)
	serverCaExpired := expiration.After(certs.ServerCaCert.NotAfter)
	clientCaExpired := expiration.After(certs.ClientCaCert.NotAfter)
	return serverCaExpired || clientCaExpired
}

func GenerateFalcoCas(clusterName string) (*FalcoCas, error) {

	falcoCas := FalcoCas{}

	skey, sca, err := GenerateCertificate("ca-falco-falcosidekick-" + clusterName)
	if err != nil {
		return nil, err
	}
	falcoCas.ServerCaKey = skey
	falcoCas.ServerCaCert = sca

	ckey, cca, err := GenerateCertificate("ca-falco-falco-" + clusterName)
	if err != nil {
		return nil, err
	}
	falcoCas.ClientCaKey = ckey
	falcoCas.ClientCaCert = cca
	return &falcoCas, nil
}

func GenerateKeysAndCerts(cas *FalcoCas, namespace string) (*FalcoCertificates, error) {

	serverKey, err := rsa.GenerateKey(rand.Reader, keyBitSize)
	if err != nil {
		return nil, err
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, keyBitSize)
	if err != nil {
		return nil, err
	}

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
		NotAfter:           time.Now().Add(time.Hour * 720),

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
		NotAfter:           time.Now().Add(time.Hour * 720),

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

	serverCaKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(cas.ServerCaKey),
		},
	)
	serverCaCrtPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cas.ServerCaCert.Raw,
		},
	)
	serverKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
		},
	)
	serverCrtPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: serverCrtDerBytes,
		},
	)

	clientCaKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(cas.ClientCaKey),
		},
	)
	clientCaCrtPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cas.ClientCaCert.Raw,
		},
	)
	clientKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
		},
	)
	clientCrtPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCrtDerBytes,
		},
	)
	return &FalcoCertificates{
		ServerCaKey: string(serverCaKeyPEM),
		ServerCaCrt: string(serverCaCrtPEM),
		ServerKey:   string(serverKeyPEM),
		ServerCrt:   string(serverCrtPEM),

		ClientCaKey: string(clientCaKeyPEM),
		ClientCaCrt: string(clientCaCrtPEM),
		ClientKey:   string(clientKeyPEM),
		ClientCrt:   string(clientCrtPEM),
	}, nil
}

func LoadCertificatesFromSecret(certs *corev1.Secret) (*FalcoCas, error) {
	var block *pem.Block
	block, _ = pem.Decode(certs.Data[constants.FalcoServerCaKey])
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode server ca key")
	}
	serverCaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(certs.Data[constants.FalcoServerCaCert])
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode server ca certificate")
	}
	serverCaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(certs.Data[constants.FalcoClientCaKey])
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode client ca key")
	}
	clientCaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(certs.Data[constants.FalcoClientCaCert])
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode server ca certificate")
	}
	clientCaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &FalcoCas{
		ServerCaKey:  serverCaKey,
		ServerCaCert: serverCaCert,
		ClientCaKey:  clientCaKey,
		ClientCaCert: clientCaCert,
	}, nil
}

func StoreFalcoCasInSecret(cas *FalcoCas, certs *corev1.Secret) {

	serverCaKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(cas.ServerCaKey),
		},
	)

	serverCaCrtPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cas.ServerCaCert.Raw,
		},
	)
	clientCaKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(cas.ClientCaKey),
		},
	)
	clientCaCrtPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cas.ClientCaCert.Raw,
		},
	)
	certs.Data = map[string][]byte{
		constants.FalcoServerCaKey:  serverCaKeyPEM,
		constants.FalcoServerCaCert: serverCaCrtPEM,
		constants.FalcoClientCaKey:  clientCaKeyPEM,
		constants.FalcoClientCaCert: clientCaCrtPEM,
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
