// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/secrets"
)

var _ = Describe("TokenIssuer", func() {
	var (
		validKey    string
		validKeyPub string
	)

	BeforeEach(func() {
		validKey, validKeyPub = genValidKey()
	})

	It("should fail with a faulty key", func() {
		key := "123"
		validity := metav1.Duration{Duration: 2000 * time.Second}
		_, err := secrets.NewTokenIssuer(key, &validity)
		Expect(err).To(HaveOccurred())
	})

	It("should succeed with a valid key", func() {
		validity := metav1.Duration{Duration: 2000 * time.Second}
		_, err := secrets.NewTokenIssuer(validKey, &validity)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should issue a valid token with correct expiration", func() {
		validity := metav1.Duration{Duration: 20 * time.Hour * 24}
		issuer, err := secrets.NewTokenIssuer(validKey, &validity)
		Expect(err).NotTo(HaveOccurred())

		tokenString, err := issuer.IssueToken("MyTestCluster")
		Expect(err).NotTo(HaveOccurred())

		pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(validKeyPub))
		Expect(err).NotTo(HaveOccurred())

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			Expect(token.Method).To(BeAssignableToTypeOf(&jwt.SigningMethodRSA{}))
			return pubKey, nil
		})
		Expect(err).NotTo(HaveOccurred())

		claims, ok := token.Claims.(jwt.MapClaims)
		Expect(ok).To(BeTrue())

		var tm time.Time
		switch iat := claims["exp"].(type) {
		case float64:
			tm = time.Unix(int64(iat), 0)
		case json.Number:
			v, _ := iat.Int64()
			tm = time.Unix(v, 0)
		}

		Expect(tm.Truncate(24 * time.Hour)).To(Equal(time.Now().Add(validity.Duration).Truncate(24 * time.Hour)))
	})
})

func genValidKey() (string, string) {
	bitSize := 1028

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	Expect(err).NotTo(HaveOccurred())

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(key.Public().(*rsa.PublicKey)),
		},
	)
	return string(keyPEM), string(pubPEM)
}
