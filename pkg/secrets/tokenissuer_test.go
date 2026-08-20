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

	Describe("Token Caching", func() {
		It("should return the same token on repeated calls within validity window", func() {
			validity := metav1.Duration{Duration: 7 * 24 * time.Hour}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			token1, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			token2, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			Expect(token1).To(Equal(token2), "Expected cached token to be returned on second call")
		})

		It("should return independent tokens for different cluster identities", func() {
			validity := metav1.Duration{Duration: 7 * 24 * time.Hour}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			tokenA, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			tokenB, err := issuer.IssueToken("cluster-b")
			Expect(err).NotTo(HaveOccurred())

			Expect(tokenA).NotTo(Equal(tokenB), "Different clusters should get different tokens")
		})

		It("should issue a new token when validity is shorter than min refresh threshold", func() {
			// With validity < minRefreshBefore (1h), every call should issue a fresh token
			// because the remaining time can never exceed the clamped threshold.
			validity := metav1.Duration{Duration: 2 * time.Second}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			token1, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			// Even without sleeping, the second call should issue a new token
			// because remaining (≈2s) < refreshThreshold (clamped to 1h)
			time.Sleep(1100 * time.Millisecond)

			token2, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			Expect(token1).NotTo(Equal(token2), "Expected a new token since validity is below min refresh threshold")
		})

		It("should cache IssueClusterIdentityToken independently", func() {
			validity := metav1.Duration{Duration: 7 * 24 * time.Hour}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			token1, err := issuer.IssueClusterIdentityToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			token2, err := issuer.IssueClusterIdentityToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			Expect(token1).To(Equal(token2), "Expected cached cluster identity token to be returned")
		})

		It("should cache IssueToken and IssueClusterIdentityToken separately", func() {
			validity := metav1.Duration{Duration: 7 * 24 * time.Hour}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			tokenIssue, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			tokenCIT, err := issuer.IssueClusterIdentityToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			Expect(tokenIssue).NotTo(Equal(tokenCIT), "IssueToken and IssueClusterIdentityToken should produce different tokens")
		})

		It("should cache tokens with long validity (refresh at 60% of lifetime)", func() {
			// With 90 days validity, the refresh threshold is 60% = 54 days.
			// A freshly issued token has ~90 days remaining, well above the threshold,
			// so the cached token is returned on a subsequent call.
			validity := metav1.Duration{Duration: 90 * 24 * time.Hour}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			token1, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			token2, err := issuer.IssueToken("cluster-a")
			Expect(err).NotTo(HaveOccurred())

			Expect(token1).To(Equal(token2), "Long-lived token should be cached")
		})
	})

	Describe("IssueClusterIdentityToken", func() {
		It("should issue a valid JWT with correct claims", func() {
			validity := metav1.Duration{Duration: 7 * 24 * time.Hour}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			clusterIdentity := "shoot--garden--aws-ha-6fe5a58a-f98e-4cf3-9fbd-197d5bcb2a78"
			tokenString, err := issuer.IssueClusterIdentityToken(clusterIdentity)
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

			Expect(claims["iss"]).To(Equal("urn:gardener:gardener-falco-extension"))
			Expect(claims["sub"]).To(Equal(clusterIdentity))
			Expect(claims).To(HaveKey("iat"))
			Expect(claims).To(HaveKey("exp"))
			Expect(claims).NotTo(HaveKey("aud"))
			Expect(claims).NotTo(HaveKey("gardener-falco"))
		})

		It("should set expiration based on configured token lifetime", func() {
			validity := metav1.Duration{Duration: 48 * time.Hour}
			issuer, err := secrets.NewTokenIssuer(validKey, &validity)
			Expect(err).NotTo(HaveOccurred())

			tokenString, err := issuer.IssueClusterIdentityToken("test-cluster")
			Expect(err).NotTo(HaveOccurred())

			pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(validKeyPub))
			Expect(err).NotTo(HaveOccurred())

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return pubKey, nil
			})
			Expect(err).NotTo(HaveOccurred())

			claims := token.Claims.(jwt.MapClaims)
			exp := time.Unix(int64(claims["exp"].(float64)), 0)
			iat := time.Unix(int64(claims["iat"].(float64)), 0)

			Expect(exp.Sub(iat)).To(Equal(48 * time.Hour))
		})
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
