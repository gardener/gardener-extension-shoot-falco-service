// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	validKey, validKeyPub = genValidKey()
)

func TestNewTokenIssuserFaultyKey(t *testing.T) {
	key := "123"
	validity := metav1.Duration{Duration: 2000 * time.Second}
	_, err := NewTokenIssuer(key, &validity)
	if err == nil {
		t.Error("Did not catch wrong key format")
	}
}

func TestNewTokenIssuserValidKey(t *testing.T) {
	validity := metav1.Duration{Duration: 2000 * time.Second}
	_, err := NewTokenIssuer(validKey, &validity)
	if err != nil {
		t.Error("Could not read correct key")
	}
}

func TestTokenIssuer(t *testing.T) {
	validity := metav1.Duration{Duration: 20 * time.Hour * 24}
	issuer, err := NewTokenIssuer(validKey, &validity)
	if err != nil {
		t.Error("Could not read correct key")
	}
	tokenString, err := issuer.IssueToken("MyTestCluster")
	if err != nil {
		t.Errorf("Could not generate token")
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(validKeyPub))
	if err != nil {
		t.Error("Could not parse public key")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("Unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})

	if err != nil {
		t.Fatal(err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Error("Could not read claims")
	}

	var tm time.Time
	switch iat := claims["exp"].(type) {
	case float64:
		tm = time.Unix(int64(iat), 0)
	case json.Number:
		v, _ := iat.Int64()
		tm = time.Unix(v, 0)
	}

	if !tm.Truncate(24 * time.Hour).Equal(time.Now().Add(validity.Duration).Truncate(24 * time.Hour)) {
		t.Error("JWT expiration is wrong")
	}
}

func genValidKey() (string, string) {
	bitSize := 1028

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

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
