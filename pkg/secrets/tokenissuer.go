// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenIssuer struct {
	// private key for signing tokens
	privateKey *rsa.PrivateKey
	// validity of the token in days
	tokenValidity int
}

func NewTokenIssuer(key string, validity int) (*TokenIssuer, error) {

	ti := &TokenIssuer{
		tokenValidity: validity,
	}
	if err := ti.loadKey(key); err != nil {
		return nil, err
	} else {
		return ti, nil
	}
}

func (t *TokenIssuer) loadKey(keyPEM string) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the public key")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("private key is of the wrong type, must be \"RSA PRIVATE KEY\", type is:%s", block.Type)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	t.privateKey = key
	return nil
}

func (t *TokenIssuer) calculateExipryDate() time.Time {
	return time.Now().AddDate(0, 0, t.tokenValidity)
}

func (t *TokenIssuer) IssueToken(clusterIdentity string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"gardener-falco": map[string]string{
			"cluster-identity": clusterIdentity,
		},
		"iss": "urn:gardener:gardener-falco-extension",
		"aud": "falco-db",
		"exp": t.calculateExipryDate().Unix(),
	})
	// TODO: decide what to do if this fails (PANIC)
	return token.SignedString(t.privateKey)
}
