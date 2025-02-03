// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type TokenIssuer struct {
	// private key for signing tokens
	privateKey *rsa.PrivateKey
	// validity of the token in days
	tokenValidity *metav1.Duration
}

func NewTokenIssuer(key string, validity *metav1.Duration) (*TokenIssuer, error) {

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
	key, err := DecodePrivateKey([]byte(keyPEM))
	if err != nil {
		return err
	}
	t.privateKey = key
	return nil
}

func (t *TokenIssuer) calculateExipryDate() time.Time {
	return time.Now().Add(t.tokenValidity.Duration)
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
