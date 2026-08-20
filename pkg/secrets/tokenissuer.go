// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rsa"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type cachedToken struct {
	token     string
	expiresAt time.Time
}

type TokenIssuer struct {
	// private key for signing tokens
	privateKey *rsa.PrivateKey
	// validity of the token
	tokenValidity *metav1.Duration

	mu    sync.Mutex
	cache map[string]cachedToken
}

func NewTokenIssuer(key string, validity *metav1.Duration) (*TokenIssuer, error) {

	ti := &TokenIssuer{
		tokenValidity: validity,
		cache:         make(map[string]cachedToken),
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

func (t *TokenIssuer) calculateExpiryDate() time.Time {
	return time.Now().Add(t.tokenValidity.Duration)
}

const (
	// minRefreshBefore is the minimum time before expiry at which a token is refreshed.
	// Even for very short-lived tokens, we refresh at least 1 hour before expiry.
	minRefreshBefore = 1 * time.Hour
)

// refreshThreshold returns how much time before expiry a token should be refreshed.
// It uses 60% of the token lifetime, clamped to a minimum of minRefreshBefore.
func refreshThreshold(validity time.Duration) time.Duration {
	threshold := validity * 60 / 100 // 60%
	if threshold < minRefreshBefore {
		threshold = minRefreshBefore
	}
	return threshold
}

func (t *TokenIssuer) IssueToken(clusterIdentity string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if cached, ok := t.cache[clusterIdentity]; ok {
		// Return cached token if remaining lifetime is above the refresh threshold
		remaining := time.Until(cached.expiresAt)
		if remaining > refreshThreshold(t.tokenValidity.Duration) {
			return cached.token, nil
		}
	}

	expiresAt := t.calculateExpiryDate()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"gardener-falco": map[string]string{
			"cluster-identity": clusterIdentity,
		},
		"iss": "urn:gardener:gardener-falco-extension",
		"aud": "falco-db",
		"exp": expiresAt.Unix(),
	})
	signed, err := token.SignedString(t.privateKey)
	if err != nil {
		return "", err
	}

	t.cache[clusterIdentity] = cachedToken{token: signed, expiresAt: expiresAt}
	return signed, nil
}

func (t *TokenIssuer) IssueClusterIdentityToken(clusterIdentity string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Use a prefixed key to separate from IssueToken cache entries
	cacheKey := "cit:" + clusterIdentity

	if cached, ok := t.cache[cacheKey]; ok {
		// Return cached token if remaining lifetime is above the refresh threshold
		remaining := time.Until(cached.expiresAt)
		if remaining > refreshThreshold(t.tokenValidity.Duration) {
			return cached.token, nil
		}
	}

	now := time.Now()
	expiresAt := now.Add(t.tokenValidity.Duration)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "urn:gardener:gardener-falco-extension",
		"sub": clusterIdentity,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
	})
	signed, err := token.SignedString(t.privateKey)
	if err != nil {
		return "", err
	}

	t.cache[cacheKey] = cachedToken{token: signed, expiresAt: expiresAt}
	return signed, nil
}
