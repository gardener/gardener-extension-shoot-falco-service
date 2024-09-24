// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	validKey = `invalid`
)

func TestNewTokenIssuserFaultyKey(t *testing.T) {
	key := "123"
	validity := 2000
	_, err := NewTokenIssuer(key, validity)
	if err == nil {
		t.Error("Did not catch wrong key format")
	}
}

func TestNewTokenIssuserValidKey(t *testing.T) {
	validity := 2000
	_, err := NewTokenIssuer(validKey, validity)
	if err != nil {
		t.Error("Could not read correct key")
	}
}

func TestTokenIssuer(t *testing.T) {
	validity := 2000
	issuer, err := NewTokenIssuer(validKey, validity)
	if err != nil {
		t.Error("Could not read correct key")
	}
	tokenString, err := issuer.IssueToken("MyTestCluster")
	if err != nil {
		t.Errorf("Could not generate token")
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPart))
	if err != nil {
		t.Error("Could not parse public key")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
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

	if !tm.Truncate(24 * time.Hour).Equal(time.Now().AddDate(0, 0, validity).Truncate(24 * time.Hour)) {
		t.Error("JWT expiration is wrong")
	}
}
