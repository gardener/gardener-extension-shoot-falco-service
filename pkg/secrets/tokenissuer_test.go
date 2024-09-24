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
	validKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgHbuj/NcU//RrzGTCJDNY4UppcUyrXztwG6+l+UY35dXxcSfYyuC
ONg1ChZp2eI6bqS8Ama2KQprUKaKsauzz/xNWGEBuJPsx5MRRjrKj+WNk9Kj4UdO
PFVVcmXlRq3PknVYo5YJ3ASvb1VujCg4KQzI7OpJIbyfJeCyBSLSsDhPAgMBAAEC
gYBcisbiE16dOVi8F2/b1KVysXR23DcYdZt90Lo6nr8kcTzHAUrWSQ7YVXUS+ax7
lwIPFug7adTHcbegz1zugQz9cVGmvX/QAP+8eDYUJ1+JC568ozon+/q5c0y6UhCG
yjl0iwTcDFj/XQq7MLbOMvBKETJrfc8Qo/6ft5SKpC7t4QJBAMIFm4Al+zAVO2RH
U0u9PTQg5IIndCEX1T4Dzl2ZxpV0iHo3AHzOW4lRGDZK1p/SBmJMKjm4pE7+Xr7r
zKz2mrECQQCc7F8Hs7EOLyjvEpI6C0b3/q2vEqZFV0bJdsQ8KfCJGM5RtCaAFMkk
TOUQhq6QR70gBI0nvXsId0nanqJVcsL/AkAm0KZeSbrp0KWUFyzTzyUKY7YzT59M
646unGZRlW0EA082XACN916apw2X9vre+E5spd4gtA6y+vKLcXL9+0vRAkBPanSB
glgVtJpDu6NTSsfE1Bf0JT0OlKfXZ4rSY+s+htZLlR9y7JILE/tNTMvlatj07ji9
pvAwDabLxEKleenjAkAqnSTy7VAsUIPHz7ZTsPYq5ZnVqrqeaU6pIGBxpB5+bShA
WAvv4q2FmZ+UEVtwNmUPutGA0TkxeW1MkfSPczml
-----END RSA PRIVATE KEY-----`

	publicKeyPart = `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHbuj/NcU//RrzGTCJDNY4UppcUy
rXztwG6+l+UY35dXxcSfYyuCONg1ChZp2eI6bqS8Ama2KQprUKaKsauzz/xNWGEB
uJPsx5MRRjrKj+WNk9Kj4UdOPFVVcmXlRq3PknVYo5YJ3ASvb1VujCg4KQzI7OpJ
IbyfJeCyBSLSsDhPAgMBAAE=
-----END PUBLIC KEY-----`
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

    if !tm.Truncate(24*time.Hour).Equal(time.Now().AddDate(0,0,validity).Truncate(24*time.Hour)) {
        t.Error("JWT expiration is wrong")
    }
}
