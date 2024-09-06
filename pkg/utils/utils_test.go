// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
)

var (
	providerConfig string = `
			{
				"apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
				"autoUpdate": false,
				"falcoVersion": "0.38.1",
				"falcoCtl": {
					"indexes": [
						{
							"name": "default",
							"url": "https://example.com"
						}
					],
					"allowedTypes": [
						"plugins",
						"rules"
					],
					"install": {
						"refs": [
								"a",
								"b"
							],
						"resolveDeps": true
					},
					"follow": {
						"refs": [
							"c"
						],
						"every": "1h"
					}
				},
				"kind": "FalcoServiceConfig",
				"resources": "falcoctl"
			}
`
	providerConfigFalcoctl *extensionsv1alpha1.Extension = &extensionsv1alpha1.Extension{
		Spec: extensionsv1alpha1.ExtensionSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				ProviderConfig: &runtime.RawExtension{
					Raw: []byte(providerConfig),
				},
			},
		},
	}
)

func TestVerifyFalcoCtlConfig(t *testing.T) {
	_, err := ExtractFalcoServiceConfig(providerConfigFalcoctl)
	if err != nil {
		t.Fatalf("FalcoServiceConfig could not be extracted %v", err)
	}
}
