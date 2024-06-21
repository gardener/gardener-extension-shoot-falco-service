// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/gardener/gardener/pkg/utils/imagevector"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
)

var (
	versions falco.Falco
	iv       imagevector.ImageVector
)

func init() {
	versions = falco.FalcoVersions()
	iv = ImageVector()
}

// Test whether there are images for all Falco versions
func TestForImageIntegrity(t *testing.T) {
	var found bool = false
	js, _ := json.Marshal(iv)
	fmt.Println(string(js))
	for _, fv := range versions.Falco.FalcoVersions {
		for _, image := range iv {
			fmt.Printf("    image: %s:%s:%s\n", image.Name, *image.Version, *image.Tag)
			if *image.Version == fv.Version && image.Name == "falco" {
				found = true
			}
		}
		if !found {
			t.Errorf("no images found for %s version %s", "falco", fv.Version)
		}
	}
	found = false
	for _, fv := range versions.FalcoSidekickVersions.FalcosidekickVersions {
		for _, image := range iv {
			if *image.Version == fv.Version && image.Name == "falcosidekick" {
				found = true
			}
		}
		if !found {
			t.Errorf("no images found for %s version %s", "falcosidekick", fv.Version)
		}
	}
}
