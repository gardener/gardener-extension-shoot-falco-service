// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	"encoding/json"
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
	t.Log(string(js))
	for _, fv := range versions.Falco.FalcoVersions {
		for _, image := range iv {
			if *image.Version == fv.Version && image.Name == "falco" {
				found = true
				break
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
				break
			}
		}
		if !found {
			t.Errorf("no images found for %s version %s", "falcosidekick", fv.Version)
		}
	}
	for _, image := range iv {
		found = false
		t.Logf("    image: %s:%s:%s\n", image.Name, *image.Version, *image.Tag)
		for _, fv := range versions.Falco.FalcoVersions {
			if *image.Version == fv.Version && image.Name == "falco" {
				found = true
				t.Log("Found")
				break
			}
		}
		for _, fv := range versions.FalcoSidekickVersions.FalcosidekickVersions {
			if *image.Version == fv.Version && image.Name == "falcosidekick" {
				found = true
				t.Log("Found sidekick")
				break
			}
		}
		for _, fv := range versions.FalcoCtlVersions.FalcoctlVersions {
			if *image.Version == fv.Version && image.Name == "falcoctl" {
				found = true
				t.Log("Found falcoctl")
				break
			}
		}
		if !found {
			t.Errorf("no version maintained for image %s version %s", image.Name, *image.Version)
		}
	}
}
