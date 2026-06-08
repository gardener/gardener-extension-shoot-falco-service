// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
)

// FindGlobalDefaultByName returns the GlobalDefaultDestination with the given name, or nil if not found.
func FindGlobalDefaultByName(gds []config.GlobalDefaultDestination, name string) *config.GlobalDefaultDestination {
	for i := range gds {
		if gds[i].Name == name {
			return &gds[i]
		}
	}
	return nil
}

// GlobalDefaultKeyMap builds a map from destination name to its Falcosidekick output key.
func GlobalDefaultKeyMap(gds []config.GlobalDefaultDestination) map[string]string {
	keys := make(map[string]string, len(gds))
	for _, gd := range gds {
		keys[gd.Name] = gd.FalcosidekickOutput.Key
	}
	return keys
}
