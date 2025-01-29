// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"github.com/go-logr/logr"

	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

// Falco Service configuration must be mutated to the new format by the
// webhook, however it must also be read by the controller before it has
// been mutated (the shoot mutator does not run if the controller is
// exchanged)

func MigrateFalcoServiceConfig(log logr.Logger, falcoServiceConfig *apisservice.FalcoServiceConfig, defaultEventCollector *string) *apisservice.FalcoServiceConfig {

	// remove old custom webhook configuration if it is disabled
	if falcoServiceConfig.CustomWebhook != nil && falcoServiceConfig.CustomWebhook.Enabled == nil {
		log.Info("Migrating FalcoServiceConfig to new format (disabled custom webhook)")
		falcoServiceConfig.CustomWebhook = nil
	}
	if falcoServiceConfig.CustomWebhook != nil && falcoServiceConfig.CustomWebhook.Enabled != nil && !*falcoServiceConfig.CustomWebhook.Enabled {
		log.Info("Migrating FalcoServiceConfig to new format (disabled custom webhook)")
		falcoServiceConfig.CustomWebhook = nil
	}

	if falcoServiceConfig.Output != nil {
		// it has been migrated, all good
		return falcoServiceConfig
	} else {
		if falcoServiceConfig.CustomWebhook != nil && falcoServiceConfig.CustomWebhook.Enabled != nil && *falcoServiceConfig.CustomWebhook.Enabled {
			log.Info("Migrating FalcoServiceConfig to new format (custom webhook)")
			t := "custom"
			falcoServiceConfig.Output.EventCollector = &t
			tb := false
			falcoServiceConfig.Output.LogFalcoEvents = &tb
			falcoServiceConfig.Output.CustomWebhook = falcoServiceConfig.CustomWebhook
			falcoServiceConfig.CustomWebhook = nil
			return falcoServiceConfig
		} else {
			log.Info("Migrating FalcoServiceConfig to new format (" + *defaultEventCollector + ")")
			var tb bool
			if *defaultEventCollector == "none" {
				tb = true
			} else {
				tb = false
			}
			falcoServiceConfig.Output = &apisservice.Output{
				EventCollector: defaultEventCollector,
				LogFalcoEvents: &tb,
			}
			return falcoServiceConfig
		}
	}
}
