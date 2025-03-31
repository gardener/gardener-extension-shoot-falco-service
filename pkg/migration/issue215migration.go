// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"sort"

	"github.com/go-logr/logr"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

func isIssue215Migrated(config *service.FalcoServiceConfig) bool {

	if config.Resources != nil || config.Output != nil || config.Gardener != nil {
		return false
	}
	return true
}

func migrateRules(log logr.Logger, falcoConf *service.FalcoServiceConfig) {
	if falcoConf.Gardener != nil {
		tmpArray := make([]string, 0)
		if falcoConf.Gardener.UseFalcoRules != nil && *falcoConf.Gardener.UseFalcoRules {
			tmpArray = append(tmpArray, constants.ConfigFalcoRules)
		}
		if falcoConf.Gardener.UseFalcoIncubatingRules != nil && *falcoConf.Gardener.UseFalcoIncubatingRules {
			tmpArray = append(tmpArray, constants.ConfigFalcoIncubatingRules)
		}
		if falcoConf.Gardener.UseFalcoSandboxRules != nil && *falcoConf.Gardener.UseFalcoSandboxRules {
			tmpArray = append(tmpArray, constants.ConfigFalcoSandboxRules)
		}
		if len(tmpArray) > 0 {
			if falcoConf.Rules == nil {
				falcoConf.Rules = &service.Rules{}
			}
			falcoConf.Rules.StandardRules = &tmpArray
		}
		if len(falcoConf.Gardener.CustomRules) > 0 {
			customRules := make([]service.CustomRule, 0)
			for _, rule := range falcoConf.Gardener.CustomRules {
				customRules = append(customRules, service.CustomRule{
					ResourceRef: rule,
				})
			}
			if falcoConf.Rules == nil {
				falcoConf.Rules = &service.Rules{}
			}
			falcoConf.Rules.CustomRules = &customRules
		}
		falcoConf.Gardener = nil
	}
}

func migrateOutput(log logr.Logger, falcoConf *service.FalcoServiceConfig) {
	destinations := make([]service.Destination, 0)
	if falcoConf.Output == nil {
		// no output set, use default
		destinations = append(destinations, service.Destination{
			Name: constants.FalcoEventDestinationLogging,
		})
	} else {
		if falcoConf.Output.LogFalcoEvents != nil && *falcoConf.Output.LogFalcoEvents {
			destinations = append(destinations, service.Destination{
				Name: constants.FalcoEventDestinationStdout,
			})
		}
		switch *falcoConf.Output.EventCollector {
		case "cluster":
			destinations = append(destinations, service.Destination{
				Name: constants.FalcoEventDestinationLogging,
			})
		case "central":
			destinations = append(destinations, service.Destination{
				Name: constants.FalcoEventDestinationCentral,
			})
		case "custom":
			destination := service.Destination{
				Name: constants.FalcoEventDestinationCustom,
			}
			if falcoConf.Output.CustomWebhook != nil && falcoConf.Output.CustomWebhook.SecretRef != nil {
				destination.ResourceSecretRef = falcoConf.Output.CustomWebhook.SecretRef
			}
			destinations = append(destinations, destination)
		}
		// sort elements of falcoConf.Events.Destinations
		sort.Slice(destinations, func(i, j int) bool {
			return destinations[i].Name < destinations[j].Name
		})
	}
	falcoConf.Destinations = &destinations
	falcoConf.Output = nil
}

func MigrateIssue215(log logr.Logger, falcoConf *service.FalcoServiceConfig) {
	if isIssue215Migrated(falcoConf) {
		log.Info("FalcoServiceConfig migrated, skipping")
		return
	}
	falcoConf.Resources = nil
	falcoConf.FalcoCtl = nil

	migrateRules(log, falcoConf)
	migrateOutput(log, falcoConf)
}
