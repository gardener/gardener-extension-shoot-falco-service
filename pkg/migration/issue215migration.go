// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package migration

import (
	"fmt"
	"sort"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/go-logr/logr"
)

func IsIssue215Migrated(config *service.FalcoServiceConfig) bool {

	if config.Resources != nil || config.Output != nil {
		return false
	}
	return true
}

func MigrateIssue215(log logr.Logger, falcoConf *service.FalcoServiceConfig) {
	falcoConf.Resources = nil
	if falcoConf.Gardener != nil {
		tmpArray := make([]string, 0)
		if *falcoConf.Gardener.UseFalcoRules {
			tmpArray = append(tmpArray, "falco-rules")
		}
		if *falcoConf.Gardener.UseFalcoIncubatingRules {
			tmpArray = append(tmpArray, "falco-incubating-rules")
		}
		if *falcoConf.Gardener.UseFalcoSandboxRules {
			tmpArray = append(tmpArray, "falco-sandbox-rules")
		}
		if len(tmpArray) > 0 {
			falcoConf.StandardRules = &tmpArray
		}
		if len(falcoConf.Gardener.CustomRules) > 0 {
			falcoConf.CustomRules = &falcoConf.Gardener.CustomRules
		}
		falcoConf.Gardener = nil
	}

	falcoConf.Events = &service.Events{}
	if falcoConf.Output.LogFalcoEvents != nil && *falcoConf.Output.LogFalcoEvents {
		falcoConf.Events.Destinations = append(falcoConf.Events.Destinations, "stdout")
	}
	switch *falcoConf.Output.EventCollector {
	case "cluster":
		falcoConf.Events.Destinations = append(falcoConf.Events.Destinations, "logging")
	case "central":
		falcoConf.Events.Destinations = append(falcoConf.Events.Destinations, "central")
	case "custom":
		falcoConf.Events.Destinations = append(falcoConf.Events.Destinations, "custom")
		falcoConf.Events.CustomConfig = falcoConf.Output.CustomWebhook.SecretRef
	}
	// sort elements of falcoConf.Events.Destinations
	sort.Sort(sort.StringSlice(falcoConf.Events.Destinations))
	falcoConf.Output = nil
	fmt.Println("Migrated", falcoConf)
}
