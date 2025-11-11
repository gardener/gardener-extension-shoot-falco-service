// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

const (
	// ValidatorName is a common name for a validation webhook.
	ValidatorName = "validator"
	// ValidatorPath is a common path for a validation webhook.
	ValidatorPath = "/webhooks/validate"
)

var loggerInstance = log.Log.WithName("shoot-falco-service-validator-webhook")

// New creates a new webhook that validates Shoot resources.
func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	loggerInstance.Info("Setting up webhook", "name", ValidatorName)

	return extensionswebhook.New(mgr, extensionswebhook.Args{
		Provider: constants.ExtensionType,
		Name:     ValidatorName,
		Path:     ValidatorPath,
		Validators: map[extensionswebhook.Validator][]extensionswebhook.Type{
			NewShootValidator(mgr): {
				{Obj: &core.Shoot{}},
				{Obj: &core.Seed{}},
			},
		},
		Target: extensionswebhook.TargetSeed,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"extensions.extensions.gardener.cloud/shoot-falco-service": "true"},
		},
	})
}
