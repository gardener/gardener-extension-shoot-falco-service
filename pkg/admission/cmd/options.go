// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	webhookcmd "github.com/gardener/gardener/extensions/pkg/webhook/cmd"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/mutator"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/admission/validator"
)

// GardenWebhookSwitchOptions are the webhookcmd.SwitchOptions for the admission webhooks.
func GardenWebhookSwitchOptions() *webhookcmd.SwitchOptions {
	return webhookcmd.NewSwitchOptions(
		webhookcmd.Switch(validator.ValidatorName, func(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
			return validator.New(mgr, nil)
		}),
		webhookcmd.Switch(mutator.MutatorName, func(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
			return mutator.New(mgr, nil)
		}),
	)
}
