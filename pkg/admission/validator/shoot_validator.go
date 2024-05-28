// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
)

// NewShootValidator returns a new instance of a shoot validator.
func NewShootValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &shoot{
		decoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

// shoot validates shoots
type shoot struct {
	decoder runtime.Decoder
}

// Validate implements extensionswebhook.Validator.Validate
func (s *shoot) Validate(ctx context.Context, new, _ client.Object) error {
	shoot, ok := new.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}
	return s.validateShoot(ctx, shoot)
}

func (s *shoot) validateShoot(_ context.Context, shoot *core.Shoot) error {
	// Need check here
	if s.isDisabled(shoot) {
		return nil
	}
	allErrs := field.ErrorList{}

	if len(allErrs) != 0 {
		return allErrs.ToAggregate()
	}

	falcoConf, err := s.extractFalcoConfig(shoot)
	if err != nil {
		return err
	}

	if err := verifyFalcoVersion(falcoConf); err != nil {
		return err
	}

	if err := verifyResources(falcoConf); err != nil {
		return err
	}

	if err := verifyFalcoCtl(falcoConf); err != nil {
		return err
	}

	if err := verifyGardenerSet(falcoConf); err != nil {
		return err
	}

	if err := verifyWebhook(falcoConf); err != nil {
		return err
	}

	return nil
}

func verifyFalcoCtl(falcoConf *service.FalcoServiceConfig) error {
	if falcoConf.FalcoCtl == nil {
		return fmt.Errorf("falcoCtl is not set")
	}
	return nil
}

func verifyGardenerSet(falcoConf *service.FalcoServiceConfig) error {
	gardenerManager := falcoConf.Gardener
	if gardenerManager == nil {
		return fmt.Errorf("gardener managing configuration not set")
	}
	if gardenerManager.UseFalcoRules == nil || gardenerManager.UseFalcoIncubatingRules == nil ||  gardenerManager.UseFalcoSandboxRules == nil{
		return fmt.Errorf("gardener rules not set")
	}
	// RulesRef will be set to default val as no pointer
	return nil
}

func verifyWebhook(falcoConf *service.FalcoServiceConfig) error {
	webhook := falcoConf.CustomWebhook
	if webhook.Enabled == nil {
		return fmt.Errorf("webhook needs to be either enabled or disbaled")
	}
	if *webhook.Enabled && webhook.Address == nil {
		return fmt.Errorf("webhook is enabled but without address")
	}
	return nil
	// TODO unclear what is required and what not maybe roll out all
}

func verifyResources(falcoConf *service.FalcoServiceConfig) error {
	resource := falcoConf.Resources
	if resource == nil {
		return fmt.Errorf("resource is not defined")
	}
	if *resource != "gardener" && *resource != "falcoctl" {
		return fmt.Errorf("resource needs to be either gardener or falcoctl")
	}
	return nil
}

func verifyFalcoVersion(falcoConf *service.FalcoServiceConfig) error {
	versions := falco.FalcoVersions().Falco
	chosenVersion := falcoConf.FalcoVersion
	if chosenVersion == nil {
		return fmt.Errorf("falcoVersion is nil")
	}

	for _, ver := range versions.FalcoVersions {
		if *chosenVersion == ver.Version {
			if ver.Classification == "deprecated" {
				return fmt.Errorf("chosen version is marked as deprecated")
			}
			return nil
		}
	}
	return fmt.Errorf("version not found in possible versions")
}

// isDisabled returns true if extension is explicitly disabled.
func (s *shoot) isDisabled(shoot *core.Shoot) bool {
	ext := s.findExtension(shoot)
	if ext == nil {
		return false
	}

	if ext.Disabled != nil {
		return *ext.Disabled
	}
	return false
}

// findExtension returns shoot-falco-service extension.
func (s *shoot) findExtension(shoot *core.Shoot) *core.Extension {
	extensionType := "shoot-falco-service"
	for i, ext := range shoot.Spec.Extensions {
		if ext.Type == extensionType {
			fmt.Println(string(shoot.Spec.Extensions[i].ProviderConfig.Raw))
			return &shoot.Spec.Extensions[i]
		}
	}
	return nil
}

func (s *shoot) extractFalcoConfig(shoot *core.Shoot) (*service.FalcoServiceConfig, error) {
	ext := s.findExtension(shoot)
	if ext != nil && ext.ProviderConfig != nil {
		// dnsConfig := &apisservice.DNSConfig{}
		falcoConfig := &service.FalcoServiceConfig{}
		if _, _, err := s.decoder.Decode(ext.ProviderConfig.Raw, nil, falcoConfig); err != nil {
			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
		}
		return falcoConfig, nil
	}
	return nil, nil
}
