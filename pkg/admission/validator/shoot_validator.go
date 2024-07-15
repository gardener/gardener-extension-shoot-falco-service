// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"errors"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
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

	falcoConf, err := s.extractFalcoConfig(shoot)
	if err != nil {
		return err
	}

	allErrs := []error{}

	// TODO enable again when testing is done
	// if err := verifyFalcoVersion(falcoConf); err != nil {
	// 	allErrs = append(allErrs, err)
	// }

	if err := verifyResources(falcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := verifyFalcoCtl(falcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := verifyGardenerSet(falcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := verifyWebhook(falcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if len(allErrs) > 0 {
		return errors.Join(allErrs...)
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
	if gardenerManager.UseFalcoRules == nil || gardenerManager.UseFalcoIncubatingRules == nil || gardenerManager.UseFalcoSandboxRules == nil {
		return fmt.Errorf("gardener rules not set")
	}
	// RulesRef will be set to default val as not a pointer
	return nil
}

func verifyWebhook(falcoConf *service.FalcoServiceConfig) error {
	webhook := falcoConf.CustomWebhook
	if webhook == nil {
		return fmt.Errorf("webhook is nil")
	} else if webhook.Enabled == nil {
		return fmt.Errorf("webhook needs to be either enabled or disbaled")
	} else if *webhook.Enabled && webhook.Address == nil {
		return fmt.Errorf("webhook is enabled but without address")
	}
	// may also want to enforce headers at some point
	return nil
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

	versions := profile.FalcoProfileManagerInstance.GetFalcoVersions()
	if err := verifyFalcoVersionInVersions(falcoConf, versions); err != nil {
		return err
	}
	return nil
}

func verifyFalcoVersionInVersions(falcoConf *service.FalcoServiceConfig, versions *map[string]profile.Version) error {
	chosenVersion := falcoConf.FalcoVersion
	if chosenVersion == nil {
		return fmt.Errorf("falcoVersion is nil")
	}

	for _, ver := range *versions {
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
		return true
	}

	if ext.Disabled != nil {
		return *ext.Disabled
	}
	return false
}

// findExtension returns shoot-falco-service extension.
func (s *shoot) findExtension(shoot *core.Shoot) *core.Extension {
	for i, ext := range shoot.Spec.Extensions {
		if ext.Type == constants.ExtensionType {
			return &shoot.Spec.Extensions[i]
		}
	}
	return nil
}

func (s *shoot) extractFalcoConfig(shoot *core.Shoot) (*service.FalcoServiceConfig, error) {
	ext := s.findExtension(shoot)
	if ext != nil && ext.ProviderConfig != nil {
		falcoConfig := &service.FalcoServiceConfig{}
		if _, _, err := s.decoder.Decode(ext.ProviderConfig.Raw, nil, falcoConfig); err != nil {
			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
		}
		return falcoConfig, nil
	}
	return nil, fmt.Errorf("no FalcoConfig found in extensions")
}
