// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// NewShootValidator returns a new instance of a shoot validator.
func NewShootValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &validator{
		decoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

// validator validates shoots
type validator struct {
	decoder runtime.Decoder
}

// Validate implements extensionswebhook.Validator.Validate
func (v *validator) Validate(ctx context.Context, new, _ client.Object) error {
	shoot, ok := new.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}
	return v.validateShoot(ctx, shoot)
}

func (v *validator) validateShoot(_ context.Context, shoot *core.Shoot) error {
	// Need check here
	if v.isDisabled(shoot) {
		return nil
	}
	allErrs := field.ErrorList{}

	if len(allErrs) != 0 {
		return allErrs.ToAggregate()
	}

	if _, err := v.extractFalcoConfig(shoot); err != nil {
		return err
	}
	return nil
}

// isDisabled returns true if extension is explicitly disabled.
func (v *validator) isDisabled(shoot *core.Shoot) bool {
	ext := v.findExtension(shoot)
	if ext == nil {
		return false
	}

	if ext.Disabled != nil {
		return *ext.Disabled
	}
	return false
}

// findExtension returns shoot-falco-service extension.
func (v *validator) findExtension(shoot *core.Shoot) *core.Extension {
	extensionType := "shoot-falco-service"
	for i, ext := range shoot.Spec.Extensions {
		if ext.Type == extensionType {
			fmt.Println(string(shoot.Spec.Extensions[i].ProviderConfig.Raw))
			return &shoot.Spec.Extensions[i]
		}
	}
	return nil
}

func (v *validator) extractFalcoConfig(shoot *core.Shoot) (*service.FalcoServiceConfig, error) {
	ext := v.findExtension(shoot)
	if ext != nil && ext.ProviderConfig != nil {
		// dnsConfig := &apisservice.DNSConfig{}
		falcoConfig := &service.FalcoServiceConfig{}
		if _, _, err := v.decoder.Decode(ext.ProviderConfig.Raw, nil, falcoConfig); err != nil {
			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
		}
		return falcoConfig, nil
	}
	return nil, nil
}
