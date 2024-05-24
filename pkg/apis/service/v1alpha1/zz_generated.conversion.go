//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	service "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*FalcoCtl)(nil), (*service.FalcoCtl)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcoCtl_To_service_FalcoCtl(a.(*FalcoCtl), b.(*service.FalcoCtl), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.FalcoCtl)(nil), (*FalcoCtl)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_FalcoCtl_To_v1alpha1_FalcoCtl(a.(*service.FalcoCtl), b.(*FalcoCtl), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*FalcoServiceConfig)(nil), (*service.FalcoServiceConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig(a.(*FalcoServiceConfig), b.(*service.FalcoServiceConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.FalcoServiceConfig)(nil), (*FalcoServiceConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig(a.(*service.FalcoServiceConfig), b.(*FalcoServiceConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Gardener)(nil), (*service.Gardener)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Gardener_To_service_Gardener(a.(*Gardener), b.(*service.Gardener), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Gardener)(nil), (*Gardener)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Gardener_To_v1alpha1_Gardener(a.(*service.Gardener), b.(*Gardener), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Rule)(nil), (*service.Rule)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Rule_To_service_Rule(a.(*Rule), b.(*service.Rule), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Rule)(nil), (*Rule)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Rule_To_v1alpha1_Rule(a.(*service.Rule), b.(*Rule), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Webhook)(nil), (*service.Webhook)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Webhook_To_service_Webhook(a.(*Webhook), b.(*service.Webhook), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Webhook)(nil), (*Webhook)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Webhook_To_v1alpha1_Webhook(a.(*service.Webhook), b.(*Webhook), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_FalcoCtl_To_service_FalcoCtl(in *FalcoCtl, out *service.FalcoCtl, s conversion.Scope) error {
	return nil
}

// Convert_v1alpha1_FalcoCtl_To_service_FalcoCtl is an autogenerated conversion function.
func Convert_v1alpha1_FalcoCtl_To_service_FalcoCtl(in *FalcoCtl, out *service.FalcoCtl, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoCtl_To_service_FalcoCtl(in, out, s)
}

func autoConvert_service_FalcoCtl_To_v1alpha1_FalcoCtl(in *service.FalcoCtl, out *FalcoCtl, s conversion.Scope) error {
	return nil
}

// Convert_service_FalcoCtl_To_v1alpha1_FalcoCtl is an autogenerated conversion function.
func Convert_service_FalcoCtl_To_v1alpha1_FalcoCtl(in *service.FalcoCtl, out *FalcoCtl, s conversion.Scope) error {
	return autoConvert_service_FalcoCtl_To_v1alpha1_FalcoCtl(in, out, s)
}

func autoConvert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig(in *FalcoServiceConfig, out *service.FalcoServiceConfig, s conversion.Scope) error {
	out.FalcoVersion = (*string)(unsafe.Pointer(in.FalcoVersion))
	out.AutoUpdate = in.AutoUpdate
	out.Resources = in.Resources
	if err := Convert_v1alpha1_FalcoCtl_To_service_FalcoCtl(&in.FalcoCtl, &out.FalcoCtl, s); err != nil {
		return err
	}
	if err := Convert_v1alpha1_Gardener_To_service_Gardener(&in.Gardener, &out.Gardener, s); err != nil {
		return err
	}
	if err := Convert_v1alpha1_Webhook_To_service_Webhook(&in.CustomWebhook, &out.CustomWebhook, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig is an autogenerated conversion function.
func Convert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig(in *FalcoServiceConfig, out *service.FalcoServiceConfig, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig(in, out, s)
}

func autoConvert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig(in *service.FalcoServiceConfig, out *FalcoServiceConfig, s conversion.Scope) error {
	out.FalcoVersion = (*string)(unsafe.Pointer(in.FalcoVersion))
	out.AutoUpdate = in.AutoUpdate
	out.Resources = in.Resources
	if err := Convert_service_FalcoCtl_To_v1alpha1_FalcoCtl(&in.FalcoCtl, &out.FalcoCtl, s); err != nil {
		return err
	}
	if err := Convert_service_Gardener_To_v1alpha1_Gardener(&in.Gardener, &out.Gardener, s); err != nil {
		return err
	}
	if err := Convert_service_Webhook_To_v1alpha1_Webhook(&in.CustomWebhook, &out.CustomWebhook, s); err != nil {
		return err
	}
	return nil
}

// Convert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig is an autogenerated conversion function.
func Convert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig(in *service.FalcoServiceConfig, out *FalcoServiceConfig, s conversion.Scope) error {
	return autoConvert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig(in, out, s)
}

func autoConvert_v1alpha1_Gardener_To_service_Gardener(in *Gardener, out *service.Gardener, s conversion.Scope) error {
	out.UseFalcoRules = in.UseFalcoRules
	out.UseFalcoIncubatingRules = in.UseFalcoIncubatingRules
	out.UseFalcoSandboxRules = in.UseFalcoSandboxRules
	out.RuleRefs = *(*[]service.Rule)(unsafe.Pointer(&in.RuleRefs))
	return nil
}

// Convert_v1alpha1_Gardener_To_service_Gardener is an autogenerated conversion function.
func Convert_v1alpha1_Gardener_To_service_Gardener(in *Gardener, out *service.Gardener, s conversion.Scope) error {
	return autoConvert_v1alpha1_Gardener_To_service_Gardener(in, out, s)
}

func autoConvert_service_Gardener_To_v1alpha1_Gardener(in *service.Gardener, out *Gardener, s conversion.Scope) error {
	out.UseFalcoRules = in.UseFalcoRules
	out.UseFalcoIncubatingRules = in.UseFalcoIncubatingRules
	out.UseFalcoSandboxRules = in.UseFalcoSandboxRules
	out.RuleRefs = *(*[]Rule)(unsafe.Pointer(&in.RuleRefs))
	return nil
}

// Convert_service_Gardener_To_v1alpha1_Gardener is an autogenerated conversion function.
func Convert_service_Gardener_To_v1alpha1_Gardener(in *service.Gardener, out *Gardener, s conversion.Scope) error {
	return autoConvert_service_Gardener_To_v1alpha1_Gardener(in, out, s)
}

func autoConvert_v1alpha1_Rule_To_service_Rule(in *Rule, out *service.Rule, s conversion.Scope) error {
	out.Ref = in.Ref
	return nil
}

// Convert_v1alpha1_Rule_To_service_Rule is an autogenerated conversion function.
func Convert_v1alpha1_Rule_To_service_Rule(in *Rule, out *service.Rule, s conversion.Scope) error {
	return autoConvert_v1alpha1_Rule_To_service_Rule(in, out, s)
}

func autoConvert_service_Rule_To_v1alpha1_Rule(in *service.Rule, out *Rule, s conversion.Scope) error {
	out.Ref = in.Ref
	return nil
}

// Convert_service_Rule_To_v1alpha1_Rule is an autogenerated conversion function.
func Convert_service_Rule_To_v1alpha1_Rule(in *service.Rule, out *Rule, s conversion.Scope) error {
	return autoConvert_service_Rule_To_v1alpha1_Rule(in, out, s)
}

func autoConvert_v1alpha1_Webhook_To_service_Webhook(in *Webhook, out *service.Webhook, s conversion.Scope) error {
	out.Enabled = in.Enabled
	out.Address = in.Address
	out.CustomHeaders = in.CustomHeaders
	out.Checkcerts = in.Checkcerts
	return nil
}

// Convert_v1alpha1_Webhook_To_service_Webhook is an autogenerated conversion function.
func Convert_v1alpha1_Webhook_To_service_Webhook(in *Webhook, out *service.Webhook, s conversion.Scope) error {
	return autoConvert_v1alpha1_Webhook_To_service_Webhook(in, out, s)
}

func autoConvert_service_Webhook_To_v1alpha1_Webhook(in *service.Webhook, out *Webhook, s conversion.Scope) error {
	out.Enabled = in.Enabled
	out.Address = in.Address
	out.CustomHeaders = in.CustomHeaders
	out.Checkcerts = in.Checkcerts
	return nil
}

// Convert_service_Webhook_To_v1alpha1_Webhook is an autogenerated conversion function.
func Convert_service_Webhook_To_v1alpha1_Webhook(in *service.Webhook, out *Webhook, s conversion.Scope) error {
	return autoConvert_service_Webhook_To_v1alpha1_Webhook(in, out, s)
}