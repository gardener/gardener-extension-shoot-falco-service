//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
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
	if err := s.AddGeneratedConversionFunc((*CustomRule)(nil), (*service.CustomRule)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_CustomRule_To_service_CustomRule(a.(*CustomRule), b.(*service.CustomRule), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.CustomRule)(nil), (*CustomRule)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_CustomRule_To_v1alpha1_CustomRule(a.(*service.CustomRule), b.(*CustomRule), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Destination)(nil), (*service.Destination)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Destination_To_service_Destination(a.(*Destination), b.(*service.Destination), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Destination)(nil), (*Destination)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Destination_To_v1alpha1_Destination(a.(*service.Destination), b.(*Destination), scope)
	}); err != nil {
		return err
	}
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
	if err := s.AddGeneratedConversionFunc((*FalcoCtlIndex)(nil), (*service.FalcoCtlIndex)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcoCtlIndex_To_service_FalcoCtlIndex(a.(*FalcoCtlIndex), b.(*service.FalcoCtlIndex), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.FalcoCtlIndex)(nil), (*FalcoCtlIndex)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_FalcoCtlIndex_To_v1alpha1_FalcoCtlIndex(a.(*service.FalcoCtlIndex), b.(*FalcoCtlIndex), scope)
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
	if err := s.AddGeneratedConversionFunc((*Follow)(nil), (*service.Follow)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Follow_To_service_Follow(a.(*Follow), b.(*service.Follow), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Follow)(nil), (*Follow)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Follow_To_v1alpha1_Follow(a.(*service.Follow), b.(*Follow), scope)
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
	if err := s.AddGeneratedConversionFunc((*Install)(nil), (*service.Install)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Install_To_service_Install(a.(*Install), b.(*service.Install), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Install)(nil), (*Install)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Install_To_v1alpha1_Install(a.(*service.Install), b.(*Install), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Output)(nil), (*service.Output)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Output_To_service_Output(a.(*Output), b.(*service.Output), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Output)(nil), (*Output)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Output_To_v1alpha1_Output(a.(*service.Output), b.(*Output), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Rules)(nil), (*service.Rules)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Rules_To_service_Rules(a.(*Rules), b.(*service.Rules), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*service.Rules)(nil), (*Rules)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_service_Rules_To_v1alpha1_Rules(a.(*service.Rules), b.(*Rules), scope)
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

func autoConvert_v1alpha1_CustomRule_To_service_CustomRule(in *CustomRule, out *service.CustomRule, s conversion.Scope) error {
	out.ResourceRef = in.ResourceRef
	return nil
}

// Convert_v1alpha1_CustomRule_To_service_CustomRule is an autogenerated conversion function.
func Convert_v1alpha1_CustomRule_To_service_CustomRule(in *CustomRule, out *service.CustomRule, s conversion.Scope) error {
	return autoConvert_v1alpha1_CustomRule_To_service_CustomRule(in, out, s)
}

func autoConvert_service_CustomRule_To_v1alpha1_CustomRule(in *service.CustomRule, out *CustomRule, s conversion.Scope) error {
	out.ResourceRef = in.ResourceRef
	return nil
}

// Convert_service_CustomRule_To_v1alpha1_CustomRule is an autogenerated conversion function.
func Convert_service_CustomRule_To_v1alpha1_CustomRule(in *service.CustomRule, out *CustomRule, s conversion.Scope) error {
	return autoConvert_service_CustomRule_To_v1alpha1_CustomRule(in, out, s)
}

func autoConvert_v1alpha1_Destination_To_service_Destination(in *Destination, out *service.Destination, s conversion.Scope) error {
	out.Name = in.Name
	out.ResourceRef = in.ResourceRef
	return nil
}

// Convert_v1alpha1_Destination_To_service_Destination is an autogenerated conversion function.
func Convert_v1alpha1_Destination_To_service_Destination(in *Destination, out *service.Destination, s conversion.Scope) error {
	return autoConvert_v1alpha1_Destination_To_service_Destination(in, out, s)
}

func autoConvert_service_Destination_To_v1alpha1_Destination(in *service.Destination, out *Destination, s conversion.Scope) error {
	out.Name = in.Name
	out.ResourceRef = in.ResourceRef
	return nil
}

// Convert_service_Destination_To_v1alpha1_Destination is an autogenerated conversion function.
func Convert_service_Destination_To_v1alpha1_Destination(in *service.Destination, out *Destination, s conversion.Scope) error {
	return autoConvert_service_Destination_To_v1alpha1_Destination(in, out, s)
}

func autoConvert_v1alpha1_FalcoCtl_To_service_FalcoCtl(in *FalcoCtl, out *service.FalcoCtl, s conversion.Scope) error {
	out.Indexes = *(*[]service.FalcoCtlIndex)(unsafe.Pointer(&in.Indexes))
	out.AllowedTypes = *(*[]string)(unsafe.Pointer(&in.AllowedTypes))
	out.Install = (*service.Install)(unsafe.Pointer(in.Install))
	out.Follow = (*service.Follow)(unsafe.Pointer(in.Follow))
	return nil
}

// Convert_v1alpha1_FalcoCtl_To_service_FalcoCtl is an autogenerated conversion function.
func Convert_v1alpha1_FalcoCtl_To_service_FalcoCtl(in *FalcoCtl, out *service.FalcoCtl, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoCtl_To_service_FalcoCtl(in, out, s)
}

func autoConvert_service_FalcoCtl_To_v1alpha1_FalcoCtl(in *service.FalcoCtl, out *FalcoCtl, s conversion.Scope) error {
	out.Indexes = *(*[]FalcoCtlIndex)(unsafe.Pointer(&in.Indexes))
	out.AllowedTypes = *(*[]string)(unsafe.Pointer(&in.AllowedTypes))
	out.Install = (*Install)(unsafe.Pointer(in.Install))
	out.Follow = (*Follow)(unsafe.Pointer(in.Follow))
	return nil
}

// Convert_service_FalcoCtl_To_v1alpha1_FalcoCtl is an autogenerated conversion function.
func Convert_service_FalcoCtl_To_v1alpha1_FalcoCtl(in *service.FalcoCtl, out *FalcoCtl, s conversion.Scope) error {
	return autoConvert_service_FalcoCtl_To_v1alpha1_FalcoCtl(in, out, s)
}

func autoConvert_v1alpha1_FalcoCtlIndex_To_service_FalcoCtlIndex(in *FalcoCtlIndex, out *service.FalcoCtlIndex, s conversion.Scope) error {
	out.Name = (*string)(unsafe.Pointer(in.Name))
	out.Url = (*string)(unsafe.Pointer(in.Url))
	return nil
}

// Convert_v1alpha1_FalcoCtlIndex_To_service_FalcoCtlIndex is an autogenerated conversion function.
func Convert_v1alpha1_FalcoCtlIndex_To_service_FalcoCtlIndex(in *FalcoCtlIndex, out *service.FalcoCtlIndex, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoCtlIndex_To_service_FalcoCtlIndex(in, out, s)
}

func autoConvert_service_FalcoCtlIndex_To_v1alpha1_FalcoCtlIndex(in *service.FalcoCtlIndex, out *FalcoCtlIndex, s conversion.Scope) error {
	out.Name = (*string)(unsafe.Pointer(in.Name))
	out.Url = (*string)(unsafe.Pointer(in.Url))
	return nil
}

// Convert_service_FalcoCtlIndex_To_v1alpha1_FalcoCtlIndex is an autogenerated conversion function.
func Convert_service_FalcoCtlIndex_To_v1alpha1_FalcoCtlIndex(in *service.FalcoCtlIndex, out *FalcoCtlIndex, s conversion.Scope) error {
	return autoConvert_service_FalcoCtlIndex_To_v1alpha1_FalcoCtlIndex(in, out, s)
}

func autoConvert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig(in *FalcoServiceConfig, out *service.FalcoServiceConfig, s conversion.Scope) error {
	out.FalcoVersion = (*string)(unsafe.Pointer(in.FalcoVersion))
	out.AutoUpdate = (*bool)(unsafe.Pointer(in.AutoUpdate))
	out.Resources = (*string)(unsafe.Pointer(in.Resources))
	out.FalcoCtl = (*service.FalcoCtl)(unsafe.Pointer(in.FalcoCtl))
	out.Gardener = (*service.Gardener)(unsafe.Pointer(in.Gardener))
	out.Output = (*service.Output)(unsafe.Pointer(in.Output))
	out.CustomWebhook = (*service.Webhook)(unsafe.Pointer(in.CustomWebhook))
	out.Rules = (*service.Rules)(unsafe.Pointer(in.Rules))
	out.Destinations = (*[]service.Destination)(unsafe.Pointer(in.Destinations))
	return nil
}

// Convert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig is an autogenerated conversion function.
func Convert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig(in *FalcoServiceConfig, out *service.FalcoServiceConfig, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoServiceConfig_To_service_FalcoServiceConfig(in, out, s)
}

func autoConvert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig(in *service.FalcoServiceConfig, out *FalcoServiceConfig, s conversion.Scope) error {
	out.FalcoVersion = (*string)(unsafe.Pointer(in.FalcoVersion))
	out.AutoUpdate = (*bool)(unsafe.Pointer(in.AutoUpdate))
	out.Resources = (*string)(unsafe.Pointer(in.Resources))
	out.FalcoCtl = (*FalcoCtl)(unsafe.Pointer(in.FalcoCtl))
	out.Gardener = (*Gardener)(unsafe.Pointer(in.Gardener))
	out.Output = (*Output)(unsafe.Pointer(in.Output))
	out.CustomWebhook = (*Webhook)(unsafe.Pointer(in.CustomWebhook))
	out.Rules = (*Rules)(unsafe.Pointer(in.Rules))
	out.Destinations = (*[]Destination)(unsafe.Pointer(in.Destinations))
	return nil
}

// Convert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig is an autogenerated conversion function.
func Convert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig(in *service.FalcoServiceConfig, out *FalcoServiceConfig, s conversion.Scope) error {
	return autoConvert_service_FalcoServiceConfig_To_v1alpha1_FalcoServiceConfig(in, out, s)
}

func autoConvert_v1alpha1_Follow_To_service_Follow(in *Follow, out *service.Follow, s conversion.Scope) error {
	out.Refs = *(*[]string)(unsafe.Pointer(&in.Refs))
	out.Every = (*string)(unsafe.Pointer(in.Every))
	return nil
}

// Convert_v1alpha1_Follow_To_service_Follow is an autogenerated conversion function.
func Convert_v1alpha1_Follow_To_service_Follow(in *Follow, out *service.Follow, s conversion.Scope) error {
	return autoConvert_v1alpha1_Follow_To_service_Follow(in, out, s)
}

func autoConvert_service_Follow_To_v1alpha1_Follow(in *service.Follow, out *Follow, s conversion.Scope) error {
	out.Refs = *(*[]string)(unsafe.Pointer(&in.Refs))
	out.Every = (*string)(unsafe.Pointer(in.Every))
	return nil
}

// Convert_service_Follow_To_v1alpha1_Follow is an autogenerated conversion function.
func Convert_service_Follow_To_v1alpha1_Follow(in *service.Follow, out *Follow, s conversion.Scope) error {
	return autoConvert_service_Follow_To_v1alpha1_Follow(in, out, s)
}

func autoConvert_v1alpha1_Gardener_To_service_Gardener(in *Gardener, out *service.Gardener, s conversion.Scope) error {
	out.UseFalcoRules = (*bool)(unsafe.Pointer(in.UseFalcoRules))
	out.UseFalcoIncubatingRules = (*bool)(unsafe.Pointer(in.UseFalcoIncubatingRules))
	out.UseFalcoSandboxRules = (*bool)(unsafe.Pointer(in.UseFalcoSandboxRules))
	out.CustomRules = *(*[]string)(unsafe.Pointer(&in.CustomRules))
	return nil
}

// Convert_v1alpha1_Gardener_To_service_Gardener is an autogenerated conversion function.
func Convert_v1alpha1_Gardener_To_service_Gardener(in *Gardener, out *service.Gardener, s conversion.Scope) error {
	return autoConvert_v1alpha1_Gardener_To_service_Gardener(in, out, s)
}

func autoConvert_service_Gardener_To_v1alpha1_Gardener(in *service.Gardener, out *Gardener, s conversion.Scope) error {
	out.UseFalcoRules = (*bool)(unsafe.Pointer(in.UseFalcoRules))
	out.UseFalcoIncubatingRules = (*bool)(unsafe.Pointer(in.UseFalcoIncubatingRules))
	out.UseFalcoSandboxRules = (*bool)(unsafe.Pointer(in.UseFalcoSandboxRules))
	out.CustomRules = *(*[]string)(unsafe.Pointer(&in.CustomRules))
	return nil
}

// Convert_service_Gardener_To_v1alpha1_Gardener is an autogenerated conversion function.
func Convert_service_Gardener_To_v1alpha1_Gardener(in *service.Gardener, out *Gardener, s conversion.Scope) error {
	return autoConvert_service_Gardener_To_v1alpha1_Gardener(in, out, s)
}

func autoConvert_v1alpha1_Install_To_service_Install(in *Install, out *service.Install, s conversion.Scope) error {
	out.Refs = *(*[]string)(unsafe.Pointer(&in.Refs))
	out.ResolveDeps = (*bool)(unsafe.Pointer(in.ResolveDeps))
	return nil
}

// Convert_v1alpha1_Install_To_service_Install is an autogenerated conversion function.
func Convert_v1alpha1_Install_To_service_Install(in *Install, out *service.Install, s conversion.Scope) error {
	return autoConvert_v1alpha1_Install_To_service_Install(in, out, s)
}

func autoConvert_service_Install_To_v1alpha1_Install(in *service.Install, out *Install, s conversion.Scope) error {
	out.Refs = *(*[]string)(unsafe.Pointer(&in.Refs))
	out.ResolveDeps = (*bool)(unsafe.Pointer(in.ResolveDeps))
	return nil
}

// Convert_service_Install_To_v1alpha1_Install is an autogenerated conversion function.
func Convert_service_Install_To_v1alpha1_Install(in *service.Install, out *Install, s conversion.Scope) error {
	return autoConvert_service_Install_To_v1alpha1_Install(in, out, s)
}

func autoConvert_v1alpha1_Output_To_service_Output(in *Output, out *service.Output, s conversion.Scope) error {
	out.LogFalcoEvents = (*bool)(unsafe.Pointer(in.LogFalcoEvents))
	out.EventCollector = (*string)(unsafe.Pointer(in.EventCollector))
	out.CustomWebhook = (*service.Webhook)(unsafe.Pointer(in.CustomWebhook))
	return nil
}

// Convert_v1alpha1_Output_To_service_Output is an autogenerated conversion function.
func Convert_v1alpha1_Output_To_service_Output(in *Output, out *service.Output, s conversion.Scope) error {
	return autoConvert_v1alpha1_Output_To_service_Output(in, out, s)
}

func autoConvert_service_Output_To_v1alpha1_Output(in *service.Output, out *Output, s conversion.Scope) error {
	out.LogFalcoEvents = (*bool)(unsafe.Pointer(in.LogFalcoEvents))
	out.EventCollector = (*string)(unsafe.Pointer(in.EventCollector))
	out.CustomWebhook = (*Webhook)(unsafe.Pointer(in.CustomWebhook))
	return nil
}

// Convert_service_Output_To_v1alpha1_Output is an autogenerated conversion function.
func Convert_service_Output_To_v1alpha1_Output(in *service.Output, out *Output, s conversion.Scope) error {
	return autoConvert_service_Output_To_v1alpha1_Output(in, out, s)
}

func autoConvert_v1alpha1_Rules_To_service_Rules(in *Rules, out *service.Rules, s conversion.Scope) error {
	out.StandardRules = (*[]string)(unsafe.Pointer(in.StandardRules))
	out.CustomRules = (*[]service.CustomRule)(unsafe.Pointer(in.CustomRules))
	return nil
}

// Convert_v1alpha1_Rules_To_service_Rules is an autogenerated conversion function.
func Convert_v1alpha1_Rules_To_service_Rules(in *Rules, out *service.Rules, s conversion.Scope) error {
	return autoConvert_v1alpha1_Rules_To_service_Rules(in, out, s)
}

func autoConvert_service_Rules_To_v1alpha1_Rules(in *service.Rules, out *Rules, s conversion.Scope) error {
	out.StandardRules = (*[]string)(unsafe.Pointer(in.StandardRules))
	out.CustomRules = (*[]CustomRule)(unsafe.Pointer(in.CustomRules))
	return nil
}

// Convert_service_Rules_To_v1alpha1_Rules is an autogenerated conversion function.
func Convert_service_Rules_To_v1alpha1_Rules(in *service.Rules, out *Rules, s conversion.Scope) error {
	return autoConvert_service_Rules_To_v1alpha1_Rules(in, out, s)
}

func autoConvert_v1alpha1_Webhook_To_service_Webhook(in *Webhook, out *service.Webhook, s conversion.Scope) error {
	out.Enabled = (*bool)(unsafe.Pointer(in.Enabled))
	out.Address = (*string)(unsafe.Pointer(in.Address))
	out.Method = (*string)(unsafe.Pointer(in.Method))
	out.CustomHeaders = (*map[string]string)(unsafe.Pointer(in.CustomHeaders))
	out.Checkcerts = (*bool)(unsafe.Pointer(in.Checkcerts))
	out.SecretRef = (*string)(unsafe.Pointer(in.SecretRef))
	return nil
}

// Convert_v1alpha1_Webhook_To_service_Webhook is an autogenerated conversion function.
func Convert_v1alpha1_Webhook_To_service_Webhook(in *Webhook, out *service.Webhook, s conversion.Scope) error {
	return autoConvert_v1alpha1_Webhook_To_service_Webhook(in, out, s)
}

func autoConvert_service_Webhook_To_v1alpha1_Webhook(in *service.Webhook, out *Webhook, s conversion.Scope) error {
	out.Enabled = (*bool)(unsafe.Pointer(in.Enabled))
	out.Address = (*string)(unsafe.Pointer(in.Address))
	out.Method = (*string)(unsafe.Pointer(in.Method))
	out.CustomHeaders = (*map[string]string)(unsafe.Pointer(in.CustomHeaders))
	out.Checkcerts = (*bool)(unsafe.Pointer(in.Checkcerts))
	out.SecretRef = (*string)(unsafe.Pointer(in.SecretRef))
	return nil
}

// Convert_service_Webhook_To_v1alpha1_Webhook is an autogenerated conversion function.
func Convert_service_Webhook_To_v1alpha1_Webhook(in *service.Webhook, out *Webhook, s conversion.Scope) error {
	return autoConvert_service_Webhook_To_v1alpha1_Webhook(in, out, s)
}
