//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	profile "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/profile"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*FalcoProfile)(nil), (*profile.FalcoProfile)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcoProfile_To_profile_FalcoProfile(a.(*FalcoProfile), b.(*profile.FalcoProfile), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.FalcoProfile)(nil), (*FalcoProfile)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_FalcoProfile_To_v1alpha1_FalcoProfile(a.(*profile.FalcoProfile), b.(*FalcoProfile), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*FalcoProfileList)(nil), (*profile.FalcoProfileList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcoProfileList_To_profile_FalcoProfileList(a.(*FalcoProfileList), b.(*profile.FalcoProfileList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.FalcoProfileList)(nil), (*FalcoProfileList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_FalcoProfileList_To_v1alpha1_FalcoProfileList(a.(*profile.FalcoProfileList), b.(*FalcoProfileList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*FalcoVersion)(nil), (*profile.FalcoVersion)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcoVersion_To_profile_FalcoVersion(a.(*FalcoVersion), b.(*profile.FalcoVersion), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.FalcoVersion)(nil), (*FalcoVersion)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_FalcoVersion_To_v1alpha1_FalcoVersion(a.(*profile.FalcoVersion), b.(*FalcoVersion), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*FalcoctlVersion)(nil), (*profile.FalcoctlVersion)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcoctlVersion_To_profile_FalcoctlVersion(a.(*FalcoctlVersion), b.(*profile.FalcoctlVersion), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.FalcoctlVersion)(nil), (*FalcoctlVersion)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_FalcoctlVersion_To_v1alpha1_FalcoctlVersion(a.(*profile.FalcoctlVersion), b.(*FalcoctlVersion), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*FalcosidekickVersion)(nil), (*profile.FalcosidekickVersion)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_FalcosidekickVersion_To_profile_FalcosidekickVersion(a.(*FalcosidekickVersion), b.(*profile.FalcosidekickVersion), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.FalcosidekickVersion)(nil), (*FalcosidekickVersion)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_FalcosidekickVersion_To_v1alpha1_FalcosidekickVersion(a.(*profile.FalcosidekickVersion), b.(*FalcosidekickVersion), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*ImageSpec)(nil), (*profile.ImageSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ImageSpec_To_profile_ImageSpec(a.(*ImageSpec), b.(*profile.ImageSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.ImageSpec)(nil), (*ImageSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_ImageSpec_To_v1alpha1_ImageSpec(a.(*profile.ImageSpec), b.(*ImageSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Images)(nil), (*profile.Images)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Images_To_profile_Images(a.(*Images), b.(*profile.Images), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.Images)(nil), (*Images)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_Images_To_v1alpha1_Images(a.(*profile.Images), b.(*Images), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Spec)(nil), (*profile.Spec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Spec_To_profile_Spec(a.(*Spec), b.(*profile.Spec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.Spec)(nil), (*Spec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_Spec_To_v1alpha1_Spec(a.(*profile.Spec), b.(*Spec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*Versions)(nil), (*profile.Versions)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Versions_To_profile_Versions(a.(*Versions), b.(*profile.Versions), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*profile.Versions)(nil), (*Versions)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_profile_Versions_To_v1alpha1_Versions(a.(*profile.Versions), b.(*Versions), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_FalcoProfile_To_profile_FalcoProfile(in *FalcoProfile, out *profile.FalcoProfile, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_Spec_To_profile_Spec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_FalcoProfile_To_profile_FalcoProfile is an autogenerated conversion function.
func Convert_v1alpha1_FalcoProfile_To_profile_FalcoProfile(in *FalcoProfile, out *profile.FalcoProfile, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoProfile_To_profile_FalcoProfile(in, out, s)
}

func autoConvert_profile_FalcoProfile_To_v1alpha1_FalcoProfile(in *profile.FalcoProfile, out *FalcoProfile, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_profile_Spec_To_v1alpha1_Spec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_profile_FalcoProfile_To_v1alpha1_FalcoProfile is an autogenerated conversion function.
func Convert_profile_FalcoProfile_To_v1alpha1_FalcoProfile(in *profile.FalcoProfile, out *FalcoProfile, s conversion.Scope) error {
	return autoConvert_profile_FalcoProfile_To_v1alpha1_FalcoProfile(in, out, s)
}

func autoConvert_v1alpha1_FalcoProfileList_To_profile_FalcoProfileList(in *FalcoProfileList, out *profile.FalcoProfileList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]profile.FalcoProfile)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_FalcoProfileList_To_profile_FalcoProfileList is an autogenerated conversion function.
func Convert_v1alpha1_FalcoProfileList_To_profile_FalcoProfileList(in *FalcoProfileList, out *profile.FalcoProfileList, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoProfileList_To_profile_FalcoProfileList(in, out, s)
}

func autoConvert_profile_FalcoProfileList_To_v1alpha1_FalcoProfileList(in *profile.FalcoProfileList, out *FalcoProfileList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]FalcoProfile)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_profile_FalcoProfileList_To_v1alpha1_FalcoProfileList is an autogenerated conversion function.
func Convert_profile_FalcoProfileList_To_v1alpha1_FalcoProfileList(in *profile.FalcoProfileList, out *FalcoProfileList, s conversion.Scope) error {
	return autoConvert_profile_FalcoProfileList_To_v1alpha1_FalcoProfileList(in, out, s)
}

func autoConvert_v1alpha1_FalcoVersion_To_profile_FalcoVersion(in *FalcoVersion, out *profile.FalcoVersion, s conversion.Scope) error {
	out.Classification = in.Classification
	out.ExpirationDate = (*string)(unsafe.Pointer(in.ExpirationDate))
	out.Version = in.Version
	out.RulesVersion = in.RulesVersion
	return nil
}

// Convert_v1alpha1_FalcoVersion_To_profile_FalcoVersion is an autogenerated conversion function.
func Convert_v1alpha1_FalcoVersion_To_profile_FalcoVersion(in *FalcoVersion, out *profile.FalcoVersion, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoVersion_To_profile_FalcoVersion(in, out, s)
}

func autoConvert_profile_FalcoVersion_To_v1alpha1_FalcoVersion(in *profile.FalcoVersion, out *FalcoVersion, s conversion.Scope) error {
	out.Classification = in.Classification
	out.ExpirationDate = (*string)(unsafe.Pointer(in.ExpirationDate))
	out.Version = in.Version
	out.RulesVersion = in.RulesVersion
	return nil
}

// Convert_profile_FalcoVersion_To_v1alpha1_FalcoVersion is an autogenerated conversion function.
func Convert_profile_FalcoVersion_To_v1alpha1_FalcoVersion(in *profile.FalcoVersion, out *FalcoVersion, s conversion.Scope) error {
	return autoConvert_profile_FalcoVersion_To_v1alpha1_FalcoVersion(in, out, s)
}

func autoConvert_v1alpha1_FalcoctlVersion_To_profile_FalcoctlVersion(in *FalcoctlVersion, out *profile.FalcoctlVersion, s conversion.Scope) error {
	out.Classification = in.Classification
	out.ExpirationDate = (*string)(unsafe.Pointer(in.ExpirationDate))
	out.Version = in.Version
	return nil
}

// Convert_v1alpha1_FalcoctlVersion_To_profile_FalcoctlVersion is an autogenerated conversion function.
func Convert_v1alpha1_FalcoctlVersion_To_profile_FalcoctlVersion(in *FalcoctlVersion, out *profile.FalcoctlVersion, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcoctlVersion_To_profile_FalcoctlVersion(in, out, s)
}

func autoConvert_profile_FalcoctlVersion_To_v1alpha1_FalcoctlVersion(in *profile.FalcoctlVersion, out *FalcoctlVersion, s conversion.Scope) error {
	out.Classification = in.Classification
	out.ExpirationDate = (*string)(unsafe.Pointer(in.ExpirationDate))
	out.Version = in.Version
	return nil
}

// Convert_profile_FalcoctlVersion_To_v1alpha1_FalcoctlVersion is an autogenerated conversion function.
func Convert_profile_FalcoctlVersion_To_v1alpha1_FalcoctlVersion(in *profile.FalcoctlVersion, out *FalcoctlVersion, s conversion.Scope) error {
	return autoConvert_profile_FalcoctlVersion_To_v1alpha1_FalcoctlVersion(in, out, s)
}

func autoConvert_v1alpha1_FalcosidekickVersion_To_profile_FalcosidekickVersion(in *FalcosidekickVersion, out *profile.FalcosidekickVersion, s conversion.Scope) error {
	out.Classification = in.Classification
	out.ExpirationDate = (*string)(unsafe.Pointer(in.ExpirationDate))
	out.Version = in.Version
	return nil
}

// Convert_v1alpha1_FalcosidekickVersion_To_profile_FalcosidekickVersion is an autogenerated conversion function.
func Convert_v1alpha1_FalcosidekickVersion_To_profile_FalcosidekickVersion(in *FalcosidekickVersion, out *profile.FalcosidekickVersion, s conversion.Scope) error {
	return autoConvert_v1alpha1_FalcosidekickVersion_To_profile_FalcosidekickVersion(in, out, s)
}

func autoConvert_profile_FalcosidekickVersion_To_v1alpha1_FalcosidekickVersion(in *profile.FalcosidekickVersion, out *FalcosidekickVersion, s conversion.Scope) error {
	out.Classification = in.Classification
	out.ExpirationDate = (*string)(unsafe.Pointer(in.ExpirationDate))
	out.Version = in.Version
	return nil
}

// Convert_profile_FalcosidekickVersion_To_v1alpha1_FalcosidekickVersion is an autogenerated conversion function.
func Convert_profile_FalcosidekickVersion_To_v1alpha1_FalcosidekickVersion(in *profile.FalcosidekickVersion, out *FalcosidekickVersion, s conversion.Scope) error {
	return autoConvert_profile_FalcosidekickVersion_To_v1alpha1_FalcosidekickVersion(in, out, s)
}

func autoConvert_v1alpha1_ImageSpec_To_profile_ImageSpec(in *ImageSpec, out *profile.ImageSpec, s conversion.Scope) error {
	out.Version = in.Version
	out.Architecture = in.Architecture
	out.Repository = in.Repository
	out.Tag = in.Tag
	return nil
}

// Convert_v1alpha1_ImageSpec_To_profile_ImageSpec is an autogenerated conversion function.
func Convert_v1alpha1_ImageSpec_To_profile_ImageSpec(in *ImageSpec, out *profile.ImageSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_ImageSpec_To_profile_ImageSpec(in, out, s)
}

func autoConvert_profile_ImageSpec_To_v1alpha1_ImageSpec(in *profile.ImageSpec, out *ImageSpec, s conversion.Scope) error {
	out.Version = in.Version
	out.Architecture = in.Architecture
	out.Repository = in.Repository
	out.Tag = in.Tag
	return nil
}

// Convert_profile_ImageSpec_To_v1alpha1_ImageSpec is an autogenerated conversion function.
func Convert_profile_ImageSpec_To_v1alpha1_ImageSpec(in *profile.ImageSpec, out *ImageSpec, s conversion.Scope) error {
	return autoConvert_profile_ImageSpec_To_v1alpha1_ImageSpec(in, out, s)
}

func autoConvert_v1alpha1_Images_To_profile_Images(in *Images, out *profile.Images, s conversion.Scope) error {
	out.Falco = *(*[]profile.ImageSpec)(unsafe.Pointer(&in.Falco))
	out.Falcosidekick = *(*[]profile.ImageSpec)(unsafe.Pointer(&in.Falcosidekick))
	out.Falcoctl = *(*[]profile.ImageSpec)(unsafe.Pointer(&in.Falcoctl))
	return nil
}

// Convert_v1alpha1_Images_To_profile_Images is an autogenerated conversion function.
func Convert_v1alpha1_Images_To_profile_Images(in *Images, out *profile.Images, s conversion.Scope) error {
	return autoConvert_v1alpha1_Images_To_profile_Images(in, out, s)
}

func autoConvert_profile_Images_To_v1alpha1_Images(in *profile.Images, out *Images, s conversion.Scope) error {
	out.Falco = *(*[]ImageSpec)(unsafe.Pointer(&in.Falco))
	out.Falcosidekick = *(*[]ImageSpec)(unsafe.Pointer(&in.Falcosidekick))
	out.Falcoctl = *(*[]ImageSpec)(unsafe.Pointer(&in.Falcoctl))
	return nil
}

// Convert_profile_Images_To_v1alpha1_Images is an autogenerated conversion function.
func Convert_profile_Images_To_v1alpha1_Images(in *profile.Images, out *Images, s conversion.Scope) error {
	return autoConvert_profile_Images_To_v1alpha1_Images(in, out, s)
}

func autoConvert_v1alpha1_Spec_To_profile_Spec(in *Spec, out *profile.Spec, s conversion.Scope) error {
	if err := Convert_v1alpha1_Versions_To_profile_Versions(&in.Versions, &out.Versions, s); err != nil {
		return err
	}
	if err := Convert_v1alpha1_Images_To_profile_Images(&in.Images, &out.Images, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_Spec_To_profile_Spec is an autogenerated conversion function.
func Convert_v1alpha1_Spec_To_profile_Spec(in *Spec, out *profile.Spec, s conversion.Scope) error {
	return autoConvert_v1alpha1_Spec_To_profile_Spec(in, out, s)
}

func autoConvert_profile_Spec_To_v1alpha1_Spec(in *profile.Spec, out *Spec, s conversion.Scope) error {
	if err := Convert_profile_Versions_To_v1alpha1_Versions(&in.Versions, &out.Versions, s); err != nil {
		return err
	}
	if err := Convert_profile_Images_To_v1alpha1_Images(&in.Images, &out.Images, s); err != nil {
		return err
	}
	return nil
}

// Convert_profile_Spec_To_v1alpha1_Spec is an autogenerated conversion function.
func Convert_profile_Spec_To_v1alpha1_Spec(in *profile.Spec, out *Spec, s conversion.Scope) error {
	return autoConvert_profile_Spec_To_v1alpha1_Spec(in, out, s)
}

func autoConvert_v1alpha1_Versions_To_profile_Versions(in *Versions, out *profile.Versions, s conversion.Scope) error {
	out.Falco = *(*[]profile.FalcoVersion)(unsafe.Pointer(&in.Falco))
	out.Falcosidekick = *(*[]profile.FalcosidekickVersion)(unsafe.Pointer(&in.Falcosidekick))
	out.Falcoctl = *(*[]profile.FalcoctlVersion)(unsafe.Pointer(&in.Falcoctl))
	return nil
}

// Convert_v1alpha1_Versions_To_profile_Versions is an autogenerated conversion function.
func Convert_v1alpha1_Versions_To_profile_Versions(in *Versions, out *profile.Versions, s conversion.Scope) error {
	return autoConvert_v1alpha1_Versions_To_profile_Versions(in, out, s)
}

func autoConvert_profile_Versions_To_v1alpha1_Versions(in *profile.Versions, out *Versions, s conversion.Scope) error {
	out.Falco = *(*[]FalcoVersion)(unsafe.Pointer(&in.Falco))
	out.Falcosidekick = *(*[]FalcosidekickVersion)(unsafe.Pointer(&in.Falcosidekick))
	out.Falcoctl = *(*[]FalcoctlVersion)(unsafe.Pointer(&in.Falcoctl))
	return nil
}

// Convert_profile_Versions_To_v1alpha1_Versions is an autogenerated conversion function.
func Convert_profile_Versions_To_v1alpha1_Versions(in *profile.Versions, out *Versions, s conversion.Scope) error {
	return autoConvert_profile_Versions_To_v1alpha1_Versions(in, out, s)
}
