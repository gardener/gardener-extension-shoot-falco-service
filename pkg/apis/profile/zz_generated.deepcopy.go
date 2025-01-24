//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
// Code generated by deepcopy-gen. DO NOT EDIT.

package profile

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcoProfile) DeepCopyInto(out *FalcoProfile) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcoProfile.
func (in *FalcoProfile) DeepCopy() *FalcoProfile {
	if in == nil {
		return nil
	}
	out := new(FalcoProfile)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FalcoProfile) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcoProfileList) DeepCopyInto(out *FalcoProfileList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]FalcoProfile, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcoProfileList.
func (in *FalcoProfileList) DeepCopy() *FalcoProfileList {
	if in == nil {
		return nil
	}
	out := new(FalcoProfileList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcoVersion) DeepCopyInto(out *FalcoVersion) {
	*out = *in
	if in.ExpirationDate != nil {
		in, out := &in.ExpirationDate, &out.ExpirationDate
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcoVersion.
func (in *FalcoVersion) DeepCopy() *FalcoVersion {
	if in == nil {
		return nil
	}
	out := new(FalcoVersion)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcoctlVersion) DeepCopyInto(out *FalcoctlVersion) {
	*out = *in
	if in.ExpirationDate != nil {
		in, out := &in.ExpirationDate, &out.ExpirationDate
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcoctlVersion.
func (in *FalcoctlVersion) DeepCopy() *FalcoctlVersion {
	if in == nil {
		return nil
	}
	out := new(FalcoctlVersion)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcosidekickVersion) DeepCopyInto(out *FalcosidekickVersion) {
	*out = *in
	if in.ExpirationDate != nil {
		in, out := &in.ExpirationDate, &out.ExpirationDate
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcosidekickVersion.
func (in *FalcosidekickVersion) DeepCopy() *FalcosidekickVersion {
	if in == nil {
		return nil
	}
	out := new(FalcosidekickVersion)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageSpec) DeepCopyInto(out *ImageSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageSpec.
func (in *ImageSpec) DeepCopy() *ImageSpec {
	if in == nil {
		return nil
	}
	out := new(ImageSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Images) DeepCopyInto(out *Images) {
	*out = *in
	if in.Falco != nil {
		in, out := &in.Falco, &out.Falco
		*out = make([]ImageSpec, len(*in))
		copy(*out, *in)
	}
	if in.Falcosidekick != nil {
		in, out := &in.Falcosidekick, &out.Falcosidekick
		*out = make([]ImageSpec, len(*in))
		copy(*out, *in)
	}
	if in.Falcoctl != nil {
		in, out := &in.Falcoctl, &out.Falcoctl
		*out = make([]ImageSpec, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Images.
func (in *Images) DeepCopy() *Images {
	if in == nil {
		return nil
	}
	out := new(Images)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Spec) DeepCopyInto(out *Spec) {
	*out = *in
	in.Versions.DeepCopyInto(&out.Versions)
	in.Images.DeepCopyInto(&out.Images)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Spec.
func (in *Spec) DeepCopy() *Spec {
	if in == nil {
		return nil
	}
	out := new(Spec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Versions) DeepCopyInto(out *Versions) {
	*out = *in
	if in.Falco != nil {
		in, out := &in.Falco, &out.Falco
		*out = make([]FalcoVersion, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Falcosidekick != nil {
		in, out := &in.Falcosidekick, &out.Falcosidekick
		*out = make([]FalcosidekickVersion, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Falcoctl != nil {
		in, out := &in.Falcoctl, &out.Falcoctl
		*out = make([]FalcoctlVersion, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Versions.
func (in *Versions) DeepCopy() *Versions {
	if in == nil {
		return nil
	}
	out := new(Versions)
	in.DeepCopyInto(out)
	return out
}
