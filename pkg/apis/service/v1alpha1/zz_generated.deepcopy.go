//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomRule) DeepCopyInto(out *CustomRule) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomRule.
func (in *CustomRule) DeepCopy() *CustomRule {
	if in == nil {
		return nil
	}
	out := new(CustomRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Destination) DeepCopyInto(out *Destination) {
	*out = *in
	if in.ResourceSecretName != nil {
		in, out := &in.ResourceSecretName, &out.ResourceSecretName
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Destination.
func (in *Destination) DeepCopy() *Destination {
	if in == nil {
		return nil
	}
	out := new(Destination)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcoCtl) DeepCopyInto(out *FalcoCtl) {
	*out = *in
	if in.Indexes != nil {
		in, out := &in.Indexes, &out.Indexes
		*out = make([]FalcoCtlIndex, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.AllowedTypes != nil {
		in, out := &in.AllowedTypes, &out.AllowedTypes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Install != nil {
		in, out := &in.Install, &out.Install
		*out = new(Install)
		(*in).DeepCopyInto(*out)
	}
	if in.Follow != nil {
		in, out := &in.Follow, &out.Follow
		*out = new(Follow)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcoCtl.
func (in *FalcoCtl) DeepCopy() *FalcoCtl {
	if in == nil {
		return nil
	}
	out := new(FalcoCtl)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcoCtlIndex) DeepCopyInto(out *FalcoCtlIndex) {
	*out = *in
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
	if in.Url != nil {
		in, out := &in.Url, &out.Url
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcoCtlIndex.
func (in *FalcoCtlIndex) DeepCopy() *FalcoCtlIndex {
	if in == nil {
		return nil
	}
	out := new(FalcoCtlIndex)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FalcoServiceConfig) DeepCopyInto(out *FalcoServiceConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.FalcoVersion != nil {
		in, out := &in.FalcoVersion, &out.FalcoVersion
		*out = new(string)
		**out = **in
	}
	if in.AutoUpdate != nil {
		in, out := &in.AutoUpdate, &out.AutoUpdate
		*out = new(bool)
		**out = **in
	}
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(string)
		**out = **in
	}
	if in.FalcoCtl != nil {
		in, out := &in.FalcoCtl, &out.FalcoCtl
		*out = new(FalcoCtl)
		(*in).DeepCopyInto(*out)
	}
	if in.Gardener != nil {
		in, out := &in.Gardener, &out.Gardener
		*out = new(Gardener)
		(*in).DeepCopyInto(*out)
	}
	if in.Output != nil {
		in, out := &in.Output, &out.Output
		*out = new(Output)
		(*in).DeepCopyInto(*out)
	}
	if in.CustomWebhook != nil {
		in, out := &in.CustomWebhook, &out.CustomWebhook
		*out = new(Webhook)
		(*in).DeepCopyInto(*out)
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(map[string]string)
		if **in != nil {
			in, out := *in, *out
			*out = make(map[string]string, len(*in))
			for key, val := range *in {
				(*out)[key] = val
			}
		}
	}
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = new(Rules)
		(*in).DeepCopyInto(*out)
	}
	if in.Destinations != nil {
		in, out := &in.Destinations, &out.Destinations
		*out = new([]Destination)
		if **in != nil {
			in, out := *in, *out
			*out = make([]Destination, len(*in))
			for i := range *in {
				(*in)[i].DeepCopyInto(&(*out)[i])
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FalcoServiceConfig.
func (in *FalcoServiceConfig) DeepCopy() *FalcoServiceConfig {
	if in == nil {
		return nil
	}
	out := new(FalcoServiceConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FalcoServiceConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Follow) DeepCopyInto(out *Follow) {
	*out = *in
	if in.Refs != nil {
		in, out := &in.Refs, &out.Refs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Every != nil {
		in, out := &in.Every, &out.Every
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Follow.
func (in *Follow) DeepCopy() *Follow {
	if in == nil {
		return nil
	}
	out := new(Follow)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Gardener) DeepCopyInto(out *Gardener) {
	*out = *in
	if in.UseFalcoRules != nil {
		in, out := &in.UseFalcoRules, &out.UseFalcoRules
		*out = new(bool)
		**out = **in
	}
	if in.UseFalcoIncubatingRules != nil {
		in, out := &in.UseFalcoIncubatingRules, &out.UseFalcoIncubatingRules
		*out = new(bool)
		**out = **in
	}
	if in.UseFalcoSandboxRules != nil {
		in, out := &in.UseFalcoSandboxRules, &out.UseFalcoSandboxRules
		*out = new(bool)
		**out = **in
	}
	if in.CustomRules != nil {
		in, out := &in.CustomRules, &out.CustomRules
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Gardener.
func (in *Gardener) DeepCopy() *Gardener {
	if in == nil {
		return nil
	}
	out := new(Gardener)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Install) DeepCopyInto(out *Install) {
	*out = *in
	if in.Refs != nil {
		in, out := &in.Refs, &out.Refs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ResolveDeps != nil {
		in, out := &in.ResolveDeps, &out.ResolveDeps
		*out = new(bool)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Install.
func (in *Install) DeepCopy() *Install {
	if in == nil {
		return nil
	}
	out := new(Install)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Output) DeepCopyInto(out *Output) {
	*out = *in
	if in.LogFalcoEvents != nil {
		in, out := &in.LogFalcoEvents, &out.LogFalcoEvents
		*out = new(bool)
		**out = **in
	}
	if in.EventCollector != nil {
		in, out := &in.EventCollector, &out.EventCollector
		*out = new(string)
		**out = **in
	}
	if in.CustomWebhook != nil {
		in, out := &in.CustomWebhook, &out.CustomWebhook
		*out = new(Webhook)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Output.
func (in *Output) DeepCopy() *Output {
	if in == nil {
		return nil
	}
	out := new(Output)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Rules) DeepCopyInto(out *Rules) {
	*out = *in
	if in.StandardRules != nil {
		in, out := &in.StandardRules, &out.StandardRules
		*out = new([]string)
		if **in != nil {
			in, out := *in, *out
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
	}
	if in.CustomRules != nil {
		in, out := &in.CustomRules, &out.CustomRules
		*out = new([]CustomRule)
		if **in != nil {
			in, out := *in, *out
			*out = make([]CustomRule, len(*in))
			copy(*out, *in)
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Rules.
func (in *Rules) DeepCopy() *Rules {
	if in == nil {
		return nil
	}
	out := new(Rules)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Webhook) DeepCopyInto(out *Webhook) {
	*out = *in
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.Address != nil {
		in, out := &in.Address, &out.Address
		*out = new(string)
		**out = **in
	}
	if in.Method != nil {
		in, out := &in.Method, &out.Method
		*out = new(string)
		**out = **in
	}
	if in.CustomHeaders != nil {
		in, out := &in.CustomHeaders, &out.CustomHeaders
		*out = new(map[string]string)
		if **in != nil {
			in, out := *in, *out
			*out = make(map[string]string, len(*in))
			for key, val := range *in {
				(*out)[key] = val
			}
		}
	}
	if in.Checkcerts != nil {
		in, out := &in.Checkcerts, &out.Checkcerts
		*out = new(bool)
		**out = **in
	}
	if in.SecretRef != nil {
		in, out := &in.SecretRef, &out.SecretRef
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Webhook.
func (in *Webhook) DeepCopy() *Webhook {
	if in == nil {
		return nil
	}
	out := new(Webhook)
	in.DeepCopyInto(out)
	return out
}
